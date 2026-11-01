package memprocfs

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/sergeyzav/gomemprocfs/internal/ffi"
)

const (
	memSearchVersion     = 0xfe3e0003 // VMMDLL_MEM_SEARCH_VERSION
	memSearchMaxLength   = 32         // VMMDLL_MEM_SEARCH_MAXLENGTH
	memSearchMaxResults  = 0x00010000 // documented max of cMaxResult (current builds ignore it)
	yaraConfigVersion    = 0xdec30001 // VMMDLL_YARA_CONFIG_VERSION
	yaraRuleMatchVersion = 0xfedc0005 // VMMYARA_RULE_MATCH_VERSION
	yaraMaxResults       = 0x00010000 // VMMDLL_YARA_CONFIG_MAX_RESULT
)

// memSearchEntryInternal mirrors VMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY.
type memSearchEntryInternal struct {
	CbAlign    uint32
	Cb         uint32
	Pb         [memSearchMaxLength]byte
	PbSkipMask [memSearchMaxLength]byte
}

// memSearchContextInternal mirrors VMMDLL_MEM_SEARCH_CONTEXT.
// It is allocated in Go and pinned for the duration of the native call.
type memSearchContextInternal struct {
	DwVersion       uint32
	_               [2]uint32
	FAbortRequested int32 // BOOL; written atomically from Go while the search runs
	CMaxResult      uint32
	CSearch         uint32
	PSearch         *memSearchEntryInternal
	VaMin           uint64
	VaMax           uint64
	VaCurrent       uint64
	_               uint32
	CResult         uint32
	CbReadTotal     uint64
	PvUserPtrOpt    uintptr
	PfnResultOptCB  uintptr
	ReadFlags       uint64
	FForcePTE       uint32 // BOOL
	FForceVAD       uint32 // BOOL
	PfnFilterOptCB  uintptr
}

// yaraConfigInternal mirrors VMMDLL_YARA_CONFIG.
// It is allocated in Go and pinned for the duration of the native call.
type yaraConfigInternal struct {
	DwVersion       uint32
	_               [2]uint32
	FAbortRequested int32 // BOOL; written atomically from Go while the search runs
	CMaxResult      uint32
	CRules          uint32
	PszRules        **byte
	VaMin           uint64
	VaMax           uint64
	VaCurrent       uint64
	_               uint32
	CResult         uint32
	CbReadTotal     uint64
	PvUserPtrOpt    uintptr
	PfnScanMemoryCB uintptr
	ReadFlags       uint64
	FForcePTE       uint32 // BOOL
	FForceVAD       uint32 // BOOL
	PfnFilterOptCB  uintptr
	PvUserPtrOpt2   uintptr
	_               uint64 // _Reserved, used by MemProcFS internally
}

// yaraMetaInternal mirrors an element of VMMYARA_RULE_MATCH.Meta.
type yaraMetaInternal struct {
	SzIdentifier uintptr
	SzString     uintptr
}

// yaraStringInternal mirrors an element of VMMYARA_RULE_MATCH.Strings.
type yaraStringInternal struct {
	SzString      uintptr
	CMatch        uint32
	CbMatchOffset [24]uintptr
}

// yaraRuleMatchInternal mirrors VMMYARA_RULE_MATCH.
type yaraRuleMatchInternal struct {
	DwVersion        uint32
	Flags            uint32
	SzRuleIdentifier uintptr
	CTags            uint32
	SzTags           [27]uintptr
	CMeta            uint32
	Meta             [32]yaraMetaInternal
	CStrings         uint32
	Strings          [16]yaraStringInternal
}

// Both native configs keep the user pointer at the same offset, so one filter
// callback serves both searches.
var _ = [1]struct{}{}[unsafe.Offsetof(memSearchContextInternal{}.PvUserPtrOpt)-
	unsafe.Offsetof(yaraConfigInternal{}.PvUserPtrOpt)]

var (
	vmmMemSearch  func(vmmHandle uintptr, pid uint32, ctx *memSearchContextInternal, ppva *uintptr, pcva *uint32) bool
	vmmYaraSearch func(vmmHandle uintptr, pid uint32, cfg *yaraConfigInternal, ppva *uintptr, pcva *uint32) bool
)

func loadSearchFunctions(lib uintptr) {
	purego.RegisterLibFunc(&vmmMemSearch, lib, "VMMDLL_MemSearch")
	purego.RegisterLibFunc(&vmmYaraSearch, lib, "VMMDLL_YaraSearch")
}

// SearchPattern is one byte pattern for MemSearch and MemSearchFunc.
type SearchPattern struct {
	// Bytes is the data to look for: 1 to 32 bytes, not all zero.
	Bytes []byte
	// Mask is optional. If set it must be as long as Bytes. Bits set to 1 are
	// wildcards: they are ignored when comparing the matching byte.
	// For example Mask byte 0xFF matches any byte, 0x0F matches any low nibble.
	Mask []byte
	// Align is the step in bytes between tested offsets. 0 or 1 tests every byte.
	// A power of two up to 4096 means "only addresses that are multiples of Align".
	Align uint32
}

// SearchRegion is a memory region offered to SearchOptions.Filter.
// Exactly one of Pte and Vad is set, depending on how the process address space
// is walked (see SearchOptions.ForcePTE and ForceVAD).
// Text fields (PteEntry.Name, Vad.Text) may be empty during YARA searches.
type SearchRegion struct {
	Pte *PteEntry
	Vad *Vad
}

// SearchOptions configures MemSearch and YaraSearch. A nil *SearchOptions
// searches the whole address space with default settings.
type SearchOptions struct {
	// MinAddress and MaxAddress limit the searched range. They are rounded to
	// page boundaries. MaxAddress 0 means the end of the address space (or the
	// end of physical memory when pid is PidPhysical).
	MinAddress uint64
	MaxAddress uint64
	// MaxResults stops the search after this many hits. 0 means no limit other
	// than the native one: about one million for MemSearch and 65536 for YARA.
	// For YaraSearchFunc it counts matched string offsets, not callback calls.
	MaxResults uint32
	// Flags are memory read flags, such as MemFlagNoCache.
	Flags MemFlag
	// ForcePTE and ForceVAD select how a process address space is walked.
	// By default MemProcFS picks one. They have no effect for PidPhysical.
	ForcePTE bool
	ForceVAD bool
	// Filter is called for each memory region before it is read.
	// Return false to skip the region. It is not called for PidPhysical.
	Filter func(SearchRegion) bool
}

// YaraMatch describes a YARA rule that matched during YaraSearchFunc.
// MemProcFS scans memory in chunks of up to 1 MiB, so one rule may be
// reported once per chunk it matches in.
type YaraMatch struct {
	Rule    string
	Tags    []string
	Meta    []YaraMeta
	Strings []YaraString
}

// YaraMeta is one meta entry of a matched YARA rule.
type YaraMeta struct {
	Identifier string
	Value      string
}

// YaraString is one string of a matched YARA rule with the addresses where it
// matched. The native library reports at most 24 addresses per string per chunk.
type YaraString struct {
	// Pattern is the string's data as defined in the rule (e.g. the text of a
	// text string), not its $identifier. It ends at the first zero byte.
	Pattern   string
	Addresses []uint64
}

// MemSearch searches the memory of process pid (or physical memory when pid is
// PidPhysical) for any of the given patterns and returns the addresses of all
// hits. Addresses are roughly ascending; with several patterns the order
// within one 1 MiB chunk follows the pattern order.
//
// A search may take a long time. Cancel ctx to stop it; the error is then
// ctx.Err() and the partial result is lost. Use MemSearchFunc to get hits as
// they are found.
func (vmm *Vmm) MemSearch(ctx context.Context, pid uint32, patterns []SearchPattern, opts *SearchOptions) ([]uint64, error) {
	hits, err := vmm.memSearch(ctx, pid, patterns, opts, nil)
	if err != nil {
		return nil, err
	}
	if opts != nil && opts.MaxResults != 0 && len(hits) > int(opts.MaxResults) {
		hits = hits[:opts.MaxResults]
	}
	return hits, nil
}

// MemSearchFunc is like MemSearch but calls fn for each hit instead of
// collecting addresses. pattern is the index into patterns that matched.
// Return false from fn to stop the search; MemSearchFunc then returns nil.
//
// fn runs on the goroutine that called MemSearchFunc, while the native search
// is in progress: it must not call back into the same search. A panic in fn
// stops the search and is re-raised after the native call returns.
func (vmm *Vmm) MemSearchFunc(ctx context.Context, pid uint32, patterns []SearchPattern, opts *SearchOptions, fn func(va uint64, pattern int) bool) error {
	if fn == nil {
		return errors.New("memsearch: fn is nil")
	}
	_, err := vmm.memSearch(ctx, pid, patterns, opts, fn)
	return err
}

func (vmm *Vmm) memSearch(ctx context.Context, pid uint32, patterns []SearchPattern, opts *SearchOptions, fn func(uint64, int) bool) ([]uint64, error) {
	entries, err := buildSearchEntries(patterns)
	if err != nil {
		return nil, err
	}
	if opts == nil {
		opts = &SearchOptions{}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c := &memSearchContextInternal{
		DwVersion:  memSearchVersion,
		CMaxResult: memSearchMaxResults,
		CSearch:    uint32(len(entries)),
		PSearch:    &entries[0],
		VaMin:      opts.MinAddress,
		VaMax:      opts.MaxAddress,
		ReadFlags:  uint64(opts.Flags),
		FForcePTE:  boolToUint32(opts.ForcePTE),
		FForceVAD:  boolToUint32(opts.ForceVAD),
	}
	// Header: cMaxResult 0 means one entry.
	if opts.MaxResults != 0 && opts.MaxResults < memSearchMaxResults {
		c.CMaxResult = opts.MaxResults
	}

	st := &searchState{abort: &c.FAbortRequested, filter: opts.Filter}
	if fn != nil {
		limit := opts.MaxResults
		var count uint32
		st.onHit = func(va uint64, pattern int) bool {
			if !fn(va, pattern) {
				return false
			}
			count++
			return limit == 0 || count < limit
		}
	}
	cb := searchCallbackPtrs()
	if st.onHit != nil {
		c.PfnResultOptCB = cb.memResult
	}
	if st.filter != nil {
		c.PfnFilterOptCB = cb.filter
	}
	c.PvUserPtrOpt = registerSearchState(st)
	defer unregisterSearchState(c.PvUserPtrOpt)

	var pinner runtime.Pinner
	pinner.Pin(c)
	pinner.Pin(&entries[0])
	defer pinner.Unpin()

	var pva uintptr
	var cva uint32
	ok := runAbortable(ctx, &c.FAbortRequested, func() bool {
		return vmmMemSearch(vmm.vmmHandle, pid, c, &pva, &cva)
	})
	if pva != 0 {
		defer vmm.free(pva)
	}
	st.rethrow()

	switch {
	case st.stopped:
		return nil, nil
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case !ok:
		return nil, fmt.Errorf("memsearch pid %d: %w", pid, ErrSearchFailed)
	}
	if fn != nil || cva == 0 {
		return nil, nil
	}
	hits := make([]uint64, cva)
	copy(hits, unsafe.Slice((*uint64)(unsafe.Pointer(pva)), cva))
	return hits, nil
}

// YaraSearch scans the memory of process pid (or physical memory when pid is
// PidPhysical) with YARA rules and returns the addresses of all matched strings.
//
// Each element of rules is either YARA rule source text or a path to a rules
// file. Alternatively rules may hold a single path to a compiled rules file.
// The search needs the vmmyara library next to the vmmdll library; if it is
// missing or the rules do not compile, ErrSearchFailed is returned.
//
// Cancel ctx to stop the search; the error is then ctx.Err().
func (vmm *Vmm) YaraSearch(ctx context.Context, pid uint32, rules []string, opts *SearchOptions) ([]uint64, error) {
	return vmm.yaraSearch(ctx, pid, rules, opts, nil)
}

// YaraSearchFunc is like YaraSearch but also calls fn for each rule match with
// details about the rule. Return false from fn to stop the search;
// YaraSearchFunc then returns nil. The returned addresses are those found
// before the search ended; they are nil if fn stopped it.
//
// fn runs on the goroutine that called YaraSearchFunc, while the native search
// is in progress. A panic in fn stops the search and is re-raised after the
// native call returns.
func (vmm *Vmm) YaraSearchFunc(ctx context.Context, pid uint32, rules []string, opts *SearchOptions, fn func(*YaraMatch) bool) ([]uint64, error) {
	if fn == nil {
		return nil, errors.New("yarasearch: fn is nil")
	}
	return vmm.yaraSearch(ctx, pid, rules, opts, fn)
}

func (vmm *Vmm) yaraSearch(ctx context.Context, pid uint32, rules []string, opts *SearchOptions, fn func(*YaraMatch) bool) ([]uint64, error) {
	if len(rules) == 0 {
		return nil, errors.New("yarasearch: no rules")
	}
	if opts == nil {
		opts = &SearchOptions{}
	}
	if opts.MaxResults > yaraMaxResults {
		return nil, fmt.Errorf("yarasearch: MaxResults %d exceeds %d", opts.MaxResults, yaraMaxResults)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var pinner runtime.Pinner
	defer pinner.Unpin()

	rulePtrs := make([]*byte, len(rules))
	for i, r := range rules {
		b := make([]byte, len(r)+1)
		copy(b, r)
		pinner.Pin(&b[0])
		rulePtrs[i] = &b[0]
	}
	pinner.Pin(&rulePtrs[0])

	c := &yaraConfigInternal{
		DwVersion:  yaraConfigVersion,
		CMaxResult: opts.MaxResults,
		CRules:     uint32(len(rules)),
		PszRules:   &rulePtrs[0],
		VaMin:      opts.MinAddress,
		VaMax:      opts.MaxAddress,
		ReadFlags:  uint64(opts.Flags),
		FForcePTE:  boolToUint32(opts.ForcePTE),
		FForceVAD:  boolToUint32(opts.ForceVAD),
	}
	pinner.Pin(c)

	st := &searchState{abort: &c.FAbortRequested, vaCurrent: &c.VaCurrent, onYara: fn, filter: opts.Filter}
	cb := searchCallbackPtrs()
	if fn != nil {
		c.PfnScanMemoryCB = cb.yaraMatch
	}
	if st.filter != nil {
		c.PfnFilterOptCB = cb.filter
	}
	c.PvUserPtrOpt = registerSearchState(st)
	defer unregisterSearchState(c.PvUserPtrOpt)

	var pva uintptr
	var cva uint32
	ok := runAbortable(ctx, &c.FAbortRequested, func() bool {
		return vmmYaraSearch(vmm.vmmHandle, pid, c, &pva, &cva)
	})
	if pva != 0 {
		defer vmm.free(pva)
	}
	st.rethrow()

	switch {
	case st.stopped:
		return nil, nil
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case !ok:
		return nil, fmt.Errorf("yarasearch pid %d: %w", pid, ErrSearchFailed)
	}
	if cva == 0 {
		return nil, nil
	}
	hits := make([]uint64, cva)
	copy(hits, unsafe.Slice((*uint64)(unsafe.Pointer(pva)), cva))
	return hits, nil
}

func buildSearchEntries(patterns []SearchPattern) ([]memSearchEntryInternal, error) {
	if len(patterns) == 0 {
		return nil, errors.New("memsearch: no patterns")
	}
	entries := make([]memSearchEntryInternal, len(patterns))
	for i, p := range patterns {
		if len(p.Bytes) == 0 || len(p.Bytes) > memSearchMaxLength {
			return nil, fmt.Errorf("memsearch: pattern %d: length %d, want 1-%d bytes", i, len(p.Bytes), memSearchMaxLength)
		}
		if p.Mask != nil && len(p.Mask) != len(p.Bytes) {
			return nil, fmt.Errorf("memsearch: pattern %d: mask length %d, want %d", i, len(p.Mask), len(p.Bytes))
		}
		// MemProcFS rejects patterns whose bytes are all zero.
		allZero := true
		for _, b := range p.Bytes {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			return nil, fmt.Errorf("memsearch: pattern %d: all bytes are zero", i)
		}
		e := &entries[i]
		e.CbAlign = p.Align
		e.Cb = uint32(len(p.Bytes))
		copy(e.Pb[:], p.Bytes)
		copy(e.PbSkipMask[:], p.Mask)
	}
	return entries, nil
}

// runAbortable runs a native search and sets *abort when ctx is cancelled,
// which makes MemProcFS stop at the next memory chunk.
func runAbortable(ctx context.Context, abort *int32, call func() bool) bool {
	stop := context.AfterFunc(ctx, func() { atomic.StoreInt32(abort, 1) })
	defer stop()
	return call()
}

func boolToUint32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

// ─── Native callbacks ────────────────────────────────────────────────────────

// searchState is the Go side of one running search. Native callbacks find it
// through the integer id stored in the config's pvUserPtrOpt field; Go
// pointers are never handed to C as user data.
type searchState struct {
	abort     *int32
	vaCurrent *uint64 // YARA: start address of the chunk being scanned
	onHit     func(va uint64, pattern int) bool
	onYara    func(*YaraMatch) bool
	filter    func(SearchRegion) bool

	stopped  bool // a Go callback asked to stop
	panicked bool
	panicVal any
}

// call runs a user callback. A panic or a false result stops the search.
func (st *searchState) call(f func() bool) (cont bool) {
	if st.panicked {
		return false
	}
	defer func() {
		if r := recover(); r != nil {
			st.panicked, st.panicVal, st.stopped = true, r, true
			atomic.StoreInt32(st.abort, 1)
			cont = false
		}
	}()
	return f()
}

func (st *searchState) rethrow() {
	if st.panicked {
		panic(st.panicVal)
	}
}

var (
	searchStates  sync.Map // uintptr -> *searchState
	searchStateID atomic.Uintptr
)

func registerSearchState(st *searchState) uintptr {
	id := searchStateID.Add(1)
	searchStates.Store(id, st)
	return id
}

func unregisterSearchState(id uintptr) {
	searchStates.Delete(id)
}

func lookupSearchState(id uintptr) *searchState {
	v, ok := searchStates.Load(id)
	if !ok {
		return nil
	}
	return v.(*searchState)
}

type searchCallbacks struct {
	memResult uintptr
	filter    uintptr
	yaraMatch uintptr
}

// The native callbacks are created once: purego never frees them.
var searchCallbackPtrs = sync.OnceValue(func() searchCallbacks {
	return searchCallbacks{
		memResult: purego.NewCallback(memSearchResultCallback),
		filter:    purego.NewCallback(searchFilterCallback),
		yaraMatch: purego.NewCallback(yaraMatchCallback),
	}
})

func cBool(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}

// memSearchResultCallback implements
// BOOL pfnResultOptCB(PVMMDLL_MEM_SEARCH_CONTEXT ctx, QWORD va, DWORD iSearch).
// All arguments are uintptr-sized so the callback works on Windows too.
func memSearchResultCallback(ctx, va, iSearch uintptr) uintptr {
	st := lookupSearchState((*memSearchContextInternal)(unsafe.Pointer(ctx)).PvUserPtrOpt)
	if st == nil || st.onHit == nil {
		return 0
	}
	cont := st.call(func() bool { return st.onHit(uint64(va), int(uint32(iSearch))) })
	if !cont {
		st.stopped = true
	}
	return cBool(cont)
}

// searchFilterCallback implements the filter callback of both searches:
// BOOL pfnFilterOptCB(ctx, PVMMDLL_MAP_PTEENTRY pePte, PVMMDLL_MAP_VADENTRY peVad).
func searchFilterCallback(ctx, pte, vad uintptr) uintptr {
	st := lookupSearchState((*memSearchContextInternal)(unsafe.Pointer(ctx)).PvUserPtrOpt)
	if st == nil || st.filter == nil {
		return 1
	}
	var region SearchRegion
	switch {
	case pte != 0:
		e := convertPteEntry((*pteEntryInternal)(unsafe.Pointer(pte)))
		region.Pte = &e
	case vad != 0:
		e := convertVadEntry((*vadEntryInternal)(unsafe.Pointer(vad)))
		region.Vad = &e
	default:
		return 1
	}
	return cBool(st.call(func() bool { return st.filter(region) }))
}

// yaraMatchCallback implements VMMYARA_SCAN_MEMORY_CALLBACK:
// BOOL cb(PVOID pvContext, PVMMYARA_RULE_MATCH pRuleMatch, PBYTE pbBuffer, SIZE_T cbBuffer).
// MemProcFS passes the config's pvUserPtrOpt as pvContext.
func yaraMatchCallback(pvContext, pRuleMatch, _, _ uintptr) uintptr {
	st := lookupSearchState(pvContext)
	if st == nil || st.onYara == nil || pRuleMatch == 0 {
		return 0
	}
	m := (*yaraRuleMatchInternal)(unsafe.Pointer(pRuleMatch))
	if m.DwVersion != yaraRuleMatchVersion {
		return 0
	}
	match := convertYaraMatch(m, *st.vaCurrent)
	cont := st.call(func() bool { return st.onYara(match) })
	if !cont {
		// Returning FALSE only ends the scan of the current chunk, so ask
		// MemProcFS to stop the whole search as well.
		st.stopped = true
		atomic.StoreInt32(st.abort, 1)
	}
	return cBool(cont)
}

func convertYaraMatch(m *yaraRuleMatchInternal, base uint64) *YaraMatch {
	out := &YaraMatch{Rule: ffi.CStringToGo(m.SzRuleIdentifier)}
	for i := range min(int(m.CTags), len(m.SzTags)) {
		out.Tags = append(out.Tags, ffi.CStringToGo(m.SzTags[i]))
	}
	for i := range min(int(m.CMeta), len(m.Meta)) {
		out.Meta = append(out.Meta, YaraMeta{
			Identifier: ffi.CStringToGo(m.Meta[i].SzIdentifier),
			Value:      ffi.CStringToGo(m.Meta[i].SzString),
		})
	}
	for i := range min(int(m.CStrings), len(m.Strings)) {
		s := &m.Strings[i]
		ys := YaraString{Pattern: ffi.CStringToGo(s.SzString)}
		for j := range min(int(s.CMatch), len(s.CbMatchOffset)) {
			ys.Addresses = append(ys.Addresses, base+uint64(s.CbMatchOffset[j]))
		}
		out.Strings = append(out.Strings, ys)
	}
	return out
}
