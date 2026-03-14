package memprocfs

import (
	"fmt"
	"unsafe"
)

// ThreadCallstackEntry represents a single entry in the thread callstack.
type ThreadCallstackEntry struct {
	Index          uint32
	RegPresent     bool
	RetAddr        uint64
	RSP            uint64
	BaseSP         uint64
	Displacement   uint32
	ModuleName     string
	FunctionName   string
}

// threadCallstackEntryInternal mirrors the C struct VMMDLL_MAP_THREAD_CALLSTACKENTRY.
type threadCallstackEntryInternal struct {
	Index          uint32
	FRegPresent    uint32 // BOOL
	VaRetAddr      uint64
	VaRSP          uint64
	VaBaseSP       uint64
	_FutureUse1    uint32
	CbDisplacement uint32
	UszModule      uintptr
	UszFunction    uintptr
}

// threadCallstackInternal mirrors the C struct VMMDLL_MAP_THREAD_CALLSTACK.
type threadCallstackInternal struct {
	DwVersion   uint32
	_Reserved1  [6]uint32
	DwPID       uint32
	DwTID       uint32
	CbText      uint32
	UszText     uintptr
	PbMultiText uintptr
	CbMultiText uint32
	CMap        uint32
	// pMap (FAM) starts here
}

// ThreadCallstack contains the callstack for a thread.
type ThreadCallstack struct {
	Version   uint32
	PID       uint32
	TID       uint32
	Text      string
	MultiText string
	Count     uint32
	Entries   []ThreadCallstackEntry
}

// GetThreadCallstack retrieves the callstack for a specific thread.
func (vmm *Vmm) GetThreadCallstack(pid, tid uint32) (*ThreadCallstack, error) {
	var pCallstackMap *threadCallstackInternal
	// flags is usually 0
	success := vmmMapGetThreadCallstackU(vmm.vmmHandle, pid, tid, 0, &pCallstackMap)
	if !success {
		return nil, fmt.Errorf("GetThreadCallstack: failed for PID %d TID %d", pid, tid)
	}
	if pCallstackMap == nil {
		return nil, fmt.Errorf("GetThreadCallstack: nil map returned")
	}
	defer vmm.free(uintptr(unsafe.Pointer(pCallstackMap)))

	if pCallstackMap.CMap == 0 {
		return &ThreadCallstack{
			Version: pCallstackMap.DwVersion,
			PID:     pCallstackMap.DwPID,
			TID:     pCallstackMap.DwTID,
			Text:    cStringToGo(pCallstackMap.UszText),
			MultiText: string(unsafe.Slice((*byte)(unsafe.Pointer(pCallstackMap.PbMultiText)), pCallstackMap.CbMultiText)),
		}, nil
	}

	entriesInternal := FAM[threadCallstackInternal, threadCallstackEntryInternal](pCallstackMap, int(pCallstackMap.CMap))

	entries := make([]ThreadCallstackEntry, pCallstackMap.CMap)
	for i, entry := range entriesInternal {
		entries[i] = ThreadCallstackEntry{
			Index:        entry.Index,
			RegPresent:   entry.FRegPresent != 0,
			RetAddr:      entry.VaRetAddr,
			RSP:          entry.VaRSP,
			BaseSP:       entry.VaBaseSP,
			Displacement: entry.CbDisplacement,
			ModuleName:   cStringToGo(entry.UszModule),
			FunctionName: cStringToGo(entry.UszFunction),
		}
	}

	return &ThreadCallstack{
		Version:   pCallstackMap.DwVersion,
		PID:       pCallstackMap.DwPID,
		TID:       pCallstackMap.DwTID,
		Text:      cStringToGo(pCallstackMap.UszText),
		MultiText: string(unsafe.Slice((*byte)(unsafe.Pointer(pCallstackMap.PbMultiText)), pCallstackMap.CbMultiText)),
		Count:     pCallstackMap.CMap,
		Entries:   entries,
	}, nil
}
