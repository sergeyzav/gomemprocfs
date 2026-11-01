package memprocfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// dosStub is the first 32 bytes of the DOS stub message found at offset 0x4E
// of nearly every PE image.
var dosStub = []byte("This program cannot be run in DO")

const dosStubOffset = 0x4E

func TestBuildSearchEntries(t *testing.T) {
	long := make([]byte, memSearchMaxLength+1)
	long[0] = 1
	tests := []struct {
		name     string
		patterns []SearchPattern
		wantErr  bool
	}{
		{"no patterns", nil, true},
		{"empty bytes", []SearchPattern{{}}, true},
		{"too long", []SearchPattern{{Bytes: long}}, true},
		{"mask length mismatch", []SearchPattern{{Bytes: []byte("MZ"), Mask: []byte{0}}}, true},
		{"all zero", []SearchPattern{{Bytes: []byte{0, 0, 0}}}, true},
		{"ok", []SearchPattern{{Bytes: []byte("MZ")}, {Bytes: []byte{0x4D, 0}, Mask: []byte{0, 0xFF}, Align: 0x1000}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries, err := buildSearchEntries(tt.patterns)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			e := entries[1]
			if e.Cb != 2 || e.CbAlign != 0x1000 || e.Pb[0] != 0x4D || e.PbSkipMask[1] != 0xFF {
				t.Errorf("unexpected entry %+v", e)
			}
		})
	}
}

// explorerImage returns the pid and image range of explorer.exe in the dump.
func explorerImage(t *testing.T, vmm *Vmm) (uint32, *SearchOptions, uint64) {
	t.Helper()
	pid, err := vmm.GetPidByName("explorer.exe")
	if err != nil {
		t.Fatalf("GetPidByName failed: %v", err)
	}
	mod, err := vmm.GetModuleByName(pid, "explorer.exe", ModuleFlagNone)
	if err != nil {
		t.Fatalf("GetModuleByName failed: %v", err)
	}
	opts := &SearchOptions{
		MinAddress: mod.BaseAddress,
		MaxAddress: mod.BaseAddress + uint64(mod.ImageSize),
		// The VAD map of this dump lacks the explorer.exe image; the PTE map has it.
		ForcePTE: true,
	}
	return pid, opts, mod.BaseAddress
}

func TestMemSearch(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()
	pid, opts, base := explorerImage(t, vmm)

	hits, err := vmm.MemSearch(context.Background(), pid, []SearchPattern{{Bytes: dosStub}}, opts)
	if err != nil {
		t.Fatalf("MemSearch failed: %v", err)
	}
	if !slices.Contains(hits, base+dosStubOffset) {
		t.Fatalf("hits %#x do not contain DOS stub at %#x", hits, base+dosStubOffset)
	}
	t.Logf("MemSearch: %d hits", len(hits))
}

func TestMemSearchMaskAlign(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()
	pid, opts, base := explorerImage(t, vmm)

	// "M?" at page-aligned addresses: the image starts with "MZ".
	p := SearchPattern{Bytes: []byte{'M', 0}, Mask: []byte{0, 0xFF}, Align: 0x1000}
	hits, err := vmm.MemSearch(context.Background(), pid, []SearchPattern{p}, opts)
	if err != nil {
		t.Fatalf("MemSearch failed: %v", err)
	}
	if !slices.Contains(hits, base) {
		t.Fatalf("hits %#x do not contain image base %#x", hits, base)
	}
	for _, va := range hits {
		if va%0x1000 != 0 {
			t.Errorf("hit %#x is not page aligned", va)
		}
	}
}

func TestMemSearchFunc(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()
	pid, opts, base := explorerImage(t, vmm)

	patterns := []SearchPattern{{Bytes: []byte("zzzz-no-such-bytes-zzzz")}, {Bytes: dosStub}}
	var calls int
	var gotVA uint64
	var gotPattern int
	err := vmm.MemSearchFunc(context.Background(), pid, patterns, opts, func(va uint64, pattern int) bool {
		calls++
		gotVA, gotPattern = va, pattern
		return false // stop at the first hit
	})
	if err != nil {
		t.Fatalf("MemSearchFunc failed: %v", err)
	}
	if calls != 1 {
		t.Fatalf("callback called %d times, want 1", calls)
	}
	if gotVA != base+dosStubOffset || gotPattern != 1 {
		t.Errorf("got hit %#x pattern %d, want %#x pattern 1", gotVA, gotPattern, base+dosStubOffset)
	}
}

func TestMemSearchFuncMaxResults(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()
	pid, opts, _ := explorerImage(t, vmm)
	opts.MaxResults = 3

	var calls int
	err := vmm.MemSearchFunc(context.Background(), pid, []SearchPattern{{Bytes: []byte{0xCC}}}, opts, func(uint64, int) bool {
		calls++
		return true
	})
	if err != nil {
		t.Fatalf("MemSearchFunc failed: %v", err)
	}
	if calls != 3 {
		t.Fatalf("callback called %d times, want 3", calls)
	}
}

func TestMemSearchFilter(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()
	pid, opts, _ := explorerImage(t, vmm)

	var regions int
	opts.Filter = func(r SearchRegion) bool {
		if (r.Pte == nil) == (r.Vad == nil) {
			t.Errorf("region must have exactly one of Pte and Vad: %+v", r)
		}
		regions++
		return false // skip everything
	}
	hits, err := vmm.MemSearch(context.Background(), pid, []SearchPattern{{Bytes: dosStub}}, opts)
	if err != nil {
		t.Fatalf("MemSearch failed: %v", err)
	}
	if regions == 0 {
		t.Fatal("filter was never called")
	}
	if len(hits) != 0 {
		t.Fatalf("got %d hits with every region filtered out", len(hits))
	}
}

func TestMemSearchCanceled(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := vmm.MemSearch(ctx, 4, []SearchPattern{{Bytes: dosStub}}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestMemSearchCancelFromCallback(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()
	pid, opts, _ := explorerImage(t, vmm)

	// Cancel the context from inside the search: MemProcFS must notice the
	// abort flag at the next chunk and the call must return ctx.Err().
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts.Filter = func(SearchRegion) bool {
		cancel()
		return true
	}
	_, err := vmm.MemSearch(ctx, pid, []SearchPattern{{Bytes: dosStub}}, opts)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestMemSearchFuncPanic(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()
	pid, opts, _ := explorerImage(t, vmm)

	defer func() {
		if r := recover(); r != "boom" {
			t.Fatalf("recovered %v, want boom", r)
		}
	}()
	_ = vmm.MemSearchFunc(context.Background(), pid, []SearchPattern{{Bytes: dosStub}}, opts, func(uint64, int) bool {
		panic("boom")
	})
	t.Fatal("MemSearchFunc did not re-panic")
}

const dosStubRule = `
rule dos_stub : pe {
	meta:
		author = "test"
	strings:
		$a = "This program cannot be run in DOS mode"
	condition:
		$a
}`

// requireYara skips the test when the vmmyara library is not next to vmmdll.
func requireYara(t *testing.T) {
	t.Helper()
	dir := filepath.Dir(os.Getenv("VMM_DLL_PATH"))
	for _, name := range []string{"vmmyara.dylib", "vmmyara.so", "vmmyara.dll"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return
		}
	}
	t.Skip("vmmyara library not found next to VMM_DLL_PATH")
}

func TestYaraSearch(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()
	requireYara(t)
	pid, opts, base := explorerImage(t, vmm)

	hits, err := vmm.YaraSearch(context.Background(), pid, []string{dosStubRule}, opts)
	if err != nil {
		t.Fatalf("YaraSearch failed: %v", err)
	}
	if !slices.Contains(hits, base+dosStubOffset) {
		t.Fatalf("hits %#x do not contain DOS stub at %#x", hits, base+dosStubOffset)
	}
}

func TestYaraSearchFunc(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()
	requireYara(t)
	pid, opts, base := explorerImage(t, vmm)

	var matches []*YaraMatch
	hits, err := vmm.YaraSearchFunc(context.Background(), pid, []string{dosStubRule}, opts, func(m *YaraMatch) bool {
		matches = append(matches, m)
		return true
	})
	if err != nil {
		t.Fatalf("YaraSearchFunc failed: %v", err)
	}
	if !slices.Contains(hits, base+dosStubOffset) {
		t.Fatalf("hits %#x do not contain DOS stub at %#x", hits, base+dosStubOffset)
	}
	if len(matches) == 0 {
		t.Fatal("callback was never called")
	}
	m := matches[0]
	if m.Rule != "dos_stub" {
		t.Errorf("Rule = %q, want dos_stub", m.Rule)
	}
	if !slices.Contains(m.Tags, "pe") {
		t.Errorf("Tags = %q, want pe", m.Tags)
	}
	if !slices.Contains(m.Meta, YaraMeta{Identifier: "author", Value: "test"}) {
		t.Errorf("Meta = %+v, want author=test", m.Meta)
	}
	found := false
	for _, mm := range matches {
		for _, s := range mm.Strings {
			if s.Pattern == "This program cannot be run in DOS mode" && slices.Contains(s.Addresses, base+dosStubOffset) {
				found = true
			}
		}
	}
	if !found {
		for _, mm := range matches {
			t.Logf("match %+v", *mm)
		}
		t.Errorf("no DOS stub string match at %#x", base+dosStubOffset)
	}
}

func TestYaraSearchFuncStop(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()
	requireYara(t)
	pid, _, _ := explorerImage(t, vmm)

	var calls int
	hits, err := vmm.YaraSearchFunc(context.Background(), pid, []string{dosStubRule}, nil, func(*YaraMatch) bool {
		calls++
		return false
	})
	if err != nil {
		t.Fatalf("YaraSearchFunc failed: %v", err)
	}
	if calls != 1 {
		t.Fatalf("callback called %d times, want 1", calls)
	}
	if hits != nil {
		t.Errorf("hits = %#x, want nil after stop", hits)
	}
}

func TestYaraSearchBadRule(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()
	requireYara(t)
	pid, opts, _ := explorerImage(t, vmm)

	_, err := vmm.YaraSearch(context.Background(), pid, []string{"rule broken { condition: "}, opts)
	if !errors.Is(err, ErrSearchFailed) {
		t.Fatalf("err = %v, want ErrSearchFailed", err)
	}
}
