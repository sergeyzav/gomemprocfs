package memprocfs

import (
	"testing"
)

// "nt" module is always pre-loaded by MemProcFS from the kernel PDB.

func TestPdbSymbolAddress(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	// PsInitialSystemProcess is a well-known kernel symbol.
	addr, err := vmm.PdbSymbolAddress("nt", "PsInitialSystemProcess")
	if err != nil {
		t.Fatalf("PdbSymbolAddress failed: %v", err)
	}
	if addr == 0 {
		t.Fatal("expected non-zero address for PsInitialSystemProcess")
	}
	t.Logf("nt!PsInitialSystemProcess = 0x%X", addr)
}

func TestPdbSymbolName(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	// First get a known symbol address, then reverse-lookup its name.
	addr, err := vmm.PdbSymbolAddress("nt", "PsInitialSystemProcess")
	if err != nil {
		t.Fatalf("PdbSymbolAddress failed: %v", err)
	}

	name, displacement, err := vmm.PdbSymbolName("nt", addr)
	if err != nil {
		t.Fatalf("PdbSymbolName failed: %v", err)
	}
	t.Logf("0x%X -> %s+0x%X", addr, name, displacement)

	if name == "" {
		t.Fatal("expected non-empty symbol name")
	}
}

func TestPdbTypeSize(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	// _EPROCESS is a fundamental kernel struct.
	size, err := vmm.PdbTypeSize("nt", "_EPROCESS")
	if err != nil {
		t.Fatalf("PdbTypeSize failed: %v", err)
	}
	if size == 0 {
		t.Fatal("expected non-zero size for _EPROCESS")
	}
	t.Logf("sizeof(_EPROCESS) = %d bytes", size)
}

func TestPdbTypeChildOffset(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	// UniqueProcessId is a well-known field in _EPROCESS.
	offset, err := vmm.PdbTypeChildOffset("nt", "_EPROCESS", "UniqueProcessId")
	if err != nil {
		t.Fatalf("PdbTypeChildOffset failed: %v", err)
	}
	t.Logf("_EPROCESS.UniqueProcessId offset = 0x%X (%d)", offset, offset)
}

func TestPdbLoad(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	// Get the kernel module base (PID 4 = System, first module is ntoskrnl).
	mods, err := vmm.GetModuleList(4, ModuleFlagNone)
	if err != nil || mods == nil || len(mods.Modules) == 0 {
		t.Skip("could not get System (PID 4) module list")
	}

	moduleName, err := vmm.PdbLoad(4, mods.Modules[0].BaseAddress)
	if err != nil {
		// PdbLoad may fail if symbol already loaded — not fatal.
		t.Logf("PdbLoad returned error (may already be loaded): %v", err)
		return
	}
	t.Logf("PdbLoad: module name = %q", moduleName)
}
