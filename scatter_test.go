package memprocfs

import (
	"bytes"
	"testing"
)

func TestScatterRead(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	pids, err := vmm.GetPidList()
	if err != nil || len(pids) == 0 {
		t.Fatal("no PIDs found")
	}
	pid := pids[0]

	mods, err := vmm.GetModuleList(pid)
	if err != nil || mods == nil || len(mods.Modules) == 0 {
		t.Skipf("no modules for PID %d, skipping", pid)
	}
	base := mods.Modules[0].BaseAddress
	const readSize = 64

	// Reference read via MemRead.
	expected, err := vmm.MemRead(pid, base, readSize)
	if err != nil || len(expected) == 0 {
		t.Skipf("MemRead failed for PID %d base=0x%X: %v", pid, base, err)
	}

	// Same region via scatter.
	hS, err := vmm.ScatterInitialize(pid, MemFlagNone)
	if err != nil {
		t.Fatalf("ScatterInitialize failed: %v", err)
	}
	defer hS.Close()

	if err := hS.Prepare(base, readSize); err != nil {
		t.Fatalf("Prepare failed: %v", err)
	}
	if err := hS.ExecuteRead(); err != nil {
		t.Fatalf("ExecuteRead failed: %v", err)
	}

	got, err := hS.Read(base, readSize)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("scatter read returned empty data")
	}

	if !bytes.Equal(expected[:len(got)], got) {
		t.Errorf("data mismatch:\n  MemRead: %x\n  Scatter: %x", expected[:len(got)], got)
	}
	t.Logf("PID=%d base=0x%X: scatter %d bytes matches MemRead ✓", pid, base, len(got))
}

func TestScatterMultipleRanges(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	pids, err := vmm.GetPidList()
	if err != nil || len(pids) == 0 {
		t.Fatal("no PIDs found")
	}
	pid := pids[0]

	mods, err := vmm.GetModuleList(pid)
	if err != nil || mods == nil || len(mods.Modules) < 2 {
		t.Skipf("need at least 2 modules for PID %d", pid)
	}

	type region struct {
		va uint64
		cb uint32
	}
	regions := []region{
		{mods.Modules[0].BaseAddress, 64},
		{mods.Modules[1].BaseAddress, 64},
	}

	hS, err := vmm.ScatterInitialize(pid, MemFlagNone)
	if err != nil {
		t.Fatalf("ScatterInitialize failed: %v", err)
	}
	defer hS.Close()

	for _, r := range regions {
		if err := hS.Prepare(r.va, r.cb); err != nil {
			t.Fatalf("Prepare 0x%X failed: %v", r.va, err)
		}
	}
	if err := hS.ExecuteRead(); err != nil {
		t.Fatalf("ExecuteRead failed: %v", err)
	}

	for _, r := range regions {
		data, err := hS.Read(r.va, r.cb)
		if err != nil {
			t.Errorf("Read 0x%X failed: %v", r.va, err)
			continue
		}
		t.Logf("0x%X: %d bytes read", r.va, len(data))
	}
}

func TestScatterClear(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	pids, _ := vmm.GetPidList()
	if len(pids) == 0 {
		t.Skip("no PIDs found")
	}
	pid := pids[0]

	mods, err := vmm.GetModuleList(pid)
	if err != nil || mods == nil || len(mods.Modules) == 0 {
		t.Skipf("no modules for PID %d", pid)
	}
	base := mods.Modules[0].BaseAddress

	hS, err := vmm.ScatterInitialize(pid, MemFlagNone)
	if err != nil {
		t.Fatalf("ScatterInitialize failed: %v", err)
	}
	defer hS.Close()

	// First round.
	if err := hS.Prepare(base, 32); err != nil {
		t.Fatalf("Prepare failed: %v", err)
	}
	if err := hS.ExecuteRead(); err != nil {
		t.Fatalf("ExecuteRead failed: %v", err)
	}

	// Clear and reuse with the same handle.
	if err := hS.Clear(pid, MemFlagNone); err != nil {
		t.Fatalf("Clear failed: %v", err)
	}

	// Second round.
	if err := hS.Prepare(base, 32); err != nil {
		t.Fatalf("Prepare (2nd) failed: %v", err)
	}
	if err := hS.ExecuteRead(); err != nil {
		t.Fatalf("ExecuteRead (2nd) failed: %v", err)
	}

	data, err := hS.Read(base, 32)
	if err != nil {
		t.Fatalf("Read (2nd) failed: %v", err)
	}
	t.Logf("2nd round: %d bytes from 0x%X ✓", len(data), base)
}
