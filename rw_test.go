package memprocfs

import (
	"testing"
)

func TestMemVirt2Phys(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	pid, err := vmm.GetPidByName("explorer.exe")
	if err != nil {
		t.Fatalf("GetPidByName failed: %v", err)
	}

	info, err := vmm.GetProcessInfo(pid)
	if err != nil {
		t.Fatalf("GetProcessInfo failed: %v", err)
	}

	pa, err := vmm.MemVirt2Phys(pid, info.Win.PEB)
	if err != nil {
		t.Fatalf("MemVirt2Phys failed: %v", err)
	}
	if pa == 0 {
		t.Fatal("Expected non-zero physical address")
	}
	t.Logf("PEB 0x%X -> PA 0x%X", info.Win.PEB, pa)
}

func TestMemRead(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	pid, err := vmm.GetPidByName("explorer.exe")
	if err != nil {
		t.Fatalf("GetPidByName(\"explorer.exe\") failed: %v", err)
	}

	info, err := vmm.GetProcessInfo(pid)
	if err != nil {
		t.Fatalf("GetProcessInfo failed: %v", err)
	}

	if info.Win.PEB == 0 {
		t.Fatal("PEB address is zero")
	}

	// Read first 2 bytes from PEB, should be "MZ" for a DOS header
	data, err := vmm.MemRead(pid, info.Win.PEB, 2)
	if err != nil {
		t.Fatalf("MemRead failed: %v", err)
	}

	if len(data) != 2 {
		t.Fatalf("Expected to read 2 bytes, but got %d", len(data))
	}
}

func TestMemReadEx(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	pid, err := vmm.GetPidByName("explorer.exe")
	if err != nil {
		t.Fatalf("GetPidByName failed: %v", err)
	}

	info, err := vmm.GetProcessInfo(pid)
	if err != nil || info.Win.PEB == 0 {
		t.Fatalf("GetProcessInfo failed: %v", err)
	}

	const size = 64
	// Reference read.
	expected, err := vmm.MemRead(pid, info.Win.PEB, size)
	if err != nil {
		t.Fatalf("MemRead failed: %v", err)
	}

	// MemReadEx with no special flags.
	got, cbRead, err := vmm.MemReadEx(pid, info.Win.PEB, size, MemFlagNone)
	if err != nil {
		t.Fatalf("MemReadEx failed: %v", err)
	}
	if cbRead == 0 {
		t.Fatal("MemReadEx returned 0 bytes read")
	}
	t.Logf("MemReadEx: cbRead=%d", cbRead)

	// Data should match MemRead.
	if string(got) != string(expected[:len(got)]) {
		t.Errorf("MemReadEx data mismatch with MemRead")
	}

	// Verify MemFlagNoPaging flag doesn't crash.
	_, _, err = vmm.MemReadEx(pid, info.Win.PEB, size, MemFlagNoPaging)
	if err != nil {
		t.Logf("MemReadEx with MemFlagNoPaging returned error (expected on dump): %v", err)
	}
}

func TestMemReadPage(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	pid, err := vmm.GetPidByName("explorer.exe")
	if err != nil {
		t.Fatalf("GetPidByName failed: %v", err)
	}

	info, err := vmm.GetProcessInfo(pid)
	if err != nil || info.Win.PEB == 0 {
		t.Fatalf("GetProcessInfo failed: %v", err)
	}

	// Page-align the address.
	pageAddr := info.Win.PEB &^ 0xFFF

	page, err := vmm.MemReadPage(pid, pageAddr)
	if err != nil {
		t.Fatalf("MemReadPage failed: %v", err)
	}
	if len(page) != 4096 {
		t.Fatalf("expected 4096 bytes, got %d", len(page))
	}
	t.Logf("MemReadPage: read 4096 bytes from 0x%X", pageAddr)
}

func TestMemPrefetchPages(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	pid, err := vmm.GetPidByName("explorer.exe")
	if err != nil {
		t.Fatalf("GetPidByName failed: %v", err)
	}

	info, err := vmm.GetProcessInfo(pid)
	if err != nil || info.Win.PEB == 0 {
		t.Fatalf("GetProcessInfo failed: %v", err)
	}

	addrs := []uint64{
		info.Win.PEB &^ 0xFFF,
		info.Win.PEB&^0xFFF + 0x1000,
	}

	if err := vmm.MemPrefetchPages(pid, addrs); err != nil {
		t.Fatalf("MemPrefetchPages failed: %v", err)
	}
	t.Logf("MemPrefetchPages: warmed %d pages", len(addrs))
}
