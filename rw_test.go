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
