package memprocfs

import (
	"testing"
)

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
