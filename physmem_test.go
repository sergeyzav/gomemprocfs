package memprocfs

import (
	"testing"
)

func TestGetPhysMem(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	physMem, err := vmm.GetPhysMem()
	if err != nil {
		t.Fatalf("Failed to get physical memory map: %v", err)
	}

	if physMem == nil {
		t.Fatal("Physical memory map is nil")
	}

	t.Logf("Found %d physical memory ranges", len(physMem.Entries))

	if len(physMem.Entries) > 0 {
		for i, entry := range physMem.Entries {
			t.Logf("Range #%d: Base=0x%x, Size=0x%x", i, entry.BaseAddress, entry.Size)
		}
	} else {
		t.Log("No physical memory ranges found (this might be expected for some dumps, but unusual)")
	}
}