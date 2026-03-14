package memprocfs

import (
	"bytes"
	"testing"
)

func TestGetProcessDirectories(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	pid, err := vmm.GetPidByName("explorer.exe")
	if err != nil {
		t.Fatalf("GetPidByName failed: %v", err)
	}

	dirs, err := vmm.GetProcessDirectories(pid, "explorer.exe")
	if err != nil {
		t.Fatalf("GetProcessDirectories failed: %v", err)
	}

	// Directory 0 is Export Table, 1 is Import Table — at least one should be non-zero
	hasNonZero := false
	for _, d := range dirs {
		if d.VirtualAddress != 0 {
			hasNonZero = true
			break
		}
	}
	if !hasNonZero {
		t.Fatal("Expected at least one non-zero data directory")
	}
	t.Logf("Export dir: VA=0x%X size=%d", dirs[0].VirtualAddress, dirs[0].Size)
	t.Logf("Import dir: VA=0x%X size=%d", dirs[1].VirtualAddress, dirs[1].Size)
}

func TestGetProcessSections(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	// 1. Get process (e.g., explorer.exe)
	pid, err := vmm.GetPidByName("explorer.exe")
	if err != nil {
		t.Skip("Could not find explorer.exe to test process sections")
	}

	moduleName := "explorer.exe" // Or kernel32.dll, ntdll.dll
	t.Logf("Testing sections for PID: %d, Module: %s", pid, moduleName)

	sections, err := vmm.GetProcessSections(pid, moduleName)
	if err != nil {
		t.Fatalf("Failed to get process sections: %v", err)
	}

	if sections == nil {
		t.Fatal("Sections list is nil")
	}

	t.Logf("Found %d sections", len(sections))

	if len(sections) > 0 {
		for i, section := range sections {
			name := string(bytes.TrimRight(section.Name[:], "\x00"))
			t.Logf("#%d: Name=%s, VA=0x%x, Size=0x%x, Characteristics=0x%x",
				i, name, section.VirtualAddress, section.VirtualSize, section.Characteristics)
		}
	} else {
		t.Log("No sections found (might be possible but unusual for main module)")
	}
}
