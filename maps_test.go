package memprocfs

import (
	"testing"
)

func TestGetModuleList(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	pid, err := vmm.GetPidByName("explorer.exe")
	if err != nil {
		t.Fatalf("GetPidByName(\"explorer.exe\") failed: %v", err)
	}

	moduleList, err := vmm.GetModuleList(pid)
	if err != nil {
		t.Fatalf("GetModuleList failed: %v", err)
	}

	if moduleList.Version != MapModuleVersion {
		t.Errorf("ModuleList version mismatch: expected %d, got %d", MapModuleVersion, moduleList.Version)
	}

	if len(moduleList.Modules) != int(moduleList.Count) {
		t.Errorf("Module count mismatch: expected %d, got %d", moduleList.Count, len(moduleList.Modules))
	}
}
