package memprocfs

import (
	"testing"
)

func TestGetPidByName(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	pid, err := vmm.GetPidByName("explorer.exe")
	if err != nil {
		t.Fatalf("GetPidByName(\"explorer.exe\") failed: %v", err)
	}
	if pid == 0 {
		t.Fatal("Expected to find a non-zero PID for 'explorer.exe'")
	}
	t.Logf("Found PID for 'explorer.exe': %d", pid)
}

func TestGetProcessInfoString(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	pid, err := vmm.GetPidByName("explorer.exe")
	if err != nil {
		t.Fatalf("GetPidByName(\"explorer.exe\") failed: %v", err)
	}

	path, err := vmm.GetProcessInfoString(pid, ProcessInformationOptStringPathUserImage)
	if err != nil {
		t.Fatalf("GetProcessInfoString failed: %v", err)
	}
	if path == "" {
		t.Fatal("Expected a non-empty path for 'explorer.exe'")
	}
	t.Logf("Path for 'explorer.exe': %s", path)
}

func TestGetProcessInfo(t *testing.T) {
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

	t.Logf("Process Info for PID %d:", pid)
	t.Logf("  Name: %s", info.Name())
	t.Logf("  NameLong: %s", info.NameLong())
	t.Logf("  Parent PID: %d", info.ParentPID)
	t.Logf("  IsWow64: %v", info.Win.IsWow64 != 0)
	t.Logf("  PEB: 0x%X", info.Win.PEB)
}

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

func TestGetThreadList(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	pid, err := vmm.GetPidByName("explorer.exe")
	if err != nil {
		t.Fatalf("GetPidByName(\"explorer.exe\") failed: %v", err)
	}

	threadList, err := vmm.GetThreadList(pid)
	if err != nil {
		t.Fatalf("GetThreadList failed: %v", err)
	}

	if threadList.Version != MapThreadVersion {
		t.Errorf("ThreadList version mismatch: expected %d, got %d", MapThreadVersion, threadList.Version)
	}

	if len(threadList.Threads) != int(threadList.Count) {
		t.Errorf("Thread count mismatch: expected %d, got %d", threadList.Count, len(threadList.Threads))
	}

	if len(threadList.Threads) == 0 {
		t.Fatal("Thread list is empty")
	}

	t.Logf("Found %d threads for PID %d", len(threadList.Threads), pid)
}
