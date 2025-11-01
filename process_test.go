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

func TestGetVadList(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	pid, err := vmm.GetPidByName("explorer.exe")
	if err != nil {
		t.Fatalf("GetPidByName(\"explorer.exe\") failed: %v", err)
	}

	vadList, err := vmm.GetVadList(pid, true)
	if err != nil {
		t.Fatalf("GetVadList failed: %v", err)
	}

	if vadList.Version != MapVADVersion {
		t.Errorf("VadList version mismatch: expected %d, got %d", MapVADVersion, vadList.Version)
	}

	if len(vadList.Vads) != int(vadList.Count) {
		t.Errorf("VAD count mismatch: expected %d, got %d", vadList.Count, len(vadList.Vads))
	}

	if len(vadList.Vads) == 0 {
		t.Fatal("VAD list is empty")
	}

	t.Logf("Found %d VADs for PID %d", len(vadList.Vads), pid)
}

func TestGetHandleList(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	pid, err := vmm.GetPidByName("explorer.exe")
	if err != nil {
		t.Fatalf("GetPidByName(\"explorer.exe\") failed: %v", err)
	}

	handleList, err := vmm.GetHandleList(pid)
	if err != nil {
		t.Fatalf("GetHandleList failed: %v", err)
	}

	if handleList.Version != MapHandleVersion {
		t.Errorf("HandleList version mismatch: expected %d, got %d", MapHandleVersion, handleList.Version)
	}

	if len(handleList.Handles) != int(handleList.Count) {
		t.Errorf("Handle count mismatch: expected %d, got %d", handleList.Count, len(handleList.Handles))
	}

	if len(handleList.Handles) == 0 {
		t.Fatal("Handle list is empty")
	}

	t.Logf("Found %d handles for PID %d", len(handleList.Handles), pid)
}

func TestGetEatList(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	pid, err := vmm.GetPidByName("explorer.exe")
	if err != nil {
		t.Fatalf("Failed to get PID for explorer.exe: %v", err)
	}

	eatList, err := vmm.GetEatList(pid, "kernel32.dll")
	if err != nil {
		t.Fatalf("GetEatList failed: %v", err)
	}

	if len(eatList.Entries) != int(eatList.Count) {
		t.Errorf("EAT entry count mismatch: expected %d, got %d", eatList.Count, len(eatList.Entries))
	}

	found := false
	for _, entry := range eatList.Entries {
		if entry.FunctionName == "CreateFileA" {
			found = true
			t.Logf("Found CreateFileA at address: 0x%x", entry.FunctionAddress)
			break
		}
	}

	if !found {
		t.Error("CreateFileA not found in kernel32.dll exports")
	}
}

func TestGetIatList(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	pid, err := vmm.GetPidByName("explorer.exe")
	if err != nil {
		t.Fatalf("Failed to get PID for explorer.exe: %v", err)
	}

	iatList, err := vmm.GetIatList(pid, "user32.dll")
	if err != nil {
		t.Fatalf("GetIatList failed: %v", err)
	}

	if iatList.Version != MapIATVersion {
		t.Errorf("IatList version mismatch: expected %d, got %d", MapIATVersion, iatList.Version)
	}

	if len(iatList.Entries) != int(iatList.Count) {
		t.Errorf("IAT entry count mismatch: expected %d, got %d", iatList.Count, len(iatList.Entries))
	}

	if iatList.ModuleBaseAddress == 0 {
		t.Error("ModuleBaseAddress is zero")
	}

	found := false
	for _, entry := range iatList.Entries {
		if entry.FunctionName == "NtQuerySystemInformation" {
			found = true
			t.Logf("Found NtQuerySystemInformation at address: 0x%x", entry.FunctionAddress)
			break
		}
	}

	if !found {
		t.Error("NtQuerySystemInformation not found in ntdll.dll imports")
	}
}

func TestGetUnloadedModuleList(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	pid, err := vmm.GetPidByName("explorer.exe")
	if err != nil {
		t.Fatalf("GetPidByName(\"explorer.exe\") failed: %v", err)
	}

	unloadedModuleList, err := vmm.GetUnloadedModuleList(pid)
	if err != nil {
		t.Fatalf("GetUnloadedModuleList failed: %v", err)
	}

	if unloadedModuleList.Version != MapUnloadedModuleVersion {
		t.Errorf("UnloadedModuleList version mismatch: expected %d, got %d", MapUnloadedModuleVersion, unloadedModuleList.Version)
	}

	if len(unloadedModuleList.Modules) != int(unloadedModuleList.Count) {
		t.Errorf("Unloaded module count mismatch: expected %d, got %d", unloadedModuleList.Count, len(unloadedModuleList.Modules))
	}

	t.Logf("Found %d unloaded modules for PID %d", len(unloadedModuleList.Modules), pid)
}
