package memprocfs

import (
	"os"
	"testing"
)

// setupVmm is a helper function to initialize the Vmm instance for tests.
// It reads environment variables, initializes the Vmm, and handles errors/skips.
// It returns the Vmm instance, and the caller is responsible for closing it.
func setupVmm(t *testing.T) *Vmm {
	t.Helper()

	dllPath := os.Getenv("VMM_DLL_PATH")
	memdumpPath := os.Getenv("MEMDUMP_PATH")

	if dllPath == "" || memdumpPath == "" {
		t.Skip("Skipping test: VMM_DLL_PATH and/or MEMDUMP_PATH environment variables not set")
	}

	vmm, err := NewVmm(
		dllPath,
		WithDevice(memdumpPath),
		WithWaitInitialize(),
		WithVerbose(),
		WithPrintf(),
	)
	if err != nil {
		t.Fatalf("Failed to initialize Vmm: %v", err)
	}
	return vmm
}

func TestConfigGet(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	// Test getting VMM Major Version
	majorVersion, err := vmm.ConfigGet(OptConfigVmmVersionMajor)
	if err != nil {
		t.Fatalf("ConfigGet(OptConfigVmmVersionMajor) failed: %v", err)
	}
	if majorVersion == 0 {
		t.Error("Expected VMM Major Version to be non-zero")
	}
	t.Logf("VMM Major Version: %d", majorVersion)

	// Test getting VMM Minor Version
	minorVersion, err := vmm.ConfigGet(OptConfigVmmVersionMinor)
	if err != nil {
		t.Fatalf("ConfigGet(OptConfigVmmVersionMinor) failed: %v", err)
	}
	if minorVersion == 0 {
		t.Error("Expected VMM Minor Version to be non-zero")
	}
	t.Logf("VMM Minor Version: %d", minorVersion)

	// Test getting VMM Revision
	revision, err := vmm.ConfigGet(OptConfigVmmVersionRevision)
	if err != nil {
		t.Fatalf("ConfigGet(OptConfigVmmVersionRevision) failed: %v", err)
	}
	t.Logf("VMM Revision: %d", revision)
}

func TestConfigSet(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	err := vmm.ConfigSet(OptCoreVerbose, 1)
	if err != nil {
		t.Fatalf("ConfigSet(OptCoreVerbose, 1) failed: %v", err)
	}
}

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
