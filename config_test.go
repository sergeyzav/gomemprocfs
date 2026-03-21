package memprocfs

import (
	"testing"
)

func TestConfigGet(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	majorVersion, err := vmm.ConfigGet(OptConfigVmmVersionMajor)
	if err != nil {
		t.Fatalf("ConfigGet(OptConfigVmmVersionMajor) failed: %v", err)
	}
	if majorVersion == 0 {
		t.Error("Expected VMM Major Version to be non-zero")
	}
	t.Logf("VMM Major Version: %d", majorVersion)

	minorVersion, err := vmm.ConfigGet(OptConfigVmmVersionMinor)
	if err != nil {
		t.Fatalf("ConfigGet(OptConfigVmmVersionMinor) failed: %v", err)
	}
	if minorVersion == 0 {
		t.Error("Expected VMM Minor Version to be non-zero")
	}
	t.Logf("VMM Minor Version: %d", minorVersion)

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
