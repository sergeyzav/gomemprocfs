package memprocfs

import "testing"

func TestGetKDriverList(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	drivers, err := vmm.GetKDriverList()
	if err != nil {
		t.Fatalf("GetKDriverList() failed: %v", err)
	}
	if drivers == nil || drivers.Count == 0 {
		t.Fatal("Expected non-empty driver list")
	}
	t.Logf("Found %d kernel drivers", drivers.Count)
	t.Logf("First driver: %s  path: %s", drivers.Entries[0].Name, drivers.Entries[0].Path)
}
