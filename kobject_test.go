package memprocfs

import "testing"

func TestGetKObjectList(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	objects, err := vmm.GetKObjectList()
	if err != nil {
		t.Fatalf("GetKObjectList() failed: %v", err)
	}
	if objects == nil || objects.Count == 0 {
		t.Fatal("Expected non-empty kernel object list")
	}
	t.Logf("Found %d kernel objects", objects.Count)
	t.Logf("First object: name=%s  type=%s  children=%d", objects.Entries[0].Name, objects.Entries[0].Type, len(objects.Entries[0].Children))
}
