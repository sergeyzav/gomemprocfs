package memprocfs

import "testing"

func TestGetKDeviceList(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	devices, err := vmm.GetKDeviceList()
	if err != nil {
		t.Fatalf("GetKDeviceList() failed: %v", err)
	}
	if devices == nil || devices.Count == 0 {
		t.Fatal("Expected non-empty device list")
	}
	t.Logf("Found %d kernel devices", devices.Count)
	t.Logf("First device: type=%s  driver=0x%X", devices.Entries[0].DeviceTypeName, devices.Entries[0].VaDriverObject)
}
