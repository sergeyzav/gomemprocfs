package memprocfs

import (
	"testing"
)

func TestGetServiceList(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	services, err := vmm.GetServiceList()
	if err != nil {
		t.Fatalf("Failed to get service list: %v", err)
	}

	if services == nil {
		t.Fatal("Service list is nil")
	}

	t.Logf("Found %d services", len(services.Entries))

	if len(services.Entries) > 0 {
		first := services.Entries[0]
		t.Logf("First service: Name=%s, PID=%d, Status=%d", first.ServiceName, first.PID, first.Status.CurrentState)
	}
}