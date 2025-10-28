package memprocfs

import (
	"strings"
	"testing"
)

func TestGetRegistryHives(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	hives, err := vmm.GetRegistryHives()
	if err != nil {
		t.Fatalf("GetRegistryHives failed: %v", err)
	}

	if len(hives) == 0 {
		t.Fatal("No registry hives found")
	}

	t.Logf("Found %d registry hives", len(hives))

	// Check for a well-known hive
	foundSystem := false
	for _, hive := range hives {
		if strings.HasSuffix(strings.ToUpper(hive.Path), "\\SYSTEM") {
			foundSystem = true
			t.Logf("Found SYSTEM hive: %s", hive.Path)
			break
		}
	}

	if !foundSystem {
		t.Error("SYSTEM hive not found")
	}
}
