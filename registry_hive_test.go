package memprocfs

import (
	"testing"
)

func TestHiveReadEx(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	hives, err := vmm.GetRegistryHives()
	if err != nil || len(hives) == 0 {
		t.Skip("could not get registry hives")
	}

	foundData := false
	for _, hive := range hives {
		t.Logf("Using hive: %q (va=0x%X)", hive.Name, hive.BaseAddress)

		// Read the first 512 bytes of the hive body (ra=0, skips regf header).
		data, n, err := vmm.HiveReadEx(hive.BaseAddress, 0, 512, MemFlagNone)
		if err == nil && n > 0 && len(data) > 0 {
			t.Logf("HiveReadEx: read %d bytes from hive body %q", n, hive.Name)
			foundData = true
			break
		}
	}
	
	if !foundData {
		t.Fatal("expected non-zero data from HiveReadEx in at least one hive")
	}
}

func TestHiveReadExOffset(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	hives, err := vmm.GetRegistryHives()
	if err != nil || len(hives) == 0 {
		t.Skip("could not get registry hives")
	}

	va := hives[0].BaseAddress

	all, _, err := vmm.HiveReadEx(va, 0, 512, MemFlagNone)
	if err != nil || len(all) < 16 {
		t.Skipf("base read failed: %v", err)
	}

	// Read same data at offset 8 and compare overlap.
	const off = 8
	partial, _, err := vmm.HiveReadEx(va, off, uint32(len(all)-off), MemFlagNone)
	if err != nil {
		t.Fatalf("HiveReadEx with offset failed: %v", err)
	}
	overlap := len(partial)
	if string(partial[:overlap]) != string(all[off:off+overlap]) {
		t.Errorf("offset read mismatch at offset %d", off)
	}
	t.Logf("offset read: %d bytes match ✓", overlap)
}
