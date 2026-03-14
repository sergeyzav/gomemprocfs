package memprocfs

import "testing"

func TestGetPoolList(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	pool, err := vmm.GetPoolList(PoolMapFlagBig)
	if err != nil {
		t.Fatalf("GetPoolList() failed: %v", err)
	}
	if pool == nil || pool.Count == 0 {
		t.Fatal("Expected non-empty pool list")
	}
	t.Logf("Found %d pool allocations (big only)", pool.Count)
	e := pool.Entries[0]
	t.Logf("First entry: va=0x%X  tag=%s  size=%d  pool=%d", e.Va, string(e.Tag[:]), e.Size, e.TpPool)
}
