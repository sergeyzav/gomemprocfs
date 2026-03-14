package memprocfs

import (
	"testing"
)

func TestGetVadExList(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	// Find a VAD with VadExPages > 0 in the System process (PID 4).
	vads, err := vmm.GetVadList(4, false)
	if err != nil || vads == nil || len(vads.Vads) == 0 {
		t.Skip("could not get VAD list for PID 4")
	}

	var oPage, cPage uint32
	for _, v := range vads.Vads {
		if v.VadExPages > 0 {
			oPage = v.VadExPagesBase
			cPage = v.VadExPages
			if cPage > 4 {
				cPage = 4 // limit to first 4 pages for speed
			}
			break
		}
	}
	if cPage == 0 {
		t.Skip("no VAD with VadExPages > 0 found")
	}

	list, err := vmm.GetVadExList(4, oPage, cPage)
	if err != nil {
		t.Fatalf("GetVadExList failed: %v", err)
	}
	t.Logf("GetVadExList(pid=4, oPage=%d, cPage=%d): got %d entries", oPage, cPage, list.Count)
	for i, e := range list.Entries {
		t.Logf("  [%d] va=0x%X pa=0x%X type=%d vadBase=0x%X", i, e.Va, e.Pa, e.Type, e.VadBase)
	}
	if list.Count == 0 {
		t.Error("expected at least one VadEx entry")
	}
}

func TestGetPfnList(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	// Use a handful of low PFNs that are likely present in any dump.
	pfns := []uint32{1, 2, 3, 4, 5}
	list, err := vmm.GetPfnList(pfns, PfnFlagNormal)
	if err != nil {
		t.Fatalf("GetPfnList failed: %v", err)
	}
	if int(list.Count) != len(pfns) {
		t.Fatalf("expected %d entries, got %d", len(pfns), list.Count)
	}
	t.Logf("GetPfnList: %d entries", list.Count)
	for _, e := range list.Entries {
		t.Logf("  pfn=%d type=%d typeExt=%d va=0x%X refCnt=%d",
			e.Pfn, e.Type, e.TypeExtended, e.Va, e.ReferenceCount)
	}
}

func TestGetPfnListExtended(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	pfns := []uint32{1, 2}
	list, err := vmm.GetPfnList(pfns, PfnFlagExtended)
	if err != nil {
		t.Fatalf("GetPfnList (extended) failed: %v", err)
	}
	t.Logf("GetPfnList extended: %d entries", list.Count)
	for _, e := range list.Entries {
		t.Logf("  pfn=%d type=%d typeExt=%d vaPte=0x%X", e.Pfn, e.Type, e.TypeExtended, e.VaPte)
	}
}

func TestGetVMList(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	list, err := vmm.GetVMList()
	if err != nil {
		t.Fatalf("GetVMList failed: %v", err)
	}
	// On bare-metal or a plain dump there may be zero VMs — that is not an error.
	t.Logf("GetVMList: %d VM(s)", list.Count)
	for i, e := range list.Entries {
		t.Logf("  [%d] name=%q type=%d active=%v gpaMax=0x%X", i, e.Name, e.Type, e.IsActive, e.GpaMax)
	}
}
