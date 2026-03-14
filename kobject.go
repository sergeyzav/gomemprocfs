package memprocfs

import "unsafe"

// KObjectEntry represents a single kernel object entry.
type KObjectEntry struct {
	Va       uint64
	VaParent uint64
	Children []uint64
	Name     string
	Type     string
}

// KObjectList contains a list of kernel objects.
type KObjectList struct {
	Version uint32
	Count   uint32
	Entries []KObjectEntry
}

// kobjectEntryInternal mirrors the C struct VMMDLL_MAP_KOBJECTENTRY.
type kobjectEntryInternal struct {
	Va       uint64
	VaParent uint64
	_Filler  uint32
	CvaChild uint32
	PvaChild uintptr
	UszName  uintptr
	UszType  uintptr
}

// kobjectListInternal mirrors the C struct VMMDLL_MAP_KOBJECT.
type kobjectListInternal struct {
	DwVersion   uint32
	_           [5]uint32
	PbMultiText uintptr
	CbMultiText uint32
	CMap        uint32
	// FAM entries follow
}

// GetKObjectList retrieves the list of kernel objects.
func (vmm *Vmm) GetKObjectList() (*KObjectList, error) {
	var pMap *kobjectListInternal
	if !vmmMapGetKObjectU(vmm.vmmHandle, &pMap) {
		return nil, nil
	}
	if pMap == nil {
		return nil, nil
	}
	defer vmm.free(uintptr(unsafe.Pointer(pMap)))

	if pMap.CMap == 0 {
		return &KObjectList{Version: pMap.DwVersion}, nil
	}

	entriesInternal := FAM[kobjectListInternal, kobjectEntryInternal](pMap, int(pMap.CMap))
	entries := make([]KObjectEntry, pMap.CMap)
	for i, e := range entriesInternal {
		var children []uint64
		if e.CvaChild > 0 && e.PvaChild != 0 {
			src := unsafe.Slice((*uint64)(unsafe.Pointer(e.PvaChild)), e.CvaChild)
			children = make([]uint64, e.CvaChild)
			copy(children, src)
		}
		entries[i] = KObjectEntry{
			Va:       e.Va,
			VaParent: e.VaParent,
			Children: children,
			Name:     cStringToGo(e.UszName),
			Type:     cStringToGo(e.UszType),
		}
	}

	return &KObjectList{
		Version: pMap.DwVersion,
		Count:   pMap.CMap,
		Entries: entries,
	}, nil
}
