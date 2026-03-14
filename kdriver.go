package memprocfs

import (
	"fmt"
	"unsafe"
)

// KDriverEntry represents a single kernel driver entry.
type KDriverEntry struct {
	Va               uint64
	VaDriverStart    uint64
	CbDriverSize     uint64
	VaDeviceObject   uint64
	Name             string
	Path             string
	ServiceKeyName   string
	MajorFunction    [28]uint64
}

// KDriverList contains a list of kernel drivers.
type KDriverList struct {
	Version uint32
	Count   uint32
	Entries []KDriverEntry
}

// kdriverEntryInternal mirrors the C struct VMMDLL_MAP_KDRIVERENTRY.
type kdriverEntryInternal struct {
	Va             uint64
	VaDriverStart  uint64
	CbDriverSize   uint64
	VaDeviceObject uint64
	UszName        uintptr
	UszPath        uintptr
	UszServiceKey  uintptr
	MajorFunction  [28]uint64
}

// kdriverListInternal mirrors the C struct VMMDLL_MAP_KDRIVER.
type kdriverListInternal struct {
	DwVersion   uint32
	_           [5]uint32
	PbMultiText uintptr
	CbMultiText uint32
	CMap        uint32
	// FAM entries follow
}

// GetKDriverList retrieves the list of kernel drivers.
func (vmm *Vmm) GetKDriverList() (*KDriverList, error) {
	var pMap *kdriverListInternal
	if !vmmMapGetKDriverU(vmm.vmmHandle, &pMap) {
		return nil, fmt.Errorf("GetKDriverList: failed")
	}
	if pMap == nil {
		return nil, fmt.Errorf("GetKDriverList: nil map returned")
	}
	defer vmm.free(uintptr(unsafe.Pointer(pMap)))

	if pMap.CMap == 0 {
		return &KDriverList{Version: pMap.DwVersion}, nil
	}

	entriesInternal := FAM[kdriverListInternal, kdriverEntryInternal](pMap, int(pMap.CMap))
	entries := make([]KDriverEntry, pMap.CMap)
	for i, e := range entriesInternal {
		entries[i] = KDriverEntry{
			Va:             e.Va,
			VaDriverStart:  e.VaDriverStart,
			CbDriverSize:   e.CbDriverSize,
			VaDeviceObject: e.VaDeviceObject,
			Name:           cStringToGo(e.UszName),
			Path:           cStringToGo(e.UszPath),
			ServiceKeyName: cStringToGo(e.UszServiceKey),
			MajorFunction:  e.MajorFunction,
		}
	}

	return &KDriverList{
		Version: pMap.DwVersion,
		Count:   pMap.CMap,
		Entries: entries,
	}, nil
}
