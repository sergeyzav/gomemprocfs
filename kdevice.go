package memprocfs

import (
	"unsafe"

	"github.com/sergeyzav/gomemprocfs/internal/ffi"
)

// KDeviceEntry represents a single kernel device object entry.
type KDeviceEntry struct {
	Va                 uint64
	Depth              uint32
	DeviceType         uint32
	DeviceTypeName     string
	VaDriverObject     uint64
	VaAttachedDevice   uint64
	VaFileSystemDevice uint64
	VolumeInfo         string
}

// KDeviceList contains a list of kernel device objects.
type KDeviceList struct {
	Version uint32
	Count   uint32
	Entries []KDeviceEntry
}

// kdeviceEntryInternal mirrors the C struct VMMDLL_MAP_KDEVICEENTRY.
type kdeviceEntryInternal struct {
	Va                 uint64
	IDepth             uint32
	DwDeviceType       uint32
	UszDeviceType      uintptr
	VaDriverObject     uint64
	VaAttachedDevice   uint64
	VaFileSystemDevice uint64
	UszVolumeInfo      uintptr
}

// kdeviceListInternal mirrors the C struct VMMDLL_MAP_KDEVICE.
type kdeviceListInternal struct {
	DwVersion   uint32
	_           [5]uint32
	PbMultiText uintptr
	CbMultiText uint32
	CMap        uint32
	// FAM entries follow
}

// GetKDeviceList retrieves the list of Windows kernel device objects.
// Each entry includes the device's virtual address, type, associated driver object, and optional volume info.
func (vmm *Vmm) GetKDeviceList() (*KDeviceList, error) {
	var pMap *kdeviceListInternal
	if !vmmMapGetKDeviceU(vmm.vmmHandle, &pMap) {
		return nil, nil
	}
	if pMap == nil {
		return nil, nil
	}
	defer vmm.free(uintptr(unsafe.Pointer(pMap)))

	if pMap.CMap == 0 {
		return &KDeviceList{Version: pMap.DwVersion}, nil
	}

	entriesInternal := ffi.FAM[kdeviceListInternal, kdeviceEntryInternal](pMap, int(pMap.CMap))
	entries := make([]KDeviceEntry, pMap.CMap)
	for i, e := range entriesInternal {
		entries[i] = KDeviceEntry{
			Va:                 e.Va,
			Depth:              e.IDepth,
			DeviceType:         e.DwDeviceType,
			DeviceTypeName:     ffi.CStringToGo(e.UszDeviceType),
			VaDriverObject:     e.VaDriverObject,
			VaAttachedDevice:   e.VaAttachedDevice,
			VaFileSystemDevice: e.VaFileSystemDevice,
			VolumeInfo:         ffi.CStringToGo(e.UszVolumeInfo),
		}
	}

	return &KDeviceList{
		Version: pMap.DwVersion,
		Count:   pMap.CMap,
		Entries: entries,
	}, nil
}
