package memprocfs

import (
	"unsafe"

	"github.com/sergeyzav/memprocfs/internal/ffi"
)

// PhysMemEntry represents a physical memory range.
type PhysMemEntry struct {
	BaseAddress uint64
	Size        uint64
}

// physMemEntryInternal mirrors the C struct VMMDLL_MAP_PHYSMEMENTRY.
type physMemEntryInternal struct {
	Pa uint64
	Cb uint64
}

// physMemListInternal mirrors the C struct VMMDLL_MAP_PHYSMEM.
type physMemListInternal struct {
	DwVersion  uint32
	_Reserved1 [5]uint32
	CMap       uint32
	_Reserved2 uint32
	// pMap (FAM) starts here
}

// PhysMemList contains a list of physical memory ranges.
type PhysMemList struct {
	Version uint32
	Count   uint32
	Entries []PhysMemEntry
}

// GetPhysMem retrieves the physical memory map of the system.
// Returns the list of physical memory ranges (base address and size) reported by the hardware/hypervisor.
func (vmm *Vmm) GetPhysMem() (*PhysMemList, error) {
	var pPhysMemMap *physMemListInternal
	success := vmmMapGetPhysMem(vmm.vmmHandle, &pPhysMemMap)
	if !success {
		return nil, nil
	}
	defer vmm.free(uintptr(unsafe.Pointer(pPhysMemMap)))

	if pPhysMemMap == nil {
		return nil, nil
	}

	if pPhysMemMap.CMap == 0 {
		return &PhysMemList{
			Version: pPhysMemMap.DwVersion,
		}, nil
	}

	entriesInternal := ffi.FAM[physMemListInternal, physMemEntryInternal](pPhysMemMap, int(pPhysMemMap.CMap))

	entries := make([]PhysMemEntry, pPhysMemMap.CMap)
	for i, entry := range entriesInternal {
		entries[i] = PhysMemEntry{
			BaseAddress: entry.Pa,
			Size:        entry.Cb,
		}
	}

	return &PhysMemList{
		Version: pPhysMemMap.DwVersion,
		Count:   pPhysMemMap.CMap,
		Entries: entries,
	}, nil
}
