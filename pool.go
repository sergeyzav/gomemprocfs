package memprocfs

import (
	"unsafe"

	"github.com/sergeyzav/memprocfs/internal/ffi"
)

// PoolMapFlag controls which pool allocations are returned.
type PoolMapFlag uint32

const (
	PoolMapFlagAll PoolMapFlag = 0
	PoolMapFlagBig PoolMapFlag = 1
)

// PoolType represents the type of a pool allocation.
type PoolType uint8

const (
	PoolTypeUnknown        PoolType = 0
	PoolTypeNonPagedPool   PoolType = 1
	PoolTypeNonPagedPoolNx PoolType = 2
	PoolTypePagedPool      PoolType = 3
)

// PoolEntry represents a single kernel pool allocation.
type PoolEntry struct {
	Va     uint64
	Tag    [4]byte
	Alloc  bool
	TpPool PoolType
	TpSS   uint8
	Size   uint32
}

// PoolList contains a list of kernel pool allocations.
type PoolList struct {
	Version uint32
	Count   uint32
	Entries []PoolEntry
}

// poolEntryInternal mirrors the C struct VMMDLL_MAP_POOLENTRY.
type poolEntryInternal struct {
	Va            uint64
	DwTag         uint32
	_ReservedZero uint8
	FAlloc        uint8
	TpPool        uint8
	TpSS          uint8
	Cb            uint32
	_Filler       uint32
}

// poolListInternal mirrors the C struct VMMDLL_MAP_POOL.
type poolListInternal struct {
	DwVersion uint32
	_         [6]uint32 // _Reserved1[6]
	CbTotal   uint32
	PiTag2Map uintptr
	PTag      uintptr
	CTag      uint32
	CMap      uint32
	// FAM entries follow
}

// GetPoolList retrieves kernel pool allocations.
// Use PoolMapFlagAll to return all allocations or PoolMapFlagBig to return only big-pool allocations.
func (vmm *Vmm) GetPoolList(flag PoolMapFlag) (*PoolList, error) {
	var pMap *poolListInternal
	if !vmmMapGetPool(vmm.vmmHandle, &pMap, uint32(flag)) {
		return nil, nil
	}
	if pMap == nil {
		return nil, nil
	}
	defer vmm.free(uintptr(unsafe.Pointer(pMap)))

	if pMap.CMap == 0 {
		return &PoolList{Version: pMap.DwVersion}, nil
	}

	entriesInternal := ffi.FAM[poolListInternal, poolEntryInternal](pMap, int(pMap.CMap))
	entries := make([]PoolEntry, pMap.CMap)
	for i, e := range entriesInternal {
		var tag [4]byte
		tag[0] = byte(e.DwTag)
		tag[1] = byte(e.DwTag >> 8)
		tag[2] = byte(e.DwTag >> 16)
		tag[3] = byte(e.DwTag >> 24)
		entries[i] = PoolEntry{
			Va:     e.Va,
			Tag:    tag,
			Alloc:  e.FAlloc != 0,
			TpPool: PoolType(e.TpPool),
			TpSS:   e.TpSS,
			Size:   e.Cb,
		}
	}

	return &PoolList{
		Version: pMap.DwVersion,
		Count:   pMap.CMap,
		Entries: entries,
	}, nil
}
