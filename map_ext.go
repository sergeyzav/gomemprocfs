package memprocfs

import (
	"fmt"
	"unsafe"

	"github.com/sergeyzav/gomemprocfs/internal/ffi"
)

// ─── VadEx ───────────────────────────────────────────────────────────────────

// vadExEntryInternal mirrors VMMDLL_MAP_VADEXENTRY (64 bytes on x64).
type vadExEntryInternal struct {
	Tp            uint32 // VMMDLL_PTE_TP
	IPML          uint8
	PteFlags      uint8
	_             uint16 // _Reserved2
	Va            uint64
	Pa            uint64
	Pte           uint64
	ProtoReserved uint32
	ProtoTp       uint32 // VMMDLL_PTE_TP
	ProtoPa       uint64
	ProtoPte      uint64
	VaVadBase     uint64
}

// vadExListInternal mirrors VMMDLL_MAP_VADEX.
type vadExListInternal struct {
	Version uint32
	_       [4]uint32
	CMap    uint32
	// FAM: vadExEntryInternal[]
}

// VadExEntry is a single extended VAD page entry returned by GetVadExList.
type VadExEntry struct {
	Type         PteType
	PageMapLevel uint8
	PteFlags     uint8
	Va           uint64
	Pa           uint64
	Pte          uint64
	ProtoType    PteType
	ProtoPa      uint64
	ProtoPte     uint64
	VadBase      uint64
}

// VadExList holds extended VAD page entries.
type VadExList struct {
	Count   uint32
	Entries []VadExEntry
}

// GetVadExList retrieves extended per-page VAD information for a process.
// oPage is the 0-based page offset into the process VAD map;
// cPage is the number of pages to retrieve.
func (vmm *Vmm) GetVadExList(pid uint32, oPage uint32, cPage uint32) (*VadExList, error) {
	var pMap *vadExListInternal
	if !vmmMapGetVadEx(vmm.vmmHandle, pid, oPage, cPage, &pMap) {
		return nil, fmt.Errorf("VMMDLL_Map_GetVadEx failed for PID %d oPage %d cPage %d", pid, oPage, cPage)
	}
	defer vmm.free(uintptr(unsafe.Pointer(pMap)))

	count := int(pMap.CMap)
	entries := ffi.FAM[vadExListInternal, vadExEntryInternal](pMap, count)
	result := &VadExList{
		Count:   pMap.CMap,
		Entries: make([]VadExEntry, count),
	}
	for i, e := range entries {
		result.Entries[i] = VadExEntry{
			Type:         PteType(e.Tp),
			PageMapLevel: e.IPML,
			PteFlags:     e.PteFlags,
			Va:           e.Va,
			Pa:           e.Pa,
			Pte:          e.Pte,
			ProtoType:    PteType(e.ProtoTp),
			ProtoPa:      e.ProtoPa,
			ProtoPte:     e.ProtoPte,
			VadBase:      e.VaVadBase,
		}
	}
	return result, nil
}

// ─── PFN ─────────────────────────────────────────────────────────────────────

// PfnType corresponds to the VMMDLL_MAP_PFN_TYPE enum.
type PfnType uint32

const (
	PfnTypeZero            PfnType = 0
	PfnTypeFree            PfnType = 1
	PfnTypeStandby         PfnType = 2
	PfnTypeModified        PfnType = 3
	PfnTypeModifiedNoWrite PfnType = 4
	PfnTypeBad             PfnType = 5
	PfnTypeActive          PfnType = 6
	PfnTypeTransition      PfnType = 7
)

// PfnTypeExtended corresponds to the VMMDLL_MAP_PFN_TYPEEXTENDED enum.
type PfnTypeExtended uint32

const (
	PfnExtUnknown        PfnTypeExtended = 0
	PfnExtUnused         PfnTypeExtended = 1
	PfnExtProcessPrivate PfnTypeExtended = 2
	PfnExtPageTable      PfnTypeExtended = 3
	PfnExtLargePage      PfnTypeExtended = 4
	PfnExtDriverLocked   PfnTypeExtended = 5
	PfnExtShareable      PfnTypeExtended = 6
	PfnExtFile           PfnTypeExtended = 7
)

// PFN flags for GetPfnList.
const (
	PfnFlagNormal   uint32 = 0
	PfnFlagExtended uint32 = 1
)

// pfnEntryInternal mirrors VMMDLL_MAP_PFNENTRY (96 bytes on x64).
// Unions and bitfields are flattened; padding fields match C struct alignment.
type pfnEntryInternal struct {
	DwPfn         uint32
	TpExtended    uint32
	AddressRaw    [5]uint32 // union: dwPid or dwPfnPte[5]
	_             uint32    // padding: align AddressVa to 8 bytes
	AddressVa     uint64
	VaPte         uint64
	OriginalPte   uint64
	U3            uint32 // bitfield: [15:0] ReferenceCount, [18:16] PageLocation
	_             uint32 // padding: align U4 to 8 bytes
	U4            uint64
	_FutureUse    [6]uint32
}

// pfnListInternal mirrors VMMDLL_MAP_PFN.
type pfnListInternal struct {
	Version uint32
	_       [5]uint32
	CMap    uint32
	// FAM: pfnEntryInternal[]
}

// PfnEntry holds information about a single Page Frame Number.
type PfnEntry struct {
	Pfn            uint32
	TypeExtended   PfnTypeExtended
	Pid            uint32  // valid for active non-prototype pages
	Va             uint64  // virtual address (non-zero when known)
	VaPte          uint64
	OriginalPte    uint64
	Type           PfnType // page location type (PageLocation bitfield)
	ReferenceCount uint16
}

// PfnList holds the result of a PFN lookup.
type PfnList struct {
	Count   uint32
	Entries []PfnEntry
}

// GetPfnList retrieves Page Frame Number information for the supplied PFNs.
// flags: PfnFlagNormal (0) for basic info, PfnFlagExtended (1) for full extended info.
func (vmm *Vmm) GetPfnList(pfns []uint32, flags uint32) (*PfnList, error) {
	if len(pfns) == 0 {
		return &PfnList{}, nil
	}
	var pMap *pfnListInternal
	if !vmmMapGetPfnEx(vmm.vmmHandle, unsafe.Pointer(&pfns[0]), uint32(len(pfns)), &pMap, flags) {
		return nil, fmt.Errorf("VMMDLL_Map_GetPfnEx failed")
	}
	defer vmm.free(uintptr(unsafe.Pointer(pMap)))

	count := int(pMap.CMap)
	entries := ffi.FAM[pfnListInternal, pfnEntryInternal](pMap, count)
	result := &PfnList{
		Count:   pMap.CMap,
		Entries: make([]PfnEntry, count),
	}
	for i, e := range entries {
		result.Entries[i] = PfnEntry{
			Pfn:            e.DwPfn,
			TypeExtended:   PfnTypeExtended(e.TpExtended),
			Pid:            e.AddressRaw[0],
			Va:             e.AddressVa,
			VaPte:          e.VaPte,
			OriginalPte:    e.OriginalPte,
			Type:           PfnType((e.U3 >> 16) & 0x7), // PageLocation = bits 18:16
			ReferenceCount: uint16(e.U3),
		}
	}
	return result, nil
}

// ─── VM ──────────────────────────────────────────────────────────────────────

// VmType corresponds to the VMMDLL_VM_TP enum.
type VmType uint32

const (
	VmTypeUnknown VmType = 0
	VmTypeHV      VmType = 1
	VmTypeHVWHVP  VmType = 2
)

// vmEntryInternal mirrors VMMDLL_MAP_VMENTRY (64 bytes on x64).
type vmEntryInternal struct {
	HVM               uintptr // VMMVM_HANDLE
	UszName           uintptr // LPSTR
	GpaMax            uint64
	Tp                uint32 // VMMDLL_VM_TP
	FActive           uint32 // BOOL
	FReadOnly         uint32 // BOOL
	FPhysicalOnly     uint32 // BOOL
	DwPartitionID     uint32
	DwVersionBuild    uint32
	TpSystem          uint32 // VMMDLL_SYSTEM_TP
	DwParentVmmMount  uint32
	DwVmMemPID        uint32
}

// vmListInternal mirrors VMMDLL_MAP_VM.
type vmListInternal struct {
	Version     uint32
	_           uint32
	PbMultiText uintptr
	CbMultiText uint32
	CMap        uint32
	// FAM: vmEntryInternal[]
}

// VmEntry represents a single virtual machine discovered by MemProcFS.
type VmEntry struct {
	Handle           uintptr
	Name             string
	GpaMax           uint64
	Type             VmType
	IsActive         bool
	IsReadOnly       bool
	IsPhysicalOnly   bool
	PartitionID      uint32
	VersionBuild     uint32
	SystemType       SystemType
	ParentVmmMountID uint32
	VmMemPID         uint32
}

// VMList holds the list of virtual machines.
type VMList struct {
	Count   uint32
	Entries []VmEntry
}

// GetVMList retrieves the list of virtual machines detected by MemProcFS.
// Returns an empty list (not an error) if no VMs are present (e.g. bare-metal dump).
func (vmm *Vmm) GetVMList() (*VMList, error) {
	var pMap *vmListInternal
	if !vmmMapGetVMU(vmm.vmmHandle, &pMap) {
		return &VMList{}, nil
	}
	defer vmm.free(uintptr(unsafe.Pointer(pMap)))

	count := int(pMap.CMap)
	entries := ffi.FAM[vmListInternal, vmEntryInternal](pMap, count)
	result := &VMList{
		Count:   pMap.CMap,
		Entries: make([]VmEntry, count),
	}
	for i, e := range entries {
		result.Entries[i] = VmEntry{
			Handle:           e.HVM,
			Name:             ffi.CStringToGo(e.UszName),
			GpaMax:           e.GpaMax,
			Type:             VmType(e.Tp),
			IsActive:         e.FActive != 0,
			IsReadOnly:       e.FReadOnly != 0,
			IsPhysicalOnly:   e.FPhysicalOnly != 0,
			PartitionID:      e.DwPartitionID,
			VersionBuild:     e.DwVersionBuild,
			SystemType:       SystemType(e.TpSystem),
			ParentVmmMountID: e.DwParentVmmMount,
			VmMemPID:         e.DwVmMemPID,
		}
	}
	return result, nil
}
