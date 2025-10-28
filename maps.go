package memprocfs

import (
	"unsafe"
)

// FAM is a helper function to access Flexible Array Members.
func FAM[P, T any](p *P, count int) []T {
	// This function assumes that the FAM immediately follows the struct P.
	headerSize := unsafe.Sizeof(*p)
	sliceStart := uintptr(unsafe.Pointer(p)) + headerSize
	return unsafe.Slice((*T)(unsafe.Pointer(sliceStart)), count)
}

// ModuleType corresponds to the VMMDLL_MODULE_TP enum.
type ModuleType uint32

const (
	ModuleTypeUnknown ModuleType = 0
	ModuleTypeNormal  ModuleType = 1
	ModuleTypeData    ModuleType = 2
)

// Module contains information about a single loaded module.
type Module struct {
	BaseAddress  uint64
	EntryPoint   uint64
	ImageSize    uint32
	IsWow64      bool
	Name         string
	FullName     string
	Type         ModuleType
	FileSize     uint32
	SectionCount uint32
	ExportCount  uint32
	ImportCount  uint32
}

// ModuleList contains a list of loaded modules for a process.
type ModuleList struct {
	Version   uint32
	Count     uint32
	MultiText string
	Modules   []Module
}

// moduleEntryInternal mirrors the C struct VMMDLL_MAP_MODULEENTRY
type moduleEntryInternal struct {
	VaBase         uint64
	VaEntry        uint64
	CbImageSize    uint32
	FWoW64         bool
	UszText        uintptr
	_              [2]uint32 // _Reserved3, _Reserved4
	UszFullName    uintptr
	Tp             ModuleType
	CbFileSizeRaw  uint32
	CSection       uint32
	CEAT           uint32
	CIAT           uint32
	_              uint32 // _Reserved2
	Reserved       [3]uint64
	PExDebugInfo   uintptr
	PExVersionInfo uintptr
}

// moduleListInternal mirrors the C struct VMMDLL_MAP_MODULE
type moduleListInternal struct {
	Version     uint32
	_           [5]uint32 // Reserved
	PbMultiText uintptr
	CbMultiText uint32
	CMap        uint32
	// pMap (FAM) starts here
}
