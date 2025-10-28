package memprocfs

import (
	"bytes"
	"fmt"
	"unsafe"
)

const (
	processInformationMagic   = 0xc0ffee663df9301e
	processInformationVersion = 7
)

// MemoryModel corresponds to the VMMDLL_MEMORYMODEL_TP enum.
type MemoryModel uint32

const (
	MemoryModelNA     MemoryModel = 0
	MemoryModelX86    MemoryModel = 1
	MemoryModelX86PAE MemoryModel = 2
	MemoryModelX64    MemoryModel = 3
	MemoryModelARM64  MemoryModel = 4
)

// SystemType corresponds to the VMMDLL_SYSTEM_TP enum.
type SystemType uint32

const (
	SystemUnknownPhysical SystemType = 0
	SystemUnknown64       SystemType = 1
	SystemWindows64       SystemType = 2
	SystemUnknown32       SystemType = 3
	SystemWindows32       SystemType = 4
)

type ProcessIntegrityLevel uint32

type ProcessInfoStringOptions uint32

const (
	ProcessInformationOptStringPathUserImage ProcessInfoStringOptions = 0x1
	ProcessInformationOptStringPathKernel    ProcessInfoStringOptions = 0x2
	ProcessInformationOptStringCmdline       ProcessInfoStringOptions = 0x4
	ProcessInformationOptStringSID           ProcessInfoStringOptions = 0x8
	ProcessInformationOptStringSystemRoot    ProcessInfoStringOptions = 0x10
)

// WinProcessInfo mirrors the nested 'win' struct from VMMDLL_PROCESS_INFORMATION
type WinProcessInfo struct {
	EPROCESS       uint64
	PEB            uint64
	Reserved1      uint64
	IsWow64        uint32 // BOOL
	PEB32          uint32
	SessionID      uint32
	_              [4]byte // Padding for LUID alignment
	LUID           uint64
	SIDRaw         [260]byte
	IntegrityLevel ProcessIntegrityLevel
}

// ProcessInfo mirrors the C struct VMMDLL_PROCESS_INFORMATION
type ProcessInfo struct {
	Magic       uint64
	Version     uint16
	Size        uint16
	MemoryModel MemoryModel
	SystemType  SystemType
	IsUserOnly  uint32 // BOOL
	PID         uint32
	ParentPID   uint32
	State       uint32
	NameRaw     [16]byte
	NameLongRaw [64]byte
	_           [4]byte // Padding for DTB alignment
	DTB         uint64
	UserDTB     uint64
	Win         WinProcessInfo
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

// Name returns the process name as a Go string.
func (pi *ProcessInfo) Name() string {
	return string(bytes.TrimRight(pi.NameRaw[:], "\x00"))
}

// NameLong returns the long process name as a Go string.
func (pi *ProcessInfo) NameLong() string {
	return string(bytes.TrimRight(pi.NameLongRaw[:], "\x00"))
}

func (vmm *Vmm) GetPidByName(processName string) (uint32, error) {
	var pid uint32
	success := vmmPidGetFromName(vmm.vmmHandle, processName, &pid)
	if !success {
		return 0, fmt.Errorf("failed to get PID for process '%s'", processName)
	}
	return pid, nil
}

func (vmm *Vmm) GetProcessInfoString(pid uint32, opt ProcessInfoStringOptions) (string, error) {
	strPtr := vmmProcessGetInformationString(vmm.vmmHandle, pid, uint32(opt))
	if strPtr == 0 {
		return "", fmt.Errorf("failed to get process info string for PID %d, option %d", pid, opt)
	}
	defer vmm.free(strPtr)
	return cStringToGo(strPtr), nil
}

func (vmm *Vmm) GetProcessInfo(pid uint32) (*ProcessInfo, error) {
	var requiredSize uint32
	// First call with nil to get the required buffer size.
	vmmProcessGetInformation(vmm.vmmHandle, pid, nil, &requiredSize)
	if requiredSize == 0 {
		return nil, fmt.Errorf("failed to get required size for process info for PID %d", pid)
	}

	var processInfo ProcessInfo
	actualSize := uint32(unsafe.Sizeof(processInfo))
	if actualSize < requiredSize {
		return nil, fmt.Errorf("ProcessInfo struct size mismatch: our size %d, required size %d", actualSize, requiredSize)
	}

	// Initialize the struct with magic and version before the second call.
	processInfo.Magic = processInformationMagic
	processInfo.Version = processInformationVersion
	processInfo.Size = uint16(actualSize)

	cb := requiredSize
	// Second call with the actual, initialized buffer.
	success := vmmProcessGetInformation(vmm.vmmHandle, pid, unsafe.Pointer(&processInfo), &cb)
	if !success {
		return nil, fmt.Errorf("failed to get process info for PID %d on second call", pid)
	}

	return &processInfo, nil
}

func (vmm *Vmm) GetModuleList(pid uint32) (*ModuleList, error) {
	var moduleListPtr *moduleListInternal
	success := vmmMapGetModuleU(vmm.vmmHandle, pid, &moduleListPtr, 0)
	if !success {
		return nil, fmt.Errorf("failed to get module list for PID %d", pid)
	}
	defer vmm.free(uintptr(unsafe.Pointer(moduleListPtr)))

	internalEntries := FAM[moduleListInternal, moduleEntryInternal](moduleListPtr, int(moduleListPtr.CMap))

	multiTextSlice := unsafe.Slice((*byte)(unsafe.Pointer(moduleListPtr.PbMultiText)), moduleListPtr.CbMultiText)

	result := &ModuleList{
		Version:   moduleListPtr.Version,
		Count:     moduleListPtr.CMap,
		MultiText: string(multiTextSlice),
		Modules:   make([]Module, len(internalEntries)),
	}

	for i, entry := range internalEntries {
		result.Modules[i] = Module{
			BaseAddress:  entry.VaBase,
			EntryPoint:   entry.VaEntry,
			ImageSize:    entry.CbImageSize,
			IsWow64:      entry.FWoW64,
			Name:         cStringToGo(entry.UszText),
			FullName:     cStringToGo(entry.UszFullName),
			Type:         entry.Tp,
			FileSize:     entry.CbFileSizeRaw,
			SectionCount: entry.CSection,
			ExportCount:  entry.CEAT,
			ImportCount:  entry.CIAT,
		}
	}

	return result, nil
}
