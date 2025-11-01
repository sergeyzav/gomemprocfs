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

// Thread represents a single thread in a process.
type Thread struct {
	TID                uint32
	PID                uint32
	ExitStatus         uint32
	State              byte
	Running            byte
	Priority           byte
	BasePriority       byte
	ETHREAD            uint64
	Teb                uint64
	CreateTime         uint64
	ExitTime           uint64
	StartAddress       uint64
	StackBaseUser      uint64
	StackLimitUser     uint64
	StackBaseKernel    uint64
	StackLimitKernel   uint64
	TrapFrame          uint64
	RIP                uint64
	RSP                uint64
	Affinity           uint64
	UserTime           uint32
	KernelTime         uint32
	SuspendCount       byte
	WaitReason         byte
	ImpersonationToken uint64
	Win32StartAddress  uint64
}

// ThreadList contains a list of threads for a process.
type ThreadList struct {
	Version uint32
	Count   uint32
	Threads []Thread
}

// threadEntryInternal mirrors the C struct VMMDLL_MAP_THREADENTRY
type threadEntryInternal struct {
	DwTID                uint32
	DwPID                uint32
	DwExitStatus         uint32
	BState               byte
	BRunning             byte
	BPriority            byte
	BBasePriority        byte
	VaETHREAD            uint64
	VaTeb                uint64
	FtCreateTime         uint64
	FtExitTime           uint64
	VaStartAddress       uint64
	VaStackBaseUser      uint64
	VaStackLimitUser     uint64
	VaStackBaseKernel    uint64
	VaStackLimitKernel   uint64
	VaTrapFrame          uint64
	VaRIP                uint64
	VaRSP                uint64
	QwAffinity           uint64
	DwUserTime           uint32
	DwKernelTime         uint32
	BSuspendCount        byte
	BWaitReason          byte
	_                    [2]byte    // FutureUse1
	_                    [11]uint32 // FutureUse2
	VaImpersonationToken uint64
	VaWin32StartAddress  uint64
}

// threadListInternal mirrors the C struct VMMDLL_MAP_THREAD
type threadListInternal struct {
	Version uint32
	_       [8]uint32 // Reserved
	CMap    uint32
	// pMap (FAM) starts here
}

// Vad represents a single Virtual Address Descriptor.
type Vad struct {
	Start            uint64
	End              uint64
	VadAddress       uint64
	VadType          uint32
	Protection       uint32
	IsImage          bool
	IsFile           bool
	IsPageFile       bool
	IsPrivateMemory  bool
	IsTeb            bool
	IsStack          bool
	HeapNum          uint32
	IsHeap           bool
	CommitCharge     uint32
	IsCommitted      bool
	PrototypePteSize uint32
	PrototypePte     uint64
	Subsection       uint64
	Text             string
	FileObject       uint64
	VadExPages       uint32
	VadExPagesBase   uint32
}

// VadList contains a list of VADs for a process.
type VadList struct {
	Version   uint32
	PageCount uint32
	Count     uint32
	MultiText string
	Vads      []Vad
}

// vadEntryInternal mirrors the C struct VMMDLL_MAP_VADENTRY
type vadEntryInternal struct {
	VaStart         uint64
	VaEnd           uint64
	VaVad           uint64
	Dw0             uint32 // Bitfield
	Dw1             uint32 // Bitfield
	U2              uint32
	CbPrototypePte  uint32
	VaPrototypePte  uint64
	VaSubsection    uint64
	UszText         uintptr
	_               uint32 // FutureUse1
	_               uint32 // Reserved1
	VaFileObject    uint64
	CVadExPages     uint32
	CVadExPagesBase uint32
	_               uint64 // Reserved2
}

// vadListInternal mirrors the C struct VMMDLL_MAP_VAD
type vadListInternal struct {
	Version     uint32
	_           [4]uint32 // Reserved1
	CPage       uint32
	PbMultiText uintptr
	CbMultiText uint32
	CMap        uint32
	// pMap (FAM) starts here
}

// Handle represents a single handle in a process.
type Handle struct {
	Object             uint64
	Handle             uint32
	GrantedAccess      uint32
	TypeIndex          uint32
	HandleCount        uint64
	PointerCount       uint64
	ObjectCreateInfo   uint64
	SecurityDescriptor uint64
	Text               string
	PID                uint32
	PoolTag            uint32
	Type               string
}

// HandleList contains a list of handles for a process.
type HandleList struct {
	Version   uint32
	Count     uint32
	MultiText string
	Handles   []Handle
}

// handleEntryInternal mirrors the C struct VMMDLL_MAP_HANDLEENTRY
type handleEntryInternal struct {
	VaObject             uint64
	DwHandle             uint32
	AccessAndType        uint32 // Combined field for GrantedAccess (24 bits) and IType (8 bits)
	QwHandleCount        uint64
	QwPointerCount       uint64
	VaObjectCreateInfo   uint64
	VaSecurityDescriptor uint64
	UszText              uintptr
	_                    uint32 // FutureUse2
	DwPID                uint32
	DwPoolTag            uint32
	_                    [7]uint32 // FutureUse
	UszType              uintptr
}

// handleListInternal mirrors the C struct VMMDLL_MAP_HANDLE
type handleListInternal struct {
	Version     uint32
	_           [5]uint32 // Reserved1
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

func (vmm *Vmm) GetVadList(pid uint32, identifyModules bool) (*VadList, error) {
	var vadListPtr *vadListInternal
	success := vmmMapGetVadU(vmm.vmmHandle, pid, identifyModules, &vadListPtr)
	if !success {
		return nil, fmt.Errorf("failed to get VAD list for PID %d", pid)
	}
	defer vmm.free(uintptr(unsafe.Pointer(vadListPtr)))

	internalEntries := FAM[vadListInternal, vadEntryInternal](vadListPtr, int(vadListPtr.CMap))

	multiTextSlice := unsafe.Slice((*byte)(unsafe.Pointer(vadListPtr.PbMultiText)), vadListPtr.CbMultiText)

	result := &VadList{
		Version:   vadListPtr.Version,
		PageCount: vadListPtr.CPage,
		Count:     vadListPtr.CMap,
		MultiText: string(multiTextSlice),
		Vads:      make([]Vad, len(internalEntries)),
	}

	for i, entry := range internalEntries {
		result.Vads[i] = Vad{
			Start:            entry.VaStart,
			End:              entry.VaEnd,
			VadAddress:       entry.VaVad,
			VadType:          entry.Dw0 & 0x7,
			Protection:       (entry.Dw0 >> 3) & 0x1F,
			IsImage:          (entry.Dw0>>8)&1 != 0,
			IsFile:           (entry.Dw0>>9)&1 != 0,
			IsPageFile:       (entry.Dw0>>10)&1 != 0,
			IsPrivateMemory:  (entry.Dw0>>11)&1 != 0,
			IsTeb:            (entry.Dw0>>12)&1 != 0,
			IsStack:          (entry.Dw0>>13)&1 != 0,
			HeapNum:          (entry.Dw0 >> 16) & 0x7F,
			IsHeap:           (entry.Dw0>>23)&1 != 0,
			CommitCharge:     entry.Dw1 & 0x7FFFFFFF,
			IsCommitted:      (entry.Dw1>>31)&1 != 0,
			PrototypePteSize: entry.CbPrototypePte,
			PrototypePte:     entry.VaPrototypePte,
			Subsection:       entry.VaSubsection,
			Text:             cStringToGo(entry.UszText),
			FileObject:       entry.VaFileObject,
			VadExPages:       entry.CVadExPages,
			VadExPagesBase:   entry.CVadExPagesBase,
		}
	}

	return result, nil
}

func (vmm *Vmm) GetThreadList(pid uint32) (*ThreadList, error) {
	var threadListPtr *threadListInternal
	success := vmmMapGetThread(vmm.vmmHandle, pid, &threadListPtr)
	if !success {
		return nil, fmt.Errorf("failed to get thread list for PID %d", pid)
	}
	defer vmm.free(uintptr(unsafe.Pointer(threadListPtr)))

	internalEntries := FAM[threadListInternal, threadEntryInternal](threadListPtr, int(threadListPtr.CMap))

	result := &ThreadList{
		Version: threadListPtr.Version,
		Count:   threadListPtr.CMap,
		Threads: make([]Thread, len(internalEntries)),
	}

	for i, entry := range internalEntries {
		result.Threads[i] = Thread{
			TID:                entry.DwTID,
			PID:                entry.DwPID,
			ExitStatus:         entry.DwExitStatus,
			State:              entry.BState,
			Running:            entry.BRunning,
			Priority:           entry.BPriority,
			BasePriority:       entry.BBasePriority,
			ETHREAD:            entry.VaETHREAD,
			Teb:                entry.VaTeb,
			CreateTime:         entry.FtCreateTime,
			ExitTime:           entry.FtExitTime,
			StartAddress:       entry.VaStartAddress,
			StackBaseUser:      entry.VaStackBaseUser,
			StackLimitUser:     entry.VaStackLimitUser,
			StackBaseKernel:    entry.VaStackBaseKernel,
			StackLimitKernel:   entry.VaStackLimitKernel,
			TrapFrame:          entry.VaTrapFrame,
			RIP:                entry.VaRIP,
			RSP:                entry.VaRSP,
			Affinity:           entry.QwAffinity,
			UserTime:           entry.DwUserTime,
			KernelTime:         entry.DwKernelTime,
			SuspendCount:       entry.BSuspendCount,
			WaitReason:         entry.BWaitReason,
			ImpersonationToken: entry.VaImpersonationToken,
			Win32StartAddress:  entry.VaWin32StartAddress,
		}
	}

	return result, nil
}

type EatList struct {
	Version                    uint32
	OrdinalBase                uint32
	NumberOfNames              uint32
	NumberOfFunctions          uint32
	NumberOfForwardedFunctions uint32
	ModuleBaseAddress          uint64
	AddressOfFunctions         uint64
	AddressOfNames             uint64
	MultiText                  string
	Count                      uint32
	Entries                    []EatEntry
}

// EatEntry represents a single entry in the Export Address Table.
type EatEntry struct {
	FunctionAddress       uint64
	Ordinal               uint32
	FunctionName          string
	ForwardedFunctionName string
	OFunctionsArray       uint32
	ONamesArray           uint32
}

// eatEntryInternal mirrors the C struct VMMDLL_MAP_EATENTRY.
type eatEntryInternal struct {
	VaFunction           uint64
	DwOrdinal            uint32
	OFunctionsArray      uint32
	ONamesArray          uint32
	_                    uint32
	UszFunction          uintptr
	UszForwardedFunction uintptr
}

// eatMapInternal mirrors the C struct VMMDLL_MAP_EAT.
type eatMapInternal struct {
	DwVersion                   uint32
	DwOrdinalBase               uint32
	CNumberOfNames              uint32
	CNumberOfFunctions          uint32
	CNumberOfForwardedFunctions uint32
	_                           [3]uint32
	VaModuleBase                uint64
	VaAddressOfFunctions        uint64
	VaAddressOfNames            uint64
	PbMultiText                 uintptr
	CbMultiText                 uint32
	CMap                        uint32
	// pMap is a flexible array member, handled via pointer arithmetic.
}

// GetEatList retrieves the Export Address Table (EAT) for a given module in a process.
func (vmm *Vmm) GetEatList(pid uint32, moduleName string) (*EatList, error) {
	var pEatMap *eatMapInternal
	success := vmmMapGetEATU(vmm.vmmHandle, pid, moduleName, &pEatMap)
	if !success {
		return nil, fmt.Errorf("VMMDLL_Map_GetEATU failed for module '%s' in PID %d", moduleName, pid)
	}
	defer vmm.free(uintptr(unsafe.Pointer(pEatMap)))

	entriesInternal := FAM[eatMapInternal, eatEntryInternal](pEatMap, int(pEatMap.CMap))

	entries := make([]EatEntry, pEatMap.CMap)
	for i := 0; i < int(pEatMap.CMap); i++ {
		entries[i] = EatEntry{
			FunctionAddress:       entriesInternal[i].VaFunction,
			Ordinal:               entriesInternal[i].DwOrdinal,
			FunctionName:          cStringToGo(entriesInternal[i].UszFunction),
			ForwardedFunctionName: cStringToGo(entriesInternal[i].UszForwardedFunction),
			OFunctionsArray:       entriesInternal[i].OFunctionsArray,
			ONamesArray:           entriesInternal[i].ONamesArray,
		}
	}

	return &EatList{
		Version:                    pEatMap.DwVersion,
		OrdinalBase:                pEatMap.DwOrdinalBase,
		NumberOfNames:              pEatMap.CNumberOfNames,
		NumberOfFunctions:          pEatMap.CNumberOfFunctions,
		NumberOfForwardedFunctions: pEatMap.CNumberOfForwardedFunctions,
		ModuleBaseAddress:          pEatMap.VaModuleBase,
		AddressOfFunctions:         pEatMap.VaAddressOfFunctions,
		AddressOfNames:             pEatMap.VaAddressOfNames,
		MultiText:                  string(unsafe.Slice((*byte)(unsafe.Pointer(pEatMap.PbMultiText)), pEatMap.CbMultiText)),
		Count:                      pEatMap.CMap,
		Entries:                    entries,
	}, nil
}

func (vmm *Vmm) GetHandleList(pid uint32) (*HandleList, error) {
	var handleListPtr *handleListInternal
	success := vmmMapGetHandleU(vmm.vmmHandle, pid, &handleListPtr)
	if !success {
		return nil, fmt.Errorf("failed to get handle list for PID %d", pid)
	}
	defer vmm.free(uintptr(unsafe.Pointer(handleListPtr)))

	internalEntries := FAM[handleListInternal, handleEntryInternal](handleListPtr, int(handleListPtr.CMap))

	multiTextSlice := unsafe.Slice((*byte)(unsafe.Pointer(handleListPtr.PbMultiText)), handleListPtr.CbMultiText)

	result := &HandleList{
		Version:   handleListPtr.Version,
		Count:     handleListPtr.CMap,
		MultiText: string(multiTextSlice),
		Handles:   make([]Handle, len(internalEntries)),
	}

	for i, entry := range internalEntries {
		result.Handles[i] = Handle{
			Object:             entry.VaObject,
			Handle:             entry.DwHandle,
			GrantedAccess:      entry.AccessAndType & 0xFFFFFF, // Lower 24 bits
			TypeIndex:          entry.AccessAndType >> 24,      // Upper 8 bits
			HandleCount:        entry.QwHandleCount,
			PointerCount:       entry.QwPointerCount,
			ObjectCreateInfo:   entry.VaObjectCreateInfo,
			SecurityDescriptor: entry.VaSecurityDescriptor,
			Text:               cStringToGo(entry.UszText),
			PID:                entry.DwPID,
			PoolTag:            entry.DwPoolTag,
			Type:               cStringToGo(entry.UszType),
		}
	}

	return result, nil
}

// IatThunk represents the Thunk data for an IAT entry.
type IatThunk struct {
	Is32Bit               bool
	Hint                  uint16
	RvaFirstThunk         uint32
	RvaOriginalFirstThunk uint32
	RvaNameModule         uint32
	RvaNameFunction       uint32
}

// IatEntry represents a single entry in the Import Address Table.
type IatEntry struct {
	FunctionAddress uint64
	FunctionName    string
	ModuleName      string
	Thunk           IatThunk
}

// IatList represents the Import Address Table for a module.
type IatList struct {
	Version           uint32
	ModuleBaseAddress uint64
	Count             uint32
	MultiText         string
	Entries           []IatEntry
}

// iatThunkInternal mirrors the nested Thunk struct in VMMDLL_MAP_IATENTRY.
type iatThunkInternal struct {
	F32                   bool
	Hint                  uint16
	_                     uint16 // Reserved1
	RvaFirstThunk         uint32
	RvaOriginalFirstThunk uint32
	RvaNameModule         uint32
	RvaNameFunction       uint32
}

// iatEntryInternal mirrors the C struct VMMDLL_MAP_IATENTRY.
type iatEntryInternal struct {
	VaFunction  uint64
	UszFunction uintptr
	_           [2]uint32 // _FutureUse1, _FutureUse2
	UszModule   uintptr
	Thunk       iatThunkInternal
}

// iatMapInternal mirrors the C struct VMMDLL_MAP_IAT.
type iatMapInternal struct {
	DwVersion    uint32
	_            [5]uint32 // Reserved
	VaModuleBase uint64
	PbMultiText  uintptr
	CbMultiText  uint32
	CMap         uint32
	// pMap is a flexible array member, handled via pointer arithmetic.
}

// GetIatList retrieves the Import Address Table (IAT) for a given module in a process.
func (vmm *Vmm) GetIatList(pid uint32, moduleName string) (*IatList, error) {

	var pIatMap *iatMapInternal
	success := vmmMapGetIATU(vmm.vmmHandle, pid, moduleName, &pIatMap)
	if !success {
		return nil, fmt.Errorf("VMMDLL_Map_GetIATU failed for module '%s' in PID %d", moduleName, pid)
	}
	defer vmm.free(uintptr(unsafe.Pointer(pIatMap)))

	if pIatMap == nil || pIatMap.CMap == 0 {
		return &IatList{
			Version:           pIatMap.DwVersion,
			ModuleBaseAddress: pIatMap.VaModuleBase,
			MultiText:         string(unsafe.Slice((*byte)(unsafe.Pointer(pIatMap.PbMultiText)), pIatMap.CbMultiText)),
		}, nil
	}

	entriesInternal := FAM[iatMapInternal, iatEntryInternal](pIatMap, int(pIatMap.CMap))

	entries := make([]IatEntry, pIatMap.CMap)
	for i := 0; i < int(pIatMap.CMap); i++ {
		entries[i] = IatEntry{
			FunctionAddress: entriesInternal[i].VaFunction,
			FunctionName:    cStringToGo(entriesInternal[i].UszFunction),
			ModuleName:      cStringToGo(entriesInternal[i].UszModule),
			Thunk: IatThunk{
				Is32Bit:               entriesInternal[i].Thunk.F32,
				Hint:                  entriesInternal[i].Thunk.Hint,
				RvaFirstThunk:         entriesInternal[i].Thunk.RvaFirstThunk,
				RvaOriginalFirstThunk: entriesInternal[i].Thunk.RvaOriginalFirstThunk,
				RvaNameModule:         entriesInternal[i].Thunk.RvaNameModule,
				RvaNameFunction:       entriesInternal[i].Thunk.RvaNameFunction,
			},
		}
	}

	return &IatList{
		Version:           pIatMap.DwVersion,
		ModuleBaseAddress: pIatMap.VaModuleBase,
		Count:             pIatMap.CMap,
		MultiText:         string(unsafe.Slice((*byte)(unsafe.Pointer(pIatMap.PbMultiText)), pIatMap.CbMultiText)),
		Entries:           entries,
	}, nil
}

// UnloadedModule represents a single unloaded module.
type UnloadedModule struct {
	BaseAddress uint64
	ImageSize   uint32
	IsWow64     bool
	Name        string
	UnloadTime  uint64
	Checksum    uint32
	Timestamp   uint32
}

// UnloadedModuleList contains a list of unloaded modules for a process.
type UnloadedModuleList struct {
	Version   uint32
	Count     uint32
	MultiText string
	Modules   []UnloadedModule
}

// unloadedModuleEntryInternal mirrors the C struct VMMDLL_MAP_UNLOADEDMODULEENTRY.
type unloadedModuleEntryInternal struct {
	VaBase          uint64
	CbImageSize     uint32
	FWoW64          uint32 // BOOL
	UszText         uintptr
	_FutureUse1     uint32
	DwCheckSum      uint32
	DwTimeDateStamp uint32
	_Reserved1      uint32
	FtUnload        uint64
}

// unloadedModuleListInternal mirrors the C struct VMMDLL_MAP_UNLOADEDMODULE.
type unloadedModuleListInternal struct {
	Version     uint32
	_           [5]uint32 // Reserved
	PbMultiText uintptr
	CbMultiText uint32
	CMap        uint32
	// pMap (FAM) starts here
}

// GetUnloadedModuleList retrieves the list of unloaded modules for a given process.
func (vmm *Vmm) GetUnloadedModuleList(pid uint32) (*UnloadedModuleList, error) {
	var pUnloadedModuleMap *unloadedModuleListInternal
	success := vmmMapGetUnloadedModuleU(vmm.vmmHandle, pid, &pUnloadedModuleMap)
	if !success {
		return nil, fmt.Errorf("VMMDLL_Map_GetUnloadedModuleU failed for PID %d", pid)
	}
	defer vmm.free(uintptr(unsafe.Pointer(pUnloadedModuleMap)))

	if pUnloadedModuleMap == nil || pUnloadedModuleMap.CMap == 0 {
		return &UnloadedModuleList{
			Version:   pUnloadedModuleMap.Version,
			MultiText: string(unsafe.Slice((*byte)(unsafe.Pointer(pUnloadedModuleMap.PbMultiText)), pUnloadedModuleMap.CbMultiText)),
		}, nil
	}

	entriesInternal := FAM[unloadedModuleListInternal, unloadedModuleEntryInternal](pUnloadedModuleMap, int(pUnloadedModuleMap.CMap))

	entries := make([]UnloadedModule, pUnloadedModuleMap.CMap)
	for i := 0; i < int(pUnloadedModuleMap.CMap); i++ {
		entries[i] = UnloadedModule{
			BaseAddress: entriesInternal[i].VaBase,
			ImageSize:   entriesInternal[i].CbImageSize,
			IsWow64:     entriesInternal[i].FWoW64 != 0,
			Name:        cStringToGo(entriesInternal[i].UszText),
			UnloadTime:  entriesInternal[i].FtUnload,
			Checksum:    entriesInternal[i].DwCheckSum,
			Timestamp:   entriesInternal[i].DwTimeDateStamp,
		}
	}

	return &UnloadedModuleList{
		Version:   pUnloadedModuleMap.Version,
		Count:     pUnloadedModuleMap.CMap,
		MultiText: string(unsafe.Slice((*byte)(unsafe.Pointer(pUnloadedModuleMap.PbMultiText)), pUnloadedModuleMap.CbMultiText)),
		Modules:   entries,
	}, nil
}

// GetModuleByName retrieves a single module by its name for a given process.
func (vmm *Vmm) GetModuleByName(pid uint32, moduleName string) (*Module, error) {
	var pModuleEntry *moduleEntryInternal
	success := vmmMapGetModuleFromNameU(vmm.vmmHandle, pid, moduleName, &pModuleEntry, 0)
	if !success {
		return nil, fmt.Errorf("VMMDLL_Map_GetModuleFromNameU failed for module '%s' in PID %d", moduleName, pid)
	}
	defer vmm.free(uintptr(unsafe.Pointer(pModuleEntry)))

	if pModuleEntry == nil {
		return nil, fmt.Errorf("module '%s' not found in PID %d", moduleName, pid)
	}

	return &Module{
		BaseAddress:  pModuleEntry.VaBase,
		EntryPoint:   pModuleEntry.VaEntry,
		ImageSize:    pModuleEntry.CbImageSize,
		IsWow64:      pModuleEntry.FWoW64,
		Name:         cStringToGo(pModuleEntry.UszText),
		FullName:     cStringToGo(pModuleEntry.UszFullName),
		Type:         pModuleEntry.Tp,
		FileSize:     pModuleEntry.CbFileSizeRaw,
		SectionCount: pModuleEntry.CSection,
		ExportCount:  pModuleEntry.CEAT,
		ImportCount:  pModuleEntry.CIAT,
	}, nil
}

// PteType corresponds to the VMMDLL_PTE_TP enum.
type PteType uint32

const (
	PteTypeNA         PteType = 0
	PteTypeHardware   PteType = 1
	PteTypeTransition PteType = 2
	PteTypePrototype  PteType = 3
	PteTypeDemandZero PteType = 4
	PteTypeCompressed PteType = 5
	PteTypePageFile   PteType = 6
	PteTypeFile       PteType = 7
)

// pteEntryInternal mirrors the C struct VMMDLL_MAP_PTEENTRY
type pteEntryInternal struct {
	VaBase      uint64
	CPages      uint64
	FPage       uint64 // Bitfield for page flags
	FWoW64      uint32 // BOOL
	_FutureUse1 uint32
	UszText     uintptr
	_Reserved1  uint32
	CSoftware   uint32
}

// PteEntry represents a single Page Table Entry.
type PteEntry struct {
	BaseAddress   uint64
	PageCount     uint64
	PageFlags     uint64
	IsWow64       bool
	Name          string
	SoftwareCount uint32
}

// pteListInternal mirrors the C struct VMMDLL_MAP_PTE
type pteListInternal struct {
	Version     uint32
	_           [5]uint32 // Reserved1
	PbMultiText uintptr
	CbMultiText uint32
	CMap        uint32
	// pMap (FAM) starts here
}

// PteList contains a list of Page Table Entries for a process.
type PteList struct {
	Version   uint32
	Count     uint32
	MultiText string
	Entries   []PteEntry
}

// GetPteList retrieves the Page Table Entries (PTEs) for a given process.
func (vmm *Vmm) GetPteList(pid uint32, identifyModules bool) (*PteList, error) {
	var pPteMap *pteListInternal
	success := vmmMapGetPteU(vmm.vmmHandle, pid, identifyModules, &pPteMap)
	if !success {
		return nil, fmt.Errorf("VMMDLL_Map_GetPteU failed for PID %d", pid)
	}
	defer vmm.free(uintptr(unsafe.Pointer(pPteMap)))

	if pPteMap == nil || pPteMap.CMap == 0 {
		return &PteList{
			Version:   pPteMap.Version,
			MultiText: string(unsafe.Slice((*byte)(unsafe.Pointer(pPteMap.PbMultiText)), pPteMap.CbMultiText)),
		}, nil
	}

	entriesInternal := FAM[pteListInternal, pteEntryInternal](pPteMap, int(pPteMap.CMap))

	entries := make([]PteEntry, pPteMap.CMap)
	for i, entry := range entriesInternal {
		entries[i] = PteEntry{
			BaseAddress:   entry.VaBase,
			PageCount:     entry.CPages,
			PageFlags:     entry.FPage,
			IsWow64:       entry.FWoW64 != 0,
			Name:          cStringToGo(entry.UszText),
			SoftwareCount: entry.CSoftware,
		}
	}

	return &PteList{
		Version:   pPteMap.Version,
		Count:     pPteMap.CMap,
		MultiText: string(unsafe.Slice((*byte)(unsafe.Pointer(pPteMap.PbMultiText)), pPteMap.CbMultiText)),
		Entries:   entries,
	}, nil
}

// netAddrInternal mirrors the nested address struct in VMMDLL_MAP_NETENTRY
type netAddrInternal struct {
	FValid    uint32 // BOOL
	_Reserved uint16
	Port      uint16
	PbAddr    [16]byte
	UszText   uintptr
}

// netEntryInternal mirrors the C struct VMMDLL_MAP_NETENTRY
type netEntryInternal struct {
	DwPID       uint32
	DwState     uint32
	_           [3]uint16 // _FutureUse3
	AF          uint16    // address family (IPv4/IPv6)
	Src         netAddrInternal
	Dst         netAddrInternal
	VaObj       uint64
	FtTime      uint64
	DwPoolTag   uint32
	_FutureUse4 uint32
	UszText     uintptr
	_           [4]uint32 // _FutureUse2
}

// NetAddr represents a single network address.
type NetAddr struct {
	Valid   bool
	Port    uint16
	Address [16]byte
	Text    string
}

// NetEntry represents a single network connection entry.
type NetEntry struct {
	PID           uint32
	State         uint32
	AddressFamily uint16
	Src           NetAddr
	Dst           NetAddr
	Object        uint64
	Timestamp     uint64
	PoolTag       uint32
	Text          string
}

// netListInternal mirrors the C struct VMMDLL_MAP_NET
type netListInternal struct {
	Version     uint32
	_           uint32 // Reserved1
	PbMultiText uintptr
	CbMultiText uint32
	CMap        uint32
	// pMap (FAM) starts here
}

// NetList contains a list of network connections for a process.
type NetList struct {
	Version   uint32
	Count     uint32
	MultiText string
	Entries   []NetEntry
}

// GetNetList retrieves the network connections for a given process.
func (vmm *Vmm) GetNetList() (*NetList, error) {
	var pNetMap *netListInternal
	success := vmmMapGetNetU(vmm.vmmHandle, &pNetMap)
	if !success {
		return nil, fmt.Errorf("VMMDLL_Map_GetNetU failed")
	}
	defer vmm.free(uintptr(unsafe.Pointer(pNetMap)))

	if pNetMap == nil || pNetMap.CMap == 0 {
		return &NetList{
			Version:   pNetMap.Version,
			MultiText: string(unsafe.Slice((*byte)(unsafe.Pointer(pNetMap.PbMultiText)), pNetMap.CbMultiText)),
		}, nil
	}

	entriesInternal := FAM[netListInternal, netEntryInternal](pNetMap, int(pNetMap.CMap))

	entries := make([]NetEntry, pNetMap.CMap)
	for i, entry := range entriesInternal {
		entries[i] = NetEntry{
			PID:           entry.DwPID,
			State:         entry.DwState,
			AddressFamily: entry.AF,
			Src: NetAddr{
				Valid:   entry.Src.FValid != 0,
				Port:    entry.Src.Port,
				Address: entry.Src.PbAddr,
				Text:    cStringToGo(entry.Src.UszText),
			},
			Dst: NetAddr{
				Valid:   entry.Dst.FValid != 0,
				Port:    entry.Dst.Port,
				Address: entry.Dst.PbAddr,
				Text:    cStringToGo(entry.Dst.UszText),
			},
			Object:    entry.VaObj,
			Timestamp: entry.FtTime,
			PoolTag:   entry.DwPoolTag,
			Text:      cStringToGo(entry.UszText),
		}
	}

	return &NetList{
		Version:   pNetMap.Version,
		Count:     pNetMap.CMap,
		MultiText: string(unsafe.Slice((*byte)(unsafe.Pointer(pNetMap.PbMultiText)), pNetMap.CbMultiText)),
		Entries:   entries,
	}, nil
}

// HeapType corresponds to the VMMDLL_HEAP_TP enum.
type HeapType uint32

const (
	HeapTypeNA  HeapType = 0
	HeapTypeNT  HeapType = 1
	HeapTypeSeg HeapType = 2
)

// HeapSegmentType corresponds to the VMMDLL_HEAP_SEGMENT_TP enum.
type HeapSegmentType uint16

const (
	HeapSegmentNA         HeapSegmentType = 0
	HeapSegmentNtSegment  HeapSegmentType = 1
	HeapSegmentNtLfh      HeapSegmentType = 2
	HeapSegmentNtLarge    HeapSegmentType = 3
	HeapSegmentNtNa       HeapSegmentType = 4
	HeapSegmentSegHeap    HeapSegmentType = 5
	HeapSegmentSegSegment HeapSegmentType = 6
	HeapSegmentSegLarge   HeapSegmentType = 7
	HeapSegmentSegNa      HeapSegmentType = 8
)

// heapEntryInternal mirrors the C struct VMMDLL_MAP_HEAPENTRY.
type heapEntryInternal struct {
	Va        uint64
	Tp        HeapType
	Is32Bit   uint32 // BOOL
	IHeap     uint32
	DwHeapNum uint32
}

// HeapEntry represents a single heap entry.
type HeapEntry struct {
	Address uint64
	Type    HeapType
	Is32Bit bool
	IHeap   uint32
	HeapNum uint32
}

// heapSegmentInternal mirrors the C struct VMMDLL_MAP_HEAP_SEGMENTENTRY.
type heapSegmentInternal struct {
	Va      uint64
	Cb      uint32
	TpIHeap uint32 // Bitfield for VMMDLL_HEAP_SEGMENT_TP and iHeap
}

// HeapSegmentEntry represents a single heap segment.
type HeapSegmentEntry struct {
	Address     uint64
	Size        uint32
	SegmentType HeapSegmentType
	HeapIndex   uint16
}

// heapListInternal mirrors the C struct VMMDLL_MAP_HEAP.
type heapListInternal struct {
	Version   uint32
	_         [7]uint32 // Reserved1
	PSegments uintptr
	CSegments uint32
	CMap      uint32
	// pMap (FAM) starts here
}

// HeapList contains a list of heap entries and segments for a process.
type HeapList struct {
	Version  uint32
	Count    uint32
	Segments []HeapSegmentEntry
	Entries  []HeapEntry
}

// GetHeapList retrieves the heap entries for a given process.
func (vmm *Vmm) GetHeapList(pid uint32) (*HeapList, error) {
	var pHeapMap *heapListInternal
	success := vmmMapGetHeap(vmm.vmmHandle, pid, &pHeapMap)
	if !success {
		return nil, fmt.Errorf("VMMDLL_Map_GetHeap failed for PID %d", pid)
	}
	defer vmm.free(uintptr(unsafe.Pointer(pHeapMap)))

	if pHeapMap == nil {
		return nil, fmt.Errorf("VMMDLL_Map_GetHeap returned a nil pointer for PID %d", pid)
	}

	// Process heap entries
	var entries []HeapEntry
	if pHeapMap.CMap > 0 {
		entriesInternal := FAM[heapListInternal, heapEntryInternal](pHeapMap, int(pHeapMap.CMap))
		entries = make([]HeapEntry, pHeapMap.CMap)
		for i, entry := range entriesInternal {
			entries[i] = HeapEntry{
				Address: entry.Va,
				Type:    entry.Tp,
				Is32Bit: entry.Is32Bit != 0,
				IHeap:   entry.IHeap,
				HeapNum: entry.DwHeapNum,
			}
		}
	}

	// Process heap segments
	var segments []HeapSegmentEntry
	if pHeapMap.CSegments > 0 {
		segmentsInternal := unsafe.Slice((*heapSegmentInternal)(unsafe.Pointer(pHeapMap.PSegments)), pHeapMap.CSegments)
		segments = make([]HeapSegmentEntry, pHeapMap.CSegments)
		for i, segment := range segmentsInternal {
			segments[i] = HeapSegmentEntry{
				Address:     segment.Va,
				Size:        segment.Cb,
				SegmentType: HeapSegmentType(segment.TpIHeap & 0xFFFF),
				HeapIndex:   uint16(segment.TpIHeap >> 16),
			}
		}
	}

	return &HeapList{
		Version:  pHeapMap.Version,
		Count:    pHeapMap.CMap,
		Entries:  entries,
		Segments: segments,
	}, nil
}

// HeapAllocType corresponds to the VMMDLL_HEAPALLOC_TP enum.
type HeapAllocType uint32

const (
	HeapAllocTypeNA       HeapAllocType = 0
	HeapAllocTypeNtHeap   HeapAllocType = 1
	HeapAllocTypeNtLfh    HeapAllocType = 2
	HeapAllocTypeNtLarge  HeapAllocType = 3
	HeapAllocTypeNtNa     HeapAllocType = 4
	HeapAllocTypeSegVs    HeapAllocType = 5
	HeapAllocTypeSegLfh   HeapAllocType = 6
	HeapAllocTypeSegLarge HeapAllocType = 7
	HeapAllocTypeSegNa    HeapAllocType = 8
)

// heapAllocEntryInternal mirrors the C struct VMMDLL_MAP_HEAPALLOCENTRY.
type heapAllocEntryInternal struct {
	Va uint64
	Cb uint32
	Tp HeapAllocType
}

// HeapAllocEntry represents a single heap allocation entry.
type HeapAllocEntry struct {
	Address uint64
	Size    uint32
	Type    HeapAllocType
}

// heapAllocListInternal mirrors the C struct VMMDLL_MAP_HEAPALLOC.
type heapAllocListInternal struct {
	Version    uint32
	_          [7]uint32 // Reserved1
	_Reserved2 [2]uintptr
	CMap       uint32
	// pMap (FAM) starts here
}

// HeapAllocList contains a list of heap allocation entries for a process and heap.
type HeapAllocList struct {
	Version uint32
	Count   uint32
	Entries []HeapAllocEntry
}

// GetHeapAllocList retrieves the heap allocation entries for a given process and heap.
func (vmm *Vmm) GetHeapAllocList(pid uint32, heapNumOrAddress uint64) (*HeapAllocList, error) {
	var pHeapAllocMap *heapAllocListInternal
	success := vmmMapGetHeapAlloc(vmm.vmmHandle, pid, heapNumOrAddress, &pHeapAllocMap)
	if !success {
		return nil, fmt.Errorf("VMMDLL_Map_GetHeapAlloc failed for PID %d, heap 0x%x", pid, heapNumOrAddress)
	}
	defer vmm.free(uintptr(unsafe.Pointer(pHeapAllocMap)))

	if pHeapAllocMap == nil || pHeapAllocMap.CMap == 0 {
		return &HeapAllocList{
			Version: pHeapAllocMap.Version,
		}, nil
	}

	entriesInternal := FAM[heapAllocListInternal, heapAllocEntryInternal](pHeapAllocMap, int(pHeapAllocMap.CMap))

	entries := make([]HeapAllocEntry, pHeapAllocMap.CMap)
	for i, entry := range entriesInternal {
		entries[i] = HeapAllocEntry{
			Address: entry.Va,
			Size:    entry.Cb,
			Type:    entry.Tp,
		}
	}

	return &HeapAllocList{
		Version: pHeapAllocMap.Version,
		Count:   pHeapAllocMap.CMap,
		Entries: entries,
	}, nil
}
