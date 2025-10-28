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
	VaStart        uint64
	VaEnd          uint64
	VaVad          uint64
	Dw0            uint32 // Bitfield
	Dw1            uint32 // Bitfield
	U2             uint32
	CbPrototypePte uint32
	VaPrototypePte uint64
	VaSubsection   uint64
	UszText        uintptr
	_              uint32 // FutureUse1
	_              uint32 // Reserved1
	VaFileObject   uint64
	CVadExPages    uint32
	CVadExPagesBase uint32
	_              uint64 // Reserved2
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
	Object              uint64
	Handle              uint32
	GrantedAccess       uint32
	TypeIndex           uint32
	HandleCount         uint64
	PointerCount        uint64
	ObjectCreateInfo    uint64
	SecurityDescriptor  uint64
	Text                string
	PID                 uint32
	PoolTag             uint32
	Type                string
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
			GrantedAccess:      entry.AccessAndType & 0xFFFFFF,   // Lower 24 bits
			TypeIndex:          entry.AccessAndType >> 24,        // Upper 8 bits
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
