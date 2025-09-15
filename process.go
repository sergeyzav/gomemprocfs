package memprocfs

/*
#include "vmmdll.h"
*/
import "C"
import (
	"context"
	"encoding/binary"
	"fmt"
	"unsafe"
)

type MemoryModel uint32

const (
	MemoryModelNA MemoryModel = iota
	MemoryModelX86
	MemoryModelX86PAE
	MemoryModelX64
	MemoryModelARM64
)

func (m MemoryModel) String() string {
	switch m {
	case MemoryModelNA:
		return "N/A"
	case MemoryModelX86:
		return "X86"
	case MemoryModelX86PAE:
		return "X86PAE"
	case MemoryModelX64:
		return "X64"
	case MemoryModelARM64:
		return "ARM64"
	default:
		return "Unknown"
	}
}

type SystemType uint32

const (
	SystemUnknownPhysical SystemType = iota
	SystemUnknown64
	SystemWindows64
	SystemUnknown32
	SystemWindows32
)

func (s SystemType) String() string {
	switch s {
	case SystemUnknownPhysical:
		return "UnknownPhysical"
	case SystemUnknown64:
		return "Unknown64"
	case SystemWindows64:
		return "Windows64"
	case SystemUnknown32:
		return "Unknown32"
	case SystemWindows32:
		return "Windows32"
	default:
		return "Unknown"
	}
}

type ProcessIntegrityLevel uint32

const (
	ProcessIntegrityLevelUnknown ProcessIntegrityLevel = iota
	ProcessIntegrityLevelUntrusted
	ProcessIntegrityLevelLow
	ProcessIntegrityLevelMedium
	ProcessIntegrityLevelMediumPlus
	ProcessIntegrityLevelHigh
	ProcessIntegrityLevelSystem
	ProcessIntegrityLevelProtected
)

// String метод для перетворення рівня інтеграції в строкове значення
func (p ProcessIntegrityLevel) String() string {
	switch p {
	case ProcessIntegrityLevelUnknown:
		return "Unknown"
	case ProcessIntegrityLevelUntrusted:
		return "Untrusted"
	case ProcessIntegrityLevelLow:
		return "Low"
	case ProcessIntegrityLevelMedium:
		return "Medium"
	case ProcessIntegrityLevelMediumPlus:
		return "MediumPlus"
	case ProcessIntegrityLevelHigh:
		return "High"
	case ProcessIntegrityLevelSystem:
		return "System"
	case ProcessIntegrityLevelProtected:
		return "Protected"
	default:
		return "Unknown"
	}
}

type ProcessInformation struct {
	Magic         uint64
	WVersion      uint16
	WSize         uint16
	TpMemoryModel MemoryModel
	TpSystem      SystemType
	FUserOnly     bool
	DwPID         uint32
	DwPPID        uint32
	DwState       uint32
	SzName        string
	SzNameLong    string
	PaDTB         uint64
	PaDTB_UserOpt uint64
	Win           struct {
		VaEPROCESS     uint64
		VaPEB          uint64
		Reserved1      uint64
		FWow64         bool
		VaPEB32        uint32
		DwSessionId    uint32
		QwLUID         uint64
		SzSID          [260]byte
		IntegrityLevel ProcessIntegrityLevel
	}
}

func newProcessInformationFromC(pInfo C.VMMDLL_PROCESS_INFORMATION) ProcessInformation {
	return ProcessInformation{
		Magic:         uint64(pInfo.magic),
		WVersion:      uint16(pInfo.wVersion),
		WSize:         uint16(pInfo.wSize),
		TpMemoryModel: MemoryModel(pInfo.tpMemoryModel),
		TpSystem:      SystemType(pInfo.tpSystem),
		FUserOnly:     pInfo.fUserOnly != 0,
		DwPID:         uint32(pInfo.dwPID),
		DwPPID:        uint32(pInfo.dwPPID),
		DwState:       uint32(pInfo.dwState),
		PaDTB:         uint64(pInfo.paDTB),
		PaDTB_UserOpt: uint64(pInfo.paDTB_UserOpt),
		SzName:        C.GoString((*C.char)(unsafe.Pointer(&pInfo.szName))),
		SzNameLong:    C.GoString((*C.char)(unsafe.Pointer(&pInfo.szNameLong))),
		Win: struct {
			VaEPROCESS     uint64
			VaPEB          uint64
			Reserved1      uint64
			FWow64         bool
			VaPEB32        uint32
			DwSessionId    uint32
			QwLUID         uint64
			SzSID          [260]byte
			IntegrityLevel ProcessIntegrityLevel
		}{
			VaEPROCESS:     uint64(pInfo.win.vaEPROCESS),
			VaPEB:          uint64(pInfo.win.vaPEB),
			Reserved1:      uint64(pInfo.win._Reserved1),
			FWow64:         pInfo.win.fWow64 != 0,
			VaPEB32:        uint32(pInfo.win.vaPEB32),
			DwSessionId:    uint32(pInfo.win.dwSessionId),
			QwLUID:         uint64(pInfo.win.qwLUID),
			IntegrityLevel: ProcessIntegrityLevel(pInfo.win.IntegrityLevel),
			SzSID:          *(*[260]byte)(unsafe.Pointer(&pInfo.win.szSID)),
		},
	}
}

func (vmm *Vmm) getProcessInfo(pid uint32) (*ProcessInformation, error) {
	var size C.SIZE_T = 0
	ok := C.VMMDLL_ProcessGetInformation(C.VMM_HANDLE(vmm.handle), C.DWORD(pid), nil, &size)

	if ok == 0 || size == 0 {
		return nil, fmt.Errorf("VMMDLL_ProcessGetInformation failed to get size")
	}

	pInfo := C.VMMDLL_PROCESS_INFORMATION{
		magic:    C.VMMDLL_PROCESS_INFORMATION_MAGIC,
		wVersion: C.VMMDLL_PROCESS_INFORMATION_VERSION,
	}
	ok = C.VMMDLL_ProcessGetInformation(C.VMM_HANDLE(vmm.handle), C.DWORD(pid), &pInfo, &size)

	if ok == 0 {
		return nil, fmt.Errorf("failed to get process info: %d", pid)
	}

	result := newProcessInformationFromC(pInfo)

	return &result, nil
}

func (vmm *Vmm) GetProcessInfo(ctx context.Context, pid uint32) (*ProcessInformation, error) {
	resultChan := make(chan struct {
		procInfo *ProcessInformation
		err      error
	})

	go func() {
		procInfo, err := vmm.getProcessInfo(pid)
		resultChan <- struct {
			procInfo *ProcessInformation
			err      error
		}{
			procInfo: procInfo,
			err:      err,
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-resultChan:
		return result.procInfo, result.err
	}
}

func (vmm *Vmm) getProcessInfoList() ([]ProcessInformation, error) {
	var processCount C.DWORD
	var processInformationAll C.PVMMDLL_PROCESS_INFORMATION

	success := C.VMMDLL_ProcessGetInformationAll(C.VMM_HANDLE(vmm.handle), &processInformationAll, &processCount)

	if success == 0 {
		return nil, fmt.Errorf("failed to retrieve process information")
	}

	defer freeMemory(C.PVOID(processInformationAll))

	result := make([]ProcessInformation, processCount)

	for i := C.DWORD(0); i < processCount; i++ {
		processInfoPtr := *(C.PVMMDLL_PROCESS_INFORMATION)(unsafe.Pointer(uintptr(unsafe.Pointer(processInformationAll)) + uintptr(i)*unsafe.Sizeof(*processInformationAll)))
		processInfo := newProcessInformationFromC(processInfoPtr)
		result[i] = processInfo
	}

	return result, nil
}

func (vmm *Vmm) GetProcessInfoList(ctx context.Context) ([]ProcessInformation, error) {
	resultChan := make(chan struct {
		result []ProcessInformation
		err    error
	})
	go func() {
		result, err := vmm.getProcessInfoList()
		resultChan <- struct {
			result []ProcessInformation
			err    error
		}{result, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-resultChan:
		return r.result, r.err
	}
}

func (vmm *Vmm) getPidByName(name string) (uint32, error) {
	pid := C.DWORD(0)

	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	ok := C.VMMDLL_PidGetFromName(C.VMM_HANDLE(vmm.handle), C.LPSTR(cName), &pid)

	if pid == 0 || ok == 0 {
		return 0, fmt.Errorf("failed to find process by name: %s", name)
	}
	return uint32(pid), nil
}

func (vmm *Vmm) GetPidByName(ctx context.Context, name string) (uint32, error) {
	resultChan := make(chan struct {
		pid uint32
		err error
	})
	go func() {
		pid, err := vmm.getPidByName(name)
		resultChan <- struct {
			pid uint32
			err error
		}{pid, err}
	}()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case result := <-resultChan:
		return result.pid, result.err
	}
}

func (vmm *Vmm) getPidList() ([]uint32, error) {
	var count C.SIZE_T = 0

	ok := C.VMMDLL_PidList(C.VMM_HANDLE(vmm.handle), nil, &count)
	if ok == 0 {
		return nil, fmt.Errorf("VMMDLL_PidList failed to get count")
	}

	if count == 0 {
		return []uint32{}, nil
	}

	pids := make([]C.DWORD, count)

	ok = C.VMMDLL_PidList(C.VMM_HANDLE(vmm.handle), (*C.DWORD)(unsafe.Pointer(&pids[0])), &count)
	if ok == 0 {
		return nil, fmt.Errorf("VMMDLL_PidList failed to get pids")
	}

	result := make([]uint32, int(count))
	for i := 0; i < int(count); i++ {
		result[i] = uint32(pids[i])
	}

	return result, nil
}

func (vmm *Vmm) GetPidList(ctx context.Context) ([]uint32, error) {
	resultChan := make(chan struct {
		pids []uint32
		err  error
	}, 1)

	go func() {
		pids, err := vmm.getPidList()
		resultChan <- struct {
			pids []uint32
			err  error
		}{pids, err}
	}()

	select {
	case <-ctx.Done():
		return []uint32{}, ctx.Err()
	case result := <-resultChan:
		return result.pids, result.err
	}
}

const (
	ProcessInformationOptStringPathKernel    = 1
	ProcessInformationOptStringPathUserImage = 2
	ProcessInformationOptStringCmdline       = 3
)

func (vmm *Vmm) getProcessInfoString(pid uint32, fOptionString uint32) (string, error) {
	cStr := C.VMMDLL_ProcessGetInformationString(C.VMM_HANDLE(vmm.handle), C.DWORD(pid), C.DWORD(fOptionString))

	if cStr == nil {
		return "", fmt.Errorf("failed to retrieve process information string")
	}

	defer freeMemory(C.PVOID(cStr))

	goString := C.GoString(cStr)
	return goString, nil
}

func (vmm *Vmm) GetProcessInfoString(ctx context.Context, pid uint32, fOptionString uint32) (string, error) {
	resultChan := make(chan struct {
		info string
		err  error
	}, 1)

	go func() {
		info, err := vmm.getProcessInfoString(pid, fOptionString)
		resultChan <- struct {
			info string
			err  error
		}{info, err}
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case result := <-resultChan:
		return result.info, result.err
	}
}

type ImageDataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

func (vmm *Vmm) getProcessDirectories(pid uint32, module string) ([]ImageDataDirectory, error) {
	var dataDirectories [16]C.IMAGE_DATA_DIRECTORY
	var dataCount uint32

	cModule := C.CString(module)
	defer C.free(unsafe.Pointer(cModule))

	success := C.VMMDLL_ProcessGetDirectoriesU(
		C.VMM_HANDLE(vmm.handle),
		C.DWORD(pid),
		cModule,
		(*C.IMAGE_DATA_DIRECTORY)(unsafe.Pointer(&dataDirectories[0])),
	)
	if success == 0 {
		return nil, fmt.Errorf("failed to retrieve directories for process %d, module %s", pid, module)
	}

	result := make([]ImageDataDirectory, dataCount)
	for i := 0; i < int(dataCount); i++ {
		result[i] = ImageDataDirectory{
			VirtualAddress: uint32(dataDirectories[i].VirtualAddress),
			Size:           uint32(dataDirectories[i].Size),
		}
	}

	return result, nil
}

func (vmm *Vmm) GetProcessDirectories(ctx context.Context, pid uint32, module string) ([]ImageDataDirectory, error) {
	resultChan := make(chan struct {
		directories []ImageDataDirectory
		err         error
	}, 1)

	go func() {
		directories, err := vmm.getProcessDirectories(pid, module)
		resultChan <- struct {
			directories []ImageDataDirectory
			err         error
		}{directories, err}
	}()

	select {
	case <-ctx.Done():
		return []ImageDataDirectory{}, ctx.Err()
	case result := <-resultChan:
		return result.directories, result.err
	}
}

const ImageSizeOfShortName = 8

type ImageSectionHeader struct {
	Name                 [ImageSizeOfShortName]byte
	Misc                 AddrUnion
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
}

type AddrUnion uint32

func (a AddrUnion) PhysicalAddress() uint32 {
	return uint32(a)
}

func (a AddrUnion) VirtualSize() uint32 {
	return uint32(a)
}

func (vmm *Vmm) getProcessSections(pid uint32, module string) ([]ImageSectionHeader, error) {
	cModule := C.CString(module)
	defer C.free(unsafe.Pointer(cModule))

	var sectionCount C.DWORD

	success := C.VMMDLL_ProcessGetSectionsU(
		C.VMM_HANDLE(vmm.handle),
		C.DWORD(pid),
		cModule,
		nil,
		0,
		&sectionCount,
	)
	if success == 0 {
		return nil, fmt.Errorf("VMMDLL_ProcessGetSectionsU: failed to get section count for module %s", module)
	}

	if sectionCount == 0 {
		return []ImageSectionHeader{}, nil
	}

	sections := make([]C.IMAGE_SECTION_HEADER, sectionCount)

	success = C.VMMDLL_ProcessGetSectionsU(
		C.VMM_HANDLE(vmm.handle),
		C.DWORD(pid),
		cModule,
		(*C.IMAGE_SECTION_HEADER)(unsafe.Pointer(&sections[0])),
		sectionCount,
		&sectionCount,
	)
	if success == 0 {
		return nil, fmt.Errorf("failed to get sections for module %s", module)
	}

	result := make([]ImageSectionHeader, sectionCount)
	for i, section := range sections {
		var name [ImageSizeOfShortName]byte
		copy(name[:], C.GoBytes(unsafe.Pointer(&section.Name[0]), ImageSizeOfShortName))

		result[i] = ImageSectionHeader{
			Name:                 name,
			Misc:                 AddrUnion(binary.LittleEndian.Uint32(section.Misc[:])),
			VirtualAddress:       uint32(section.VirtualAddress),
			SizeOfRawData:        uint32(section.SizeOfRawData),
			PointerToRawData:     uint32(section.PointerToRawData),
			PointerToRelocations: uint32(section.PointerToRelocations),
			PointerToLineNumbers: uint32(section.PointerToLinenumbers),
			NumberOfRelocations:  uint16(section.NumberOfRelocations),
			NumberOfLineNumbers:  uint16(section.NumberOfLinenumbers),
			Characteristics:      uint32(section.Characteristics),
		}
	}

	return result, nil
}

func (vmm *Vmm) GetProcessSections(ctx context.Context, pid uint32, module string) ([]ImageSectionHeader, error) {
	resultChan := make(chan struct {
		sections []ImageSectionHeader
		err      error
	}, 1)

	go func() {
		sections, err := vmm.getProcessSections(pid, module)
		resultChan <- struct {
			sections []ImageSectionHeader
			err      error
		}{sections, err}
	}()

	select {
	case <-ctx.Done():
		return []ImageSectionHeader{}, ctx.Err()
	case result := <-resultChan:
		return result.sections, result.err
	}
}

func (vmm *Vmm) GetProcessAddress(ctx context.Context, pid uint32, module string, funcName string) (uint64, error) {
	resultChan := make(chan struct {
		addr uint64
		err  error
	}, 1)

	go func() {
		cModule := C.CString(module)
		defer C.free(unsafe.Pointer(cModule))

		cFuncName := C.CString(funcName)
		defer C.free(unsafe.Pointer(cFuncName))

		addr := C.VMMDLL_ProcessGetProcAddressU(C.VMM_HANDLE(vmm.handle), C.DWORD(pid), cModule, cFuncName)

		var err error
		if addr == 0 {
			err = fmt.Errorf("VMMDLL_ProcessGetProcAddressU: failed to get function address 0x%x for module %s", addr, module)
		}

		resultChan <- struct {
			addr uint64
			err  error
		}{uint64(addr), err}
	}()

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case result := <-resultChan:
		return result.addr, result.err
	}
}

func (vmm *Vmm) GetProcessModule(ctx context.Context, pid uint32, module string) (uint64, error) {
	resultChan := make(chan struct {
		addr uint64
		err  error
	}, 1)

	go func() {
		cModule := C.CString(module)
		defer C.free(unsafe.Pointer(cModule))

		addr := C.VMMDLL_ProcessGetModuleBaseU(C.VMM_HANDLE(vmm.handle), C.DWORD(pid), cModule)

		var err error
		if addr == 0 {
			err = fmt.Errorf("VMMDLL_ProcessGetModuleBaseU: failed to get address 0x%x of module %s", addr, module)
		}

		resultChan <- struct {
			addr uint64
			err  error
		}{uint64(addr), err}
	}()

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case result := <-resultChan:
		return result.addr, result.err
	}
}

type PTEEntry struct {
	VABase     uint64
	Pages      uint64
	PageFlags  uint64
	IsWoW64    bool
	FutureUse1 uint32
	Text       string
	Reserved1  uint32
	SoftCount  uint32
}

func newPTEEntryFromC(cEntry *C.VMMDLL_MAP_PTEENTRY) PTEEntry {
	offsetUnion := unsafe.Offsetof(cEntry._FutureUse1) + unsafe.Sizeof(cEntry._FutureUse1)
	textPtr := *(*uintptr)(unsafe.Pointer(uintptr(unsafe.Pointer(cEntry)) + offsetUnion))

	return PTEEntry{
		VABase:     uint64(cEntry.vaBase),
		Pages:      uint64(cEntry.cPages),
		PageFlags:  uint64(cEntry.fPage),
		IsWoW64:    cEntry.fWoW64 != 0,
		FutureUse1: uint32(cEntry._FutureUse1),
		Text:       C.GoString((*C.char)(unsafe.Pointer(textPtr))),
		Reserved1:  uint32(cEntry._Reserved1),
		SoftCount:  uint32(cEntry.cSoftware),
	}
}

// C.VMMDLL_MAP_PTE.
type PTE struct {
	Version    uint32
	MultiText  []string
	MapEntries []PTEEntry
}

func newPTEFromC(cPte *C.VMMDLL_MAP_PTE) PTE {
	var multiText []string
	if cPte.pbMultiText != nil && cPte.cbMultiText > 0 {
		multiText = multiString(C.GoBytes(unsafe.Pointer(cPte.pbMultiText), C.int(cPte.cbMultiText)))
	}

	count := int(cPte.cMap)
	entries := make([]PTEEntry, count)
	cEntryPtr := unsafe.Pointer(uintptr(unsafe.Pointer(cPte)) + unsafe.Offsetof(cPte.cMap) + unsafe.Sizeof(cPte.cMap))
	for i, cEntry := range cArray[C.VMMDLL_MAP_PTEENTRY](cEntryPtr, count) {
		entries[i] = newPTEEntryFromC(cEntry)
	}

	return PTE{
		Version:    uint32(cPte.dwVersion),
		MultiText:  multiText,
		MapEntries: entries,
	}
}

func (vmm *Vmm) getProcessMapPTE(pid uint32, identifyModules bool) (*PTE, error) {
	var cPteMap C.PVMMDLL_MAP_PTE
	success := C.VMMDLL_Map_GetPteU(C.VMM_HANDLE(vmm.handle), C.DWORD(pid), C.BOOL(boolToInt(identifyModules)), &cPteMap)

	if success == 0 || cPteMap == nil {
		return nil, fmt.Errorf("failed to get PTE map for process %d", pid)
	}

	defer freeMemory(C.PVOID(cPteMap))

	if cPteMap.dwVersion != MapPTEVersion {
		return nil, ErrUnsupportedPTEVersion
	}

	pte := newPTEFromC(cPteMap)

	return &pte, nil
}

func (vmm *Vmm) GetProcessMapPTE(ctx context.Context, pid uint32, identifyModules bool) (*PTE, error) {
	resultChan := make(chan struct {
		pte *PTE
		err error
	}, 1)

	go func() {
		pte, err := vmm.getProcessMapPTE(pid, identifyModules)
		resultChan <- struct {
			pte *PTE
			err error
		}{pte, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-resultChan:
		return result.pte, result.err
	}
}

type VADEntry struct {
	VaStart uint64
	VaEnd   uint64
	VaVad   uint64

	VadType         uint8
	Protection      uint8
	IsImage         bool
	IsFile          bool
	IsPageFile      bool
	IsPrivateMemory bool
	IsTeb           bool
	IsStack         bool
	Spare           uint8
	HeapNum         uint8
	IsHeap          bool
	CwszDescription uint8

	CommitCharge   uint32
	MemCommit      bool
	U2             uint32
	CbPrototypePte uint32
	VaPrototypePte uint64
	VaSubsection   uint64

	Text string

	FutureUse1      uint32
	Reserved1       uint32
	VaFileObject    uint64
	CVadExPages     uint32
	CVadExPagesBase uint32
	Reserved2       uint64
}

type VAD struct {
	Version    uint32
	PageCount  uint32
	MultiText  []string
	MapEntries []VADEntry
}

func newVADEntry(cEntry *C.VMMDLL_MAP_VADENTRY) VADEntry {

	ptr := *(*uintptr)(unsafe.Pointer(uintptr(unsafe.Pointer(cEntry)) + unsafe.Offsetof(cEntry.vaSubsection) + unsafe.Sizeof(cEntry.vaSubsection)))
	text := C.GoString((*C.char)(unsafe.Pointer(ptr)))

	flags := *(*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(cEntry)) + unsafe.Offsetof(cEntry.vaVad) + unsafe.Sizeof(cEntry.vaVad)))
	nextFlags := *(*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(cEntry)) + unsafe.Offsetof(cEntry.vaVad) + unsafe.Sizeof(cEntry.vaVad) + unsafe.Sizeof(C.DWORD(0))))

	return VADEntry{
		VaStart: uint64(cEntry.vaStart),
		VaEnd:   uint64(cEntry.vaEnd),
		VaVad:   uint64(cEntry.vaVad),

		VadType:         uint8((flags >> 0) & 0x7),
		Protection:      uint8((flags >> 3) & 0x1F),
		IsImage:         ((flags >> 8) & 0x1) != 0,
		IsFile:          ((flags >> 9) & 0x1) != 0,
		IsPageFile:      ((flags >> 10) & 0x1) != 0,
		IsPrivateMemory: ((flags >> 11) & 0x1) != 0,
		IsTeb:           ((flags >> 12) & 0x1) != 0,
		IsStack:         ((flags >> 13) & 0x1) != 0,
		Spare:           uint8((flags >> 14) & 0x3),
		HeapNum:         uint8((flags >> 16) & 0x7F),
		IsHeap:          ((flags >> 23) & 0x1) != 0,
		CwszDescription: uint8((flags >> 24) & 0xFF),

		CommitCharge:    nextFlags & 0x7FFFFFFF,
		MemCommit:       (nextFlags>>31)&0x1 != 0,
		U2:              uint32(cEntry.u2),
		CbPrototypePte:  uint32(cEntry.cbPrototypePte),
		VaPrototypePte:  uint64(cEntry.vaPrototypePte),
		VaSubsection:    uint64(cEntry.vaSubsection),
		Text:            text,
		FutureUse1:      uint32(cEntry._FutureUse1),
		Reserved1:       uint32(cEntry._Reserved1),
		VaFileObject:    uint64(cEntry.vaFileObject),
		CVadExPages:     uint32(cEntry.cVadExPages),
		CVadExPagesBase: uint32(cEntry.cVadExPagesBase),
		Reserved2:       uint64(cEntry._Reserved2),
	}
}

func newVAD(cVad *C.VMMDLL_MAP_VAD) VAD {
	count := uint32(cVad.cMap)

	entries := make([]VADEntry, count)
	cEntryPtr := unsafe.Pointer(uintptr(unsafe.Pointer(cVad)) + unsafe.Offsetof(cVad.cMap) + unsafe.Sizeof(cVad.cMap))

	for i, cEntry := range cArray[C.VMMDLL_MAP_VADENTRY](cEntryPtr, int(count)) {
		entries[i] = newVADEntry(cEntry)
	}
	return VAD{
		Version:    uint32(cVad.dwVersion),
		PageCount:  uint32(cVad.cPage),
		MultiText:  multiString(C.GoBytes(unsafe.Pointer(cVad.pbMultiText), C.int(cVad.cbMultiText))),
		MapEntries: entries,
	}
}

func (vmm *Vmm) getProcessMapVAD(pid uint32, identifyModules bool) (*VAD, error) {
	var cVadMap C.PVMMDLL_MAP_VAD
	success := C.VMMDLL_Map_GetVadU(C.VMM_HANDLE(vmm.handle), C.DWORD(pid), C.BOOL(boolToInt(identifyModules)), &cVadMap)

	if success == 0 || cVadMap == nil {
		return nil, fmt.Errorf("failed to get VAD map for process %d", pid)
	}

	defer freeMemory(C.PVOID(cVadMap))

	if cVadMap.dwVersion != MapVADVersion {
		return nil, ErrUnsupportedVADVersion
	}

	vad := newVAD(cVadMap)

	return &vad, nil
}

func (vmm *Vmm) GetProcessMapVAD(ctx context.Context, pid uint32, identifyModules bool) (*VAD, error) {
	resultChan := make(chan struct {
		vad *VAD
		err error
	}, 1)

	go func() {
		vad, err := vmm.getProcessMapVAD(pid, identifyModules)
		resultChan <- struct {
			vad *VAD
			err error
		}{vad, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-resultChan:
		return result.vad, result.err
	}
}

type Module struct {
	Version   uint32
	MultiText []string
	Entries   []ModuleEntry
}

type ModuleEntry struct {
	VaBase       uint64
	VaEntry      uint64
	ImageSize    uint32
	WoW64        bool
	Name         string
	FullName     string
	FileSizeRaw  uint32
	SectionCount uint32
	EatCount     uint32
	IatCount     uint32
}

func newModuleEntry(cEntry *C.VMMDLL_MAP_MODULEENTRY) ModuleEntry {
	entry := ModuleEntry{
		VaBase:       uint64(cEntry.vaBase),
		VaEntry:      uint64(cEntry.vaEntry),
		ImageSize:    uint32(cEntry.cbImageSize),
		WoW64:        cEntry.fWoW64 != 0,
		FileSizeRaw:  uint32(cEntry.cbFileSizeRaw),
		SectionCount: uint32(cEntry.cSection),
		EatCount:     uint32(cEntry.cEAT),
		IatCount:     uint32(cEntry.cIAT),
	}

	uszTextPtr := *(*uintptr)(unsafe.Pointer(uintptr(unsafe.Pointer(cEntry)) + unsafe.Offsetof(cEntry.fWoW64) + unsafe.Sizeof(cEntry.fWoW64)))
	entry.Name = C.GoString((*C.char)(unsafe.Pointer(uszTextPtr)))

	uszFullNamePtr := *(*uintptr)(unsafe.Pointer(uintptr(unsafe.Pointer(cEntry)) + unsafe.Offsetof(cEntry._Reserved4) + unsafe.Sizeof(cEntry._Reserved4)))
	entry.FullName = C.GoString((*C.char)(unsafe.Pointer(uszFullNamePtr)))

	return entry
}
func newModule(cMod *C.VMMDLL_MAP_MODULE) Module {
	mod := Module{
		Version: uint32(cMod.dwVersion),
	}

	// MultiText
	if cMod.pbMultiText != nil && cMod.cbMultiText > 0 {
		mod.MultiText = multiString(C.GoBytes(unsafe.Pointer(cMod.pbMultiText), C.int(cMod.cbMultiText)))
	}

	// Entries
	count := int(cMod.cMap)

	//entriesPtr := unsafe.Pointer(uintptr(unsafe.Pointer(cMod)) + unsafe.Offsetof(cMod.cMap) + unsafe.Sizeof(cMod.cMap))
	entriesPtr := afterDWORD(unsafe.Pointer(&cMod.cMap))

	mod.Entries = make([]ModuleEntry, count)

	for i, cEntry := range cArray[C.VMMDLL_MAP_MODULEENTRY](entriesPtr, count) {
		entry := newModuleEntry(cEntry)

		mod.Entries[i] = entry
	}

	return mod
}

/**
todo :VMMDLL_Map_GetVadEx
*/

func (vmm *Vmm) getProcessModuleList(pid uint32, flags uint32) (*Module, error) {
	var cModules C.PVMMDLL_MAP_MODULE

	success := C.VMMDLL_Map_GetModuleU(C.VMM_HANDLE(vmm.handle), C.DWORD(pid), &cModules, C.DWORD(flags))

	if success == 0 {
		return nil, fmt.Errorf("failed to get module list for process %d", pid)
	}

	defer freeMemory(C.PVOID(cModules))

	module := newModule(cModules)
	return &module, nil
}
func (vmm *Vmm) GetProcessModuleList(ctx context.Context, pid uint32, flags uint32) (*Module, error) {
	resultChan := make(chan struct {
		module *Module
		err    error
	}, 1)

	go func() {
		module, err := vmm.getProcessModuleList(pid, flags)
		resultChan <- struct {
			module *Module
			err    error
		}{module, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-resultChan:
		return result.module, result.err
	}
}
