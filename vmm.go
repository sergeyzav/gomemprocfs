package memprocfs

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"github.com/ebitengine/purego"
)

type Vmm struct {
	libHandle uintptr
	vmmHandle uintptr
}

var (
	// ─── core ────────────────────────────────────────────────────────────────
	vmmInitialize func(argc int32, args []*byte) uintptr
	vmmClose      func(vmmHandle uintptr) uintptr
	vmmCloseAll   func()
	vmmMemSize    func(handle uintptr) uint64
	vmmMemFree    func(handle uintptr) uintptr

	// ─── config ──────────────────────────────────────────────────────────────
	vmmConfigGet         func(vmmHandle uintptr, option uint64, value *uint64) bool
	vmmConfigSet         func(vmmHandle uintptr, option uint64, value uint64) bool
	vmmInitializePlugins func(vmmHandle uintptr) bool

	// ─── process ─────────────────────────────────────────────────────────────
	vmmPidList                     func(vmmHandle uintptr, pPIDs unsafe.Pointer, pcPIDs *uint64) bool
	vmmPidGetFromName              func(vmmHandle uintptr, name string, pid *uint32) bool
	vmmProcessGetInformationString func(vmmHandle uintptr, pid uint32, opt uint32) uintptr
	vmmProcessGetInformation       func(vmmHandle uintptr, pid uint32, pProcessInformation unsafe.Pointer, pcbProcessInformation *uint32) bool
	vmmProcessGetInformationAll    func(vmmHandle uintptr, ppInfoAll **ProcessInfo, pcInfo *uint32) bool
	vmmProcessGetModuleBaseU       func(vmmHandle uintptr, pid uint32, moduleName string) uint64
	vmmProcessGetProcAddressU      func(vmmHandle uintptr, pid uint32, moduleName string, funcName string) uint64
	vmmProcessGetSectionsU         func(vmmHandle uintptr, pid uint32, moduleName string, pSections unsafe.Pointer, cSections uint32, pcSections *uint32) bool
	vmmProcessGetDirectoriesU      func(vmmHandle uintptr, pid uint32, moduleName string, pDirectories unsafe.Pointer) bool

	// ─── memory ──────────────────────────────────────────────────────────────
	vmmMemRead          func(vmmHandle uintptr, pid uint32, addr uint64, pb unsafe.Pointer, cb uint32) bool
	vmmMemReadEx        func(vmmHandle uintptr, pid uint32, addr uint64, pb unsafe.Pointer, cb uint32, pcbRead *uint32, flags uint64) bool
	vmmMemReadPage      func(vmmHandle uintptr, pid uint32, addr uint64, pb unsafe.Pointer) bool
	vmmMemPrefetchPages func(vmmHandle uintptr, pid uint32, pAddresses unsafe.Pointer, cAddresses uint32) bool
	vmmMemWrite         func(vmmHandle uintptr, pid uint32, addr uint64, pb unsafe.Pointer, cb uint32) bool
	vmmMemVirt2Phys     func(vmmHandle uintptr, pid uint32, va uint64, pa *uint64) bool

	// ─── scatter ─────────────────────────────────────────────────────────────
	vmmScatterInitialize  func(vmmHandle uintptr, pid uint32, flags uint32) uintptr
	vmmScatterPrepare     func(hS uintptr, va uint64, cb uint32) bool
	vmmScatterPrepareWrite func(hS uintptr, va uint64, pb unsafe.Pointer, cb uint32) bool
	vmmScatterExecute     func(hS uintptr) bool
	vmmScatterExecuteRead func(hS uintptr) bool
	vmmScatterRead        func(hS uintptr, va uint64, cb uint32, pb unsafe.Pointer, pcbRead *uint32) bool
	vmmScatterClear       func(hS uintptr, pid uint32, flags uint32) bool
	vmmScatterCloseHandle func(hS uintptr)

	// ─── map (process) ───────────────────────────────────────────────────────
	vmmMapGetModuleU         func(vmmHandle uintptr, pid uint32, ppModuleMap **moduleListInternal, flags uint32) bool
	vmmMapGetModuleFromNameU func(vmmHandle uintptr, pid uint32, moduleName string, ppModuleEntry **moduleEntryInternal, flags uint32) bool
	vmmMapGetThread          func(vmmHandle uintptr, pid uint32, ppThreadMap **threadListInternal) bool
	vmmMapGetVadU            func(vmmHandle uintptr, pid uint32, identifyModules bool, ppVadMap **vadListInternal) bool
	vmmMapGetVadEx           func(vmmHandle uintptr, pid uint32, oPage uint32, cPage uint32, ppVadExMap **vadExListInternal) bool
	vmmMapGetHandleU         func(vmmHandle uintptr, pid uint32, ppHandleMap **handleListInternal) bool
	vmmMapGetPteU            func(vmmHandle uintptr, pid uint32, identifyModules bool, ppPteMap **pteListInternal) bool
	vmmMapGetEATU            func(vmmHandle uintptr, pid uint32, moduleName string, ppEatMap **eatMapInternal) bool
	vmmMapGetIATU            func(vmmHandle uintptr, pid uint32, moduleName string, ppIatMap **iatMapInternal) bool
	vmmMapGetUnloadedModuleU func(vmmHandle uintptr, pid uint32, ppUnloadedModuleMap **unloadedModuleListInternal) bool
	vmmMapGetHeap            func(vmmHandle uintptr, pid uint32, ppHeapMap **heapListInternal) bool
	vmmMapGetHeapAlloc       func(vmmHandle uintptr, pid uint32, heapNumOrAddress uint64, ppHeapAllocMap **heapAllocListInternal) bool

	// ─── map (system) ────────────────────────────────────────────────────────
	vmmMapGetKDeviceU         func(vmmHandle uintptr, ppKDeviceMap **kdeviceListInternal) bool
	vmmMapGetKDriverU         func(vmmHandle uintptr, ppKDriverMap **kdriverListInternal) bool
	vmmMapGetKObjectU         func(vmmHandle uintptr, ppKObjectMap **kobjectListInternal) bool
	vmmMapGetUsersU           func(vmmHandle uintptr, ppUserMap **userListInternal) bool
	vmmMapGetPool             func(vmmHandle uintptr, ppPoolMap **poolListInternal, flags uint32) bool
	vmmMapGetNetU             func(vmmHandle uintptr, ppNetMap **netListInternal) bool
	vmmMapGetServicesU        func(vmmHandle uintptr, ppServiceMap **serviceListInternal) bool
	vmmMapGetPhysMem          func(vmmHandle uintptr, ppPhysMemMap **physMemListInternal) bool
	vmmMapGetPfnEx            func(vmmHandle uintptr, pPfns unsafe.Pointer, cPfns uint32, ppPfnMap **pfnListInternal, flags uint32) bool
	vmmMapGetVMU              func(vmmHandle uintptr, ppVmMap **vmListInternal) bool
	vmmMapGetThreadCallstackU func(vmmHandle uintptr, pid, tid, flags uint32, ppCallstackMap **threadCallstackInternal) bool

	// ─── registry ────────────────────────────────────────────────────────────
	vmmWinRegHiveList      func(vmmHandle uintptr, pHives *registryHiveInfoInternal, cHives uint32, pcHives *uint32) bool
	vmmWinRegHiveReadEx    func(vmmHandle uintptr, vaCMHive uint64, ra uint32, pb unsafe.Pointer, cb uint32, pcbRead *uint32, flags uint64) bool
	vmmWinRegHiveWrite     func(vmmHandle uintptr, vaCMHive uint64, ra uint32, pb unsafe.Pointer, cb uint32) bool
	vmmWinRegEnumKeyExU    func(vmmHandle uintptr, fullPathKey string, index uint32, lpName unsafe.Pointer, lpcchName *uint32, lpftLastWriteTime *uint64) bool
	vmmWinRegEnumValueU    func(vmmHandle uintptr, fullPathKey string, index uint32, lpValueName unsafe.Pointer, lpcchValueName *uint32, lpType *uint32, lpData unsafe.Pointer, lpcbData *uint32) bool
	vmmWinRegQueryValueExU func(vmmHandle uintptr, fullPathKeyValue string, lpType *uint32, lpData unsafe.Pointer, lpcbData *uint32) bool

	// ─── pdb ─────────────────────────────────────────────────────────────────
	vmmPdbLoad            func(vmmHandle uintptr, pid uint32, vaModuleBase uint64, szModuleName unsafe.Pointer) bool
	vmmPdbSymbolName      func(vmmHandle uintptr, szModule string, cbSymbolAddressOrOffset uint64, szSymbolName unsafe.Pointer, pdwDisplacement *uint32) bool
	vmmPdbSymbolAddress   func(vmmHandle uintptr, szModule string, szSymbolName string, pvaSymbolAddress *uint64) bool
	vmmPdbTypeSize        func(vmmHandle uintptr, szModule string, szTypeName string, pcbTypeSize *uint32) bool
	vmmPdbTypeChildOffset func(vmmHandle uintptr, szModule string, szTypeName string, szTypeChildName string, pcbTypeChildOffset *uint32) bool

	// ─── vfs ─────────────────────────────────────────────────────────────────
	vmmVfsListBlobU func(vmmHandle uintptr, path string) uintptr
	vmmVfsReadU     func(vmmHandle uintptr, path string, pb unsafe.Pointer, cb uint32, pcbRead *uint32, cbOffset uint64) uint32
	vmmVfsWriteU    func(vmmHandle uintptr, path string, pb unsafe.Pointer, cb uint32, pcbWrite *uint32, cbOffset uint64) uint32

	// ─── win ─────────────────────────────────────────────────────────────────
	vmmWinGetThunkInfoIATU func(vmmHandle uintptr, pid uint32, moduleName string, importModuleName string, importFunctionName string, pThunkInfo unsafe.Pointer) bool

	// ─── vm ──────────────────────────────────────────────────────────────────
	vmmVmGetVmmHandle    func(vmmHandle uintptr, hVM uintptr) uintptr
	vmmVmScatterInitialize func(vmmHandle uintptr, hVM uintptr) uintptr
	vmmVmMemRead         func(vmmHandle uintptr, hVM uintptr, qwGPA uint64, pb unsafe.Pointer, cb uint32) bool
	vmmVmMemWrite        func(vmmHandle uintptr, hVM uintptr, qwGPA uint64, pb unsafe.Pointer, cb uint32) bool
	vmmVmMemTranslateGPA func(vmmHandle uintptr, hVM uintptr, qwGPA uint64, pPA *uint64, pVA *uint64) bool
)

func NewVmm(libPath string, opts ...Option) (*Vmm, error) {
	var args []string

	for _, opt := range opts {
		args = append(args, opt()...)
	}

	if len(args) == 0 {
		args = defaultArgs
	}

	lib, err := openLibrary(libPath)

	if err != nil {
		return nil, err
	}

	if err := loadFunctions(lib); err != nil {
		return nil, err
	}

	argsBytes := make([]*byte, len(args))
	for i, arg := range args {
		argsBytes[i], err = syscall.BytePtrFromString(arg)
	}

	vmmHandle := vmmInitialize(int32(len(args)), argsBytes)

	if vmmHandle == 0 {
		return nil, errors.New("failed to initialize Vmm")
	}

	vmm := &Vmm{
		libHandle: lib,
		vmmHandle: vmmHandle,
	}

	if err := vmm.InitializePlugins(); err != nil {
		vmm.Close()
		return nil, fmt.Errorf("failed to initialize plugins: %w", err)
	}

	return vmm, nil
}

func (vmm *Vmm) InitializePlugins() error {
	if !vmmInitializePlugins(vmm.vmmHandle) {
		return errors.New("failed to initialize plugins")
	}
	return nil
}

func (vmm *Vmm) Close() error {
	result := vmmClose(vmm.vmmHandle)

	if result == 0 {
		return errors.New("failed to close Vmm")
	}

	return nil
}

// CloseAll closes all active VMM_HANDLE instances and frees all resources.
// It is a global operation — use with care when multiple Vmm instances exist.
func CloseAll() {
	vmmCloseAll()
}

func (vmm *Vmm) free(recourse uintptr) error {
	result := vmmMemFree(recourse)

	if result != 0 {
		return errors.New("failed to free memory")
	}

	return nil
}

func loadFunctions(lib uintptr) error {
	purego.RegisterLibFunc(&vmmInitialize, lib, "VMMDLL_Initialize")
	purego.RegisterLibFunc(&vmmClose, lib, "VMMDLL_Close")
	purego.RegisterLibFunc(&vmmCloseAll, lib, "VMMDLL_CloseAll")
	purego.RegisterLibFunc(&vmmMemSize, lib, "VMMDLL_MemSize")
	purego.RegisterLibFunc(&vmmMemFree, lib, "VMMDLL_MemFree")
	purego.RegisterLibFunc(&vmmConfigGet, lib, "VMMDLL_ConfigGet")
	purego.RegisterLibFunc(&vmmConfigSet, lib, "VMMDLL_ConfigSet")
	purego.RegisterLibFunc(&vmmInitializePlugins, lib, "VMMDLL_InitializePlugins")
	purego.RegisterLibFunc(&vmmPidList, lib, "VMMDLL_PidList")
	purego.RegisterLibFunc(&vmmPidGetFromName, lib, "VMMDLL_PidGetFromName")
	purego.RegisterLibFunc(&vmmProcessGetInformationString, lib, "VMMDLL_ProcessGetInformationString")
	purego.RegisterLibFunc(&vmmProcessGetInformation, lib, "VMMDLL_ProcessGetInformation")
	purego.RegisterLibFunc(&vmmProcessGetInformationAll, lib, "VMMDLL_ProcessGetInformationAll")
	purego.RegisterLibFunc(&vmmMemRead, lib, "VMMDLL_MemRead")
	purego.RegisterLibFunc(&vmmMemReadEx, lib, "VMMDLL_MemReadEx")
	purego.RegisterLibFunc(&vmmMemReadPage, lib, "VMMDLL_MemReadPage")
	purego.RegisterLibFunc(&vmmMemPrefetchPages, lib, "VMMDLL_MemPrefetchPages")
	purego.RegisterLibFunc(&vmmMemWrite, lib, "VMMDLL_MemWrite")
	purego.RegisterLibFunc(&vmmMemVirt2Phys, lib, "VMMDLL_MemVirt2Phys")
	purego.RegisterLibFunc(&vmmProcessGetModuleBaseU, lib, "VMMDLL_ProcessGetModuleBaseU")
	purego.RegisterLibFunc(&vmmProcessGetProcAddressU, lib, "VMMDLL_ProcessGetProcAddressU")
	purego.RegisterLibFunc(&vmmMapGetModuleU, lib, "VMMDLL_Map_GetModuleU")
	purego.RegisterLibFunc(&vmmMapGetThread, lib, "VMMDLL_Map_GetThread")
	purego.RegisterLibFunc(&vmmMapGetVadU, lib, "VMMDLL_Map_GetVadU")
	purego.RegisterLibFunc(&vmmMapGetHandleU, lib, "VMMDLL_Map_GetHandleU")
	purego.RegisterLibFunc(&vmmWinRegHiveList, lib, "VMMDLL_WinReg_HiveList")
	purego.RegisterLibFunc(&vmmWinRegHiveReadEx, lib, "VMMDLL_WinReg_HiveReadEx")
	purego.RegisterLibFunc(&vmmWinRegHiveWrite, lib, "VMMDLL_WinReg_HiveWrite")
	purego.RegisterLibFunc(&vmmWinRegEnumKeyExU, lib, "VMMDLL_WinReg_EnumKeyExU")
	purego.RegisterLibFunc(&vmmWinRegEnumValueU, lib, "VMMDLL_WinReg_EnumValueU")
	purego.RegisterLibFunc(&vmmWinRegQueryValueExU, lib, "VMMDLL_WinReg_QueryValueExU")
	purego.RegisterLibFunc(&vmmMapGetEATU, lib, "VMMDLL_Map_GetEATU")
	purego.RegisterLibFunc(&vmmMapGetIATU, lib, "VMMDLL_Map_GetIATU")
	purego.RegisterLibFunc(&vmmMapGetUnloadedModuleU, lib, "VMMDLL_Map_GetUnloadedModuleU")
	purego.RegisterLibFunc(&vmmMapGetModuleFromNameU, lib, "VMMDLL_Map_GetModuleFromNameU")
	purego.RegisterLibFunc(&vmmMapGetPteU, lib, "VMMDLL_Map_GetPteU")
	purego.RegisterLibFunc(&vmmMapGetKDeviceU, lib, "VMMDLL_Map_GetKDeviceU")
	purego.RegisterLibFunc(&vmmMapGetKDriverU, lib, "VMMDLL_Map_GetKDriverU")
	purego.RegisterLibFunc(&vmmMapGetKObjectU, lib, "VMMDLL_Map_GetKObjectU")
	purego.RegisterLibFunc(&vmmMapGetUsersU, lib, "VMMDLL_Map_GetUsersU")
	purego.RegisterLibFunc(&vmmMapGetPool, lib, "VMMDLL_Map_GetPool")
	purego.RegisterLibFunc(&vmmMapGetNetU, lib, "VMMDLL_Map_GetNetU")
	purego.RegisterLibFunc(&vmmMapGetHeap, lib, "VMMDLL_Map_GetHeap")
	purego.RegisterLibFunc(&vmmMapGetHeapAlloc, lib, "VMMDLL_Map_GetHeapAlloc")
	purego.RegisterLibFunc(&vmmMapGetServicesU, lib, "VMMDLL_Map_GetServicesU")
	purego.RegisterLibFunc(&vmmMapGetPhysMem, lib, "VMMDLL_Map_GetPhysMem")
	purego.RegisterLibFunc(&vmmMapGetThreadCallstackU, lib, "VMMDLL_Map_GetThread_CallstackU")
	purego.RegisterLibFunc(&vmmProcessGetSectionsU, lib, "VMMDLL_ProcessGetSectionsU")
	purego.RegisterLibFunc(&vmmProcessGetDirectoriesU, lib, "VMMDLL_ProcessGetDirectoriesU")
	purego.RegisterLibFunc(&vmmScatterInitialize, lib, "VMMDLL_Scatter_Initialize")
	purego.RegisterLibFunc(&vmmScatterPrepare, lib, "VMMDLL_Scatter_Prepare")
	purego.RegisterLibFunc(&vmmScatterPrepareWrite, lib, "VMMDLL_Scatter_PrepareWrite")
	purego.RegisterLibFunc(&vmmScatterExecute, lib, "VMMDLL_Scatter_Execute")
	purego.RegisterLibFunc(&vmmScatterExecuteRead, lib, "VMMDLL_Scatter_ExecuteRead")
	purego.RegisterLibFunc(&vmmScatterRead, lib, "VMMDLL_Scatter_Read")
	purego.RegisterLibFunc(&vmmScatterClear, lib, "VMMDLL_Scatter_Clear")
	purego.RegisterLibFunc(&vmmScatterCloseHandle, lib, "VMMDLL_Scatter_CloseHandle")
	purego.RegisterLibFunc(&vmmPdbLoad, lib, "VMMDLL_PdbLoad")
	purego.RegisterLibFunc(&vmmPdbSymbolName, lib, "VMMDLL_PdbSymbolName")
	purego.RegisterLibFunc(&vmmPdbSymbolAddress, lib, "VMMDLL_PdbSymbolAddress")
	purego.RegisterLibFunc(&vmmPdbTypeSize, lib, "VMMDLL_PdbTypeSize")
	purego.RegisterLibFunc(&vmmPdbTypeChildOffset, lib, "VMMDLL_PdbTypeChildOffset")
	purego.RegisterLibFunc(&vmmVfsListBlobU, lib, "VMMDLL_VfsListBlobU")
	purego.RegisterLibFunc(&vmmVfsReadU, lib, "VMMDLL_VfsReadU")
	purego.RegisterLibFunc(&vmmVfsWriteU, lib, "VMMDLL_VfsWriteU")
	purego.RegisterLibFunc(&vmmMapGetVadEx, lib, "VMMDLL_Map_GetVadEx")
	purego.RegisterLibFunc(&vmmMapGetPfnEx, lib, "VMMDLL_Map_GetPfnEx")
	purego.RegisterLibFunc(&vmmMapGetVMU, lib, "VMMDLL_Map_GetVMU")
	purego.RegisterLibFunc(&vmmWinGetThunkInfoIATU, lib, "VMMDLL_WinGetThunkInfoIATU")
	purego.RegisterLibFunc(&vmmVmGetVmmHandle, lib, "VMMDLL_VmGetVmmHandle")
	purego.RegisterLibFunc(&vmmVmScatterInitialize, lib, "VMMDLL_VmScatterInitialize")
	purego.RegisterLibFunc(&vmmVmMemRead, lib, "VMMDLL_VmMemRead")
	purego.RegisterLibFunc(&vmmVmMemWrite, lib, "VMMDLL_VmMemWrite")
	purego.RegisterLibFunc(&vmmVmMemTranslateGPA, lib, "VMMDLL_VmMemTranslateGPA")

	return nil
}
