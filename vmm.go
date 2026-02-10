package memprocfs

import "C"
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
	vmmInitialize                  func(argc int32, args []*byte) uintptr
	vmmClose                       func(vmmHandle uintptr) uintptr
	vmmMemSize                     func(handle uintptr) uint64
	vmmMemFree                     func(handle uintptr) uintptr
	vmmConfigGet                   func(vmmHandle uintptr, option uint64, value *uint64) bool
	vmmConfigSet                   func(vmmHandle uintptr, option uint64, value uint64) bool
	vmmInitializePlugins           func(vmmHandle uintptr) bool
	vmmPidGetFromName              func(vmmHandle uintptr, name string, pid *uint32) bool
	vmmProcessGetInformationString func(vmmHandle uintptr, pid uint32, opt uint32) uintptr
	vmmProcessGetInformation       func(vmmHandle uintptr, pid uint32, pProcessInformation unsafe.Pointer, pcbProcessInformation *uint32) bool
	vmmMemRead                     func(vmmHandle uintptr, pid uint32, addr uint64, pb unsafe.Pointer, cb uint32) bool
	vmmMapGetModuleU               func(vmmHandle uintptr, pid uint32, ppModuleMap **moduleListInternal, flags uint32) bool
	vmmMapGetThread                func(vmmHandle uintptr, pid uint32, ppThreadMap **threadListInternal) bool
	vmmMapGetVadU                  func(vmmHandle uintptr, pid uint32, identifyModules bool, ppVadMap **vadListInternal) bool
	vmmMapGetHandleU               func(vmmHandle uintptr, pid uint32, ppHandleMap **handleListInternal) bool
	vmmWinRegHiveList              func(vmmHandle uintptr, pHives *registryHiveInfoInternal, cHives uint32, pcHives *uint32) bool
	vmmMapGetEATU                  func(vmmHandle uintptr, pid uint32, moduleName string, ppEatMap **eatMapInternal) bool
	vmmMapGetIATU                  func(vmmHandle uintptr, pid uint32, moduleName string, ppIatMap **iatMapInternal) bool
	vmmMapGetUnloadedModuleU       func(vmmHandle uintptr, pid uint32, ppUnloadedModuleMap **unloadedModuleListInternal) bool
	vmmMapGetModuleFromNameU       func(vmmHandle uintptr, pid uint32, moduleName string, ppModuleEntry **moduleEntryInternal, flags uint32) bool
	vmmMapGetPteU                  func(vmmHandle uintptr, pid uint32, identifyModules bool, ppPteMap **pteListInternal) bool
	vmmMapGetNetU                  func(vmmHandle uintptr, ppNetMap **netListInternal) bool
	vmmMapGetHeap                  func(vmmHandle uintptr, pid uint32, ppHeapMap **heapListInternal) bool
	vmmMapGetHeapAlloc             func(vmmHandle uintptr, pid uint32, heapNumOrAddress uint64, ppHeapAllocMap **heapAllocListInternal) bool
	vmmMapGetServicesU             func(vmmHandle uintptr, ppServiceMap **serviceListInternal) bool
	vmmMapGetPhysMem               func(vmmHandle uintptr, ppPhysMemMap **physMemListInternal) bool
	vmmMapGetThreadCallstackU      func(vmmHandle uintptr, pid, tid, flags uint32, ppCallstackMap **threadCallstackInternal) bool
	vmmProcessGetSectionsU         func(vmmHandle uintptr, pid uint32, moduleName string, pSections unsafe.Pointer, cSections uint32, pcSections *uint32) bool
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

	if loadFunctions(lib) != nil {
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
	purego.RegisterLibFunc(&vmmMemSize, lib, "VMMDLL_MemSize")
	purego.RegisterLibFunc(&vmmMemFree, lib, "VMMDLL_MemFree")
	purego.RegisterLibFunc(&vmmConfigGet, lib, "VMMDLL_ConfigGet")
	purego.RegisterLibFunc(&vmmConfigSet, lib, "VMMDLL_ConfigSet")
	purego.RegisterLibFunc(&vmmInitializePlugins, lib, "VMMDLL_InitializePlugins")
	purego.RegisterLibFunc(&vmmPidGetFromName, lib, "VMMDLL_PidGetFromName")
	purego.RegisterLibFunc(&vmmProcessGetInformationString, lib, "VMMDLL_ProcessGetInformationString")
	purego.RegisterLibFunc(&vmmProcessGetInformation, lib, "VMMDLL_ProcessGetInformation")
	purego.RegisterLibFunc(&vmmMemRead, lib, "VMMDLL_MemRead")
	purego.RegisterLibFunc(&vmmMapGetModuleU, lib, "VMMDLL_Map_GetModuleU")
	purego.RegisterLibFunc(&vmmMapGetThread, lib, "VMMDLL_Map_GetThread")
	purego.RegisterLibFunc(&vmmMapGetVadU, lib, "VMMDLL_Map_GetVadU")
	purego.RegisterLibFunc(&vmmMapGetHandleU, lib, "VMMDLL_Map_GetHandleU")
	purego.RegisterLibFunc(&vmmWinRegHiveList, lib, "VMMDLL_WinReg_HiveList")
	purego.RegisterLibFunc(&vmmMapGetEATU, lib, "VMMDLL_Map_GetEATU")
	purego.RegisterLibFunc(&vmmMapGetIATU, lib, "VMMDLL_Map_GetIATU")
	purego.RegisterLibFunc(&vmmMapGetUnloadedModuleU, lib, "VMMDLL_Map_GetUnloadedModuleU")
	purego.RegisterLibFunc(&vmmMapGetModuleFromNameU, lib, "VMMDLL_Map_GetModuleFromNameU")
	purego.RegisterLibFunc(&vmmMapGetPteU, lib, "VMMDLL_Map_GetPteU")
	purego.RegisterLibFunc(&vmmMapGetNetU, lib, "VMMDLL_Map_GetNetU")
	purego.RegisterLibFunc(&vmmMapGetHeap, lib, "VMMDLL_Map_GetHeap")
	purego.RegisterLibFunc(&vmmMapGetHeapAlloc, lib, "VMMDLL_Map_GetHeapAlloc")
	purego.RegisterLibFunc(&vmmMapGetServicesU, lib, "VMMDLL_Map_GetServicesU")
	purego.RegisterLibFunc(&vmmMapGetPhysMem, lib, "VMMDLL_Map_GetPhysMem")
	purego.RegisterLibFunc(&vmmMapGetThreadCallstackU, lib, "VMMDLL_Map_GetThread_CallstackU")
	purego.RegisterLibFunc(&vmmProcessGetSectionsU, lib, "VMMDLL_ProcessGetSectionsU")

	return nil
}
