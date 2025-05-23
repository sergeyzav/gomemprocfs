package memprocfs

/*
#include "vmmdll.h"
#include "leechcore.h"
*/
import "C"
import (
	"errors"
	"unsafe"
)

// Special PID to enable kernel memory access
const (
	PidProcessWithKernelMemory = 0x80000000
)

// Memory read/write flags
const (
	VMMDLL_MEM_FLAG_NONE            = 0x00000000
	VMMDLL_MEM_FLAG_ZEROPAD_ON_FAIL = 0x00000001
	VMMDLL_MEM_FLAG_CACHE_READ      = 0x00000002
	VMMDLL_MEM_FLAG_NOCACHE         = 0x00000004
	VMMDLL_MEM_FLAG_NOCACHEPUT      = 0x00000008
	VMMDLL_MEM_FLAG_NOPAGING        = 0x00000010
	VMMDLL_MEM_FLAG_NOPAGING_IO     = 0x00000020
)

type vmmHandle C.VMM_HANDLE

type Vmm struct {
	handle vmmHandle
}

var defaultArgs = []string{"-device", "fpga"}

func NewVmm(args ...string) (*Vmm, error) {
	if len(args) == 0 {
		args = defaultArgs
	}
	cArgs := make([]C.LPCSTR, len(args))
	for i, s := range args {
		cArgs[i] = C.CString(s)
		defer C.free(unsafe.Pointer(cArgs[i]))
	}

	argc := C.DWORD(len(args))

	handle := C.VMMDLL_Initialize(argc, &cArgs[0])
	if handle == nil {
		return nil, errors.New("VMM initialization failed")
	}

	return &Vmm{handle: vmmHandle(handle)}, nil
}

func (v *Vmm) Close() {
	if v.handle == nil {
		return
	}

	go C.VMMDLL_Close(v.handle)
}

func CloseAll() {
	C.VMMDLL_CloseAll()
}

// MemReadScatter reads memory in a scattered way

func (v *Vmm) NewScatterTask(pid uint32, flags uint32) (*ScatterTask, error) {
	return InitializeScatter(v, pid, flags)
}

func freeMemory(ptr C.PVOID) {
	if ptr != nil {
		C.VMMDLL_MemFree(ptr)
	}
}

func getMemSize(ptr C.PVOID) uint64 {
	if ptr == nil {
		return 0
	}

	return uint64(C.VMMDLL_MemSize(ptr))
}
