package memprocfs

/*
#include "vmmdll.h"
#include "leechcore.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"strconv"
	"unsafe"
)

// Special PID to enable kernel memory access
const (
	PidProcessWithKernelMemory = 0x80000000
)

type vmmHandle C.VMM_HANDLE

type Vmm struct {
	handle vmmHandle
}

var defaultArgs = []string{"-device", "fpga"}

type Option func() []string

func WithDevice(device string) Option {
	return func() []string {
		return []string{"-device", device}
	}
}

func WithDeviceFPGA() Option {
	return func() []string {
		return []string{"-device", "fpga"}
	}
}

func WithPrintf() Option {
	return func() []string {
		return []string{"-printf"}
	}
}

func WithMemMap(filename string) Option {
	return func() []string {
		return []string{"-memmap", filename}
	}
}

func WithVerbose() Option {
	return func() []string {
		return []string{"-v"}
	}
}
func WithPageFile(pageID int, pageFile string) Option {
	return func() []string {
		return []string{fmt.Sprintf("-pagefile%d", pageID), pageFile}
	}
}

func WithRemote(dsn string) Option {
	return func() []string {
		return []string{"-remote", dsn}
	}
}

func WithNorefresh() Option {
	return func() []string {
		return []string{"-norefresh"}
	}
}

func WithDisablePython() Option {
	return func() []string {
		return []string{"-disable-python"}
	}
}

func WithDisableSymbolServer() Option {
	return func() []string {
		return []string{"-disable-symbolserver"}
	}
}

func WithDisableSymbols() Option {
	return func() []string {
		return []string{"-disable-symbols"}
	}
}
func WithDisableInfoDB() Option {
	return func() []string {
		return []string{"-disable-infodb"}
	}
}
func WithWaitInitialize() Option {
	return func() []string {
		return []string{"-waitinitialize"}
	}
}

func WithVM() Option {
	return func() []string {
		return []string{"-vm"}
	}
}

func WithVMBasic() Option {
	return func() []string {
		return []string{"-vm-basic"}
	}
}

func WithVMNested() Option {
	return func() []string {
		return []string{"-vm-nested"}
	}
}

func WithForensic(lvl int) Option {
	return func() []string {
		return []string{"-forensic", strconv.Itoa(lvl)}
	}
}

func NewVmm(opts ...Option) (*Vmm, error) {
	var args []string

	for _, opt := range opts {
		args = append(args, opt()...)
	}

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

	C.VMMDLL_Close(v.handle)
}

func CloseAll() {
	C.VMMDLL_CloseAll()
}

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
