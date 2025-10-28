package memprocfs

import "C"
import (
	"fmt"
	"strconv"
)

// Special PID to enable kernel memory access
const (
	PidProcessWithKernelMemory = 0x80000000
)

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
