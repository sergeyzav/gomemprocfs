package memprocfs

import (
	"fmt"
	"strconv"
)

// Special PID to enable kernel memory access
const (
	PidProcessWithKernelMemory = 0x80000000
)

var defaultArgs = []string{"-device", "fpga"}

// Option is a functional option for NewVmm.
// Use the With* constructors to build the option list.
type Option func() []string

// WithDevice sets the target device or memory source.
// Accepts a file path (e.g. "./dump.raw"), a device name, or a special string like "fpga".
func WithDevice(device string) Option {
	return func() []string {
		return []string{"-device", device}
	}
}

// WithDeviceFPGA connects to an FPGA hardware device (default if no option is given).
func WithDeviceFPGA() Option {
	return func() []string {
		return []string{"-device", "fpga"}
	}
}

// WithPrintf enables stdout output from the native vmmdll library.
func WithPrintf() Option {
	return func() []string {
		return []string{"-printf"}
	}
}

// WithMemMap provides a physical memory map file that describes memory regions.
func WithMemMap(filename string) Option {
	return func() []string {
		return []string{"-memmap", filename}
	}
}

// WithVerbose enables verbose diagnostic output from the native library.
func WithVerbose() Option {
	return func() []string {
		return []string{"-v"}
	}
}
// WithPageFile attaches a Windows page file to supplement the memory image.
// pageID is 0–9 corresponding to pagefile0–pagefile9.
func WithPageFile(pageID int, pageFile string) Option {
	return func() []string {
		return []string{fmt.Sprintf("-pagefile%d", pageID), pageFile}
	}
}

// WithRemote connects to a remote LeechAgent instead of a local device.
// dsn format: "remoteaddr:port" or a LeechCore DSN string.
func WithRemote(dsn string) Option {
	return func() []string {
		return []string{"-remote", dsn}
	}
}

// WithNorefresh disables the background memory refresh that re-reads live targets periodically.
func WithNorefresh() Option {
	return func() []string {
		return []string{"-norefresh"}
	}
}

// WithDisablePython disables the Python plugin subsystem.
func WithDisablePython() Option {
	return func() []string {
		return []string{"-disable-python"}
	}
}

// WithDisableSymbolServer disables network access to the Microsoft symbol server.
// Use when offline or to speed up initialization.
func WithDisableSymbolServer() Option {
	return func() []string {
		return []string{"-disable-symbolserver"}
	}
}

// WithDisableSymbols skips PDB symbol loading entirely (faster startup, no symbol resolution).
func WithDisableSymbols() Option {
	return func() []string {
		return []string{"-disable-symbols"}
	}
}
// WithDisableInfoDB disables the internal info/symbol database.
func WithDisableInfoDB() Option {
	return func() []string {
		return []string{"-disable-infodb"}
	}
}
// WithWaitInitialize blocks NewVmm until full initialization is complete.
// Without this, some data (e.g. processes) may not be ready immediately after NewVmm returns.
func WithWaitInitialize() Option {
	return func() []string {
		return []string{"-waitinitialize"}
	}
}

// WithVM enables detection and parsing of virtual machines in the memory image.
func WithVM() Option {
	return func() []string {
		return []string{"-vm"}
	}
}

// WithVMBasic enables basic VM detection (less thorough than WithVM, faster).
func WithVMBasic() Option {
	return func() []string {
		return []string{"-vm-basic"}
	}
}

// WithVMNested enables nested VM detection (VMs inside VMs).
func WithVMNested() Option {
	return func() []string {
		return []string{"-vm-nested"}
	}
}

// WithForensic enables forensic mode at the given level (0–4).
// Higher levels perform more analysis (e.g. timeline, yara scanning) at the cost of time.
func WithForensic(lvl int) Option {
	return func() []string {
		return []string{"-forensic", strconv.Itoa(lvl)}
	}
}
