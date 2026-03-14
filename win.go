package memprocfs

import (
	"fmt"
	"unsafe"
)

// IATThunkInfo holds information about a single Import Address Table thunk.
// Useful for detecting IAT hooks and for locating where a specific import lives in memory.
type IATThunkInfo struct {
	Is32Bit      bool   // true if thunk entry is 4 bytes wide (32-bit process)
	VaThunk      uint64 // virtual address of the IAT slot itself
	VaFunction   uint64 // current value of the IAT slot = actual function address
	VaNameModule uint64 // VA of the null-terminated module name string
	VaNameFunc   uint64 // VA of the null-terminated function name string
}

// winThunkInfoInternal mirrors VMMDLL_WIN_THUNKINFO_IAT (40 bytes on x64).
type winThunkInfoInternal struct {
	FValid         uint32 // BOOL
	F32            uint32 // BOOL
	VaThunk        uint64
	VaFunction     uint64
	VaNameModule   uint64
	VaNameFunction uint64
}

// GetIATThunkInfo retrieves IAT thunk details for a specific imported function.
//   - pid               — target process PID
//   - moduleName        — the module that owns the IAT (e.g. "notepad.exe")
//   - importModuleName  — the DLL being imported from (e.g. "ntdll.dll")
//   - importFuncName    — the function name (e.g. "NtCreateFile")
func (vmm *Vmm) GetIATThunkInfo(pid uint32, moduleName string, importModuleName string, importFuncName string) (*IATThunkInfo, error) {
	var raw winThunkInfoInternal
	if !vmmWinGetThunkInfoIATU(vmm.vmmHandle, pid, moduleName, importModuleName, importFuncName, unsafe.Pointer(&raw)) {
		return nil, fmt.Errorf("GetIATThunkInfo failed for PID %d module %q import %q!%q",
			pid, moduleName, importModuleName, importFuncName)
	}
	return &IATThunkInfo{
		Is32Bit:      raw.F32 != 0,
		VaThunk:      raw.VaThunk,
		VaFunction:   raw.VaFunction,
		VaNameModule: raw.VaNameModule,
		VaNameFunc:   raw.VaNameFunction,
	}, nil
}
