package memprocfs

import (
	"fmt"
	"unsafe"

	"github.com/sergeyzav/memprocfs/internal/ffi"
)

// PdbLoad loads the PDB symbol file for the given module and returns
// the module name used internally (e.g. "nt", "kernel32").
// The module name can then be passed to PdbSymbolAddress, PdbTypeSize, etc.
func (vmm *Vmm) PdbLoad(pid uint32, vaModuleBase uint64) (string, error) {
	buf := make([]byte, 260) // MAX_PATH
	if !vmmPdbLoad(vmm.vmmHandle, pid, vaModuleBase, unsafe.Pointer(&buf[0])) {
		return "", fmt.Errorf("PdbLoad failed for PID %d module base 0x%X", pid, vaModuleBase)
	}
	return ffi.ByteSliceToString(buf), nil
}

// PdbSymbolName resolves a symbol name from a virtual address or offset
// within the given module. Also returns the displacement from the symbol start.
func (vmm *Vmm) PdbSymbolName(module string, addressOrOffset uint64) (string, uint32, error) {
	buf := make([]byte, 260) // MAX_PATH
	var displacement uint32
	if !vmmPdbSymbolName(vmm.vmmHandle, module, addressOrOffset, unsafe.Pointer(&buf[0]), &displacement) {
		return "", 0, fmt.Errorf("PdbSymbolName failed for module %q address 0x%X", module, addressOrOffset)
	}
	return ffi.ByteSliceToString(buf), displacement, nil
}

// PdbSymbolAddress returns the virtual address of a symbol in the given module.
func (vmm *Vmm) PdbSymbolAddress(module string, symbolName string) (uint64, error) {
	var va uint64
	if !vmmPdbSymbolAddress(vmm.vmmHandle, module, symbolName, &va) {
		return 0, fmt.Errorf("PdbSymbolAddress failed for module %q symbol %q", module, symbolName)
	}
	return va, nil
}

// PdbTypeSize returns the byte size of a named type in the given module.
func (vmm *Vmm) PdbTypeSize(module string, typeName string) (uint32, error) {
	var size uint32
	if !vmmPdbTypeSize(vmm.vmmHandle, module, typeName, &size) {
		return 0, fmt.Errorf("PdbTypeSize failed for module %q type %q", module, typeName)
	}
	return size, nil
}

// PdbTypeChildOffset returns the byte offset of a child field within a struct type.
func (vmm *Vmm) PdbTypeChildOffset(module string, typeName string, childName string) (uint32, error) {
	var offset uint32
	if !vmmPdbTypeChildOffset(vmm.vmmHandle, module, typeName, childName, &offset) {
		return 0, fmt.Errorf("PdbTypeChildOffset failed for module %q type %q field %q", module, typeName, childName)
	}
	return offset, nil
}
