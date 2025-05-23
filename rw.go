package memprocfs

/*
#include "vmmdll.h"
*/
import "C"
import (
	"errors"
	"unsafe"
)

// MemRead reads memory from the specified process
func (v *Vmm) MemRead(pid uint32, va uint64, size uint32) ([]byte, error) {
	buf := make([]byte, size)
	success := C.VMMDLL_MemRead(v.handle, C.DWORD(pid), C.ULONG64(va), (*C.BYTE)(unsafe.Pointer(&buf[0])), C.DWORD(size))
	if success == 0 {
		return nil, errors.New("failed to read memory")
	}

	return buf, nil
}

// MemReadEx reads memory with additional flags
func (v *Vmm) MemReadEx(pid uint32, va uint64, buffer []byte, flags VMMFlag) (uint32, error) {
	var bytesRead uint32
	size := uint32(len(buffer))
	success := C.VMMDLL_MemReadEx(v.handle, C.DWORD(pid), C.ULONG64(va),
		(*C.BYTE)(unsafe.Pointer(&buffer[0])), C.DWORD(size),
		(*C.DWORD)(unsafe.Pointer(&bytesRead)), C.ULONG64(flags))

	if success == 0 {
		return 0, errors.New("failed to read memory")
	}

	return bytesRead, nil
}

// MemWrite writes memory to the specified process
func (v *Vmm) MemWrite(pid uint32, va uint64, data []byte) error {
	success := C.VMMDLL_MemWrite(v.handle, C.DWORD(pid), C.ULONG64(va),
		(*C.BYTE)(unsafe.Pointer(&data[0])), C.DWORD(len(data)))
	if success == 0 {
		return errors.New("failed to write memory")
	}
	return nil
}

// MemVirt2Phys converts virtual address to physical address
func (v *Vmm) MemVirt2Phys(pid uint32, va uint64) (uint64, error) {
	var pa uint64
	success := C.VMMDLL_MemVirt2Phys(v.handle, C.DWORD(pid), C.ULONG64(va), (*C.ULONG64)(unsafe.Pointer(&pa)))
	if success == 0 {
		return 0, errors.New("failed to convert virtual address to physical")
	}
	return pa, nil
}

/*
todo
VMMDLL_MemReadScatter
VMMDLL_MemWriteScatter
VMMDLL_MemReadPage
*/
