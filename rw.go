package memprocfs

/*
#include "vmmdll.h"
*/
import "C"
import (
	"errors"
	"unsafe"
)

// FLAG used to supress the default read cache in calls to VMM_MemReadEx()
// which will lead to the read being fetched from the target system always.
// Cached page tables (used for translating virtual2physical) are still used.
type VMMFlag uint32

const (
	// FlagNoCache suppresses the default read cache in calls to VMM_MemReadEx.
	// This will lead to the read being fetched from the target system always.
	// Cached page tables (used for translating virtual2physical) are still used.
	FlagNoCache VMMFlag = 0x0001

	// FlagZeroPadOnFail zero pads failed physical memory reads and reports success if read within range of physical memory.
	FlagZeroPadOnFail VMMFlag = 0x0002

	// FlagForceCacheRead forces use of cache - fail non-cached pages.
	// Only valid for reads, invalid with FlagNoCache/FlagZeroPadOnFail.
	FlagForceCacheRead VMMFlag = 0x0008

	// FlagNoPaging does not try to retrieve memory from paged out memory from pagefile/compressed (even if possible).
	FlagNoPaging VMMFlag = 0x0010

	// FlagNoPagingIO does not try to retrieve memory from paged out memory if read would incur additional I/O (even if possible).
	FlagNoPagingIO VMMFlag = 0x0020

	// FlagNoCachePut does not write back to the data cache upon successful read from memory acquisition device.
	FlagNoCachePut VMMFlag = 0x0100

	// FlagCacheRecentOnly only fetches from the most recent active cache region when reading.
	FlagCacheRecentOnly VMMFlag = 0x0200

	// FlagNoPredictiveRead is deprecated/unused.
	FlagNoPredictiveRead VMMFlag = 0x0400

	// FlagForceCacheReadDisable disables/overrides any use of FlagForceCacheRead.
	// Only recommended for local files. Improves forensic artifact order.
	FlagForceCacheReadDisable VMMFlag = 0x0800

	// FlagScatterPrepareExNoMemZero does not zero out the memory buffer when preparing a scatter read.
	FlagScatterPrepareExNoMemZero VMMFlag = 0x1000

	// FlagNoMemCallback does not call user-set memory callback functions when reading memory (even if active).
	FlagNoMemCallback VMMFlag = 0x2000

	// FlagScatterForcePageRead forces page-sized reads when using scatter functionality.
	FlagScatterForcePageRead VMMFlag = 0x4000
)

// MemRead reads memory from the specified process
func (v *Vmm) MemRead(pid uint32, va uint64, buffer []byte) error {
	success := C.VMMDLL_MemRead(v.handle, C.DWORD(pid), C.ULONG64(va), (*C.BYTE)(unsafe.Pointer(&buffer[0])), C.DWORD(len(buffer)))
	if success == 0 {
		return errors.New("failed to read memory")
	}

	return nil
}

// MemReadEx reads memory with additional flags
func (v *Vmm) MemReadEx(pid uint32, va uint64, buffer []byte, flags ...VMMFlag) (uint32, error) {
	var flagsValue uint32
	for _, flag := range flags {
		flagsValue |= uint32(flag)
	}

	var bytesRead uint32
	success := C.VMMDLL_MemReadEx(v.handle, C.DWORD(pid), C.ULONG64(va),
		(*C.BYTE)(unsafe.Pointer(&buffer[0])), C.DWORD(len(buffer)),
		(*C.DWORD)(unsafe.Pointer(&bytesRead)), C.ULONG64(flagsValue))

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
