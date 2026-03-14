package memprocfs

import (
	"fmt"
	"unsafe"
)

func (vmm *Vmm) MemWrite(pid uint32, addr uint64, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if !vmmMemWrite(vmm.vmmHandle, pid, addr, unsafe.Pointer(&data[0]), uint32(len(data))) {
		return fmt.Errorf("failed to write memory to PID %d at address 0x%X", pid, addr)
	}
	return nil
}

func (vmm *Vmm) MemVirt2Phys(pid uint32, va uint64) (uint64, error) {
	var pa uint64
	if !vmmMemVirt2Phys(vmm.vmmHandle, pid, va, &pa) {
		return 0, fmt.Errorf("failed to translate virtual address 0x%X for PID %d", va, pid)
	}
	return pa, nil
}

func (vmm *Vmm) MemRead(pid uint32, addr uint64, size uint32) ([]byte, error) {
	buffer := make([]byte, size)
	success := vmmMemRead(vmm.vmmHandle, pid, addr, unsafe.Pointer(&buffer[0]), size)
	if !success {
		return nil, fmt.Errorf("failed to read memory from PID %d at address 0x%X", pid, addr)
	}
	return buffer, nil
}

// MemReadEx reads memory with optional flags and reports the actual bytes read.
// NB: may return success even if fewer than size bytes were read — check bytesRead.
func (vmm *Vmm) MemReadEx(pid uint32, addr uint64, size uint32, flags MemFlag) ([]byte, uint32, error) {
	buf := make([]byte, size)
	var cbRead uint32
	if !vmmMemReadEx(vmm.vmmHandle, pid, addr, unsafe.Pointer(&buf[0]), size, &cbRead, uint64(flags)) {
		return nil, 0, fmt.Errorf("failed to read memory (ex) from PID %d at 0x%X", pid, addr)
	}
	return buf[:cbRead], cbRead, nil
}

// MemReadPage reads exactly one 4096-byte memory page.
func (vmm *Vmm) MemReadPage(pid uint32, addr uint64) ([]byte, error) {
	buf := make([]byte, 4096)
	if !vmmMemReadPage(vmm.vmmHandle, pid, addr, unsafe.Pointer(&buf[0])) {
		return nil, fmt.Errorf("failed to read page from PID %d at 0x%X", pid, addr)
	}
	return buf, nil
}

// MemPrefetchPages preloads the given virtual addresses into the memory cache.
// Useful to batch-warm the cache before making multiple smaller reads.
func (vmm *Vmm) MemPrefetchPages(pid uint32, addresses []uint64) error {
	if len(addresses) == 0 {
		return nil
	}
	if !vmmMemPrefetchPages(vmm.vmmHandle, pid, unsafe.Pointer(&addresses[0]), uint32(len(addresses))) {
		return fmt.Errorf("failed to prefetch pages for PID %d", pid)
	}
	return nil
}
