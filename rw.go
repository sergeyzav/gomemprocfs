package memprocfs

import (
	"fmt"
	"unsafe"
)

func (vmm *Vmm) MemRead(pid uint32, addr uint64, size uint32) ([]byte, error) {
	buffer := make([]byte, size)
	success := vmmMemRead(vmm.vmmHandle, pid, addr, unsafe.Pointer(&buffer[0]), size)
	if !success {
		return nil, fmt.Errorf("failed to read memory from PID %d at address 0x%X", pid, addr)
	}
	return buffer, nil
}
