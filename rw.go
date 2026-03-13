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

func (vmm *Vmm) MemRead(pid uint32, addr uint64, size uint32) ([]byte, error) {
	buffer := make([]byte, size)
	success := vmmMemRead(vmm.vmmHandle, pid, addr, unsafe.Pointer(&buffer[0]), size)
	if !success {
		return nil, fmt.Errorf("failed to read memory from PID %d at address 0x%X", pid, addr)
	}
	return buffer, nil
}
