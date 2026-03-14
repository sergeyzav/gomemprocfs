package memprocfs

import (
	"fmt"
	"unsafe"
)

// VmGetVmmHandle returns a full VMM_HANDLE for the given virtual machine,
// allowing all standard Vmm methods to be used directly against the VM guest.
// The returned *Vmm must be closed by calling Close() when no longer needed.
// Physical-memory-only VMs are not supported.
func (vmm *Vmm) VmGetVmmHandle(vm *VmEntry) (*Vmm, error) {
	h := vmmVmGetVmmHandle(vmm.vmmHandle, vm.Handle)
	if h == 0 {
		return nil, fmt.Errorf("VmGetVmmHandle: failed (physical-only VM?)")
	}
	return &Vmm{libHandle: vmm.libHandle, vmmHandle: h}, nil
}

// VmScatterInitialize returns a ScatterHandle for efficient scatter-read/write
// of guest physical address (GPA) memory inside a virtual machine.
// The handle must be closed with Close() when no longer needed.
func (vmm *Vmm) VmScatterInitialize(vm *VmEntry) (*ScatterHandle, error) {
	h := vmmVmScatterInitialize(vmm.vmmHandle, vm.Handle)
	if h == 0 {
		return nil, fmt.Errorf("VmScatterInitialize: failed")
	}
	return &ScatterHandle{handle: h}, nil
}

// VmMemRead reads cb bytes from guest physical address qwGPA inside the VM.
func (vmm *Vmm) VmMemRead(vm *VmEntry, qwGPA uint64, cb uint32) ([]byte, error) {
	buf := make([]byte, cb)
	if !vmmVmMemRead(vmm.vmmHandle, vm.Handle, qwGPA, unsafe.Pointer(&buf[0]), cb) {
		return nil, fmt.Errorf("VmMemRead: failed at GPA 0x%x", qwGPA)
	}
	return buf, nil
}

// VmMemWrite writes data to guest physical address qwGPA inside the VM.
func (vmm *Vmm) VmMemWrite(vm *VmEntry, qwGPA uint64, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if !vmmVmMemWrite(vmm.vmmHandle, vm.Handle, qwGPA, unsafe.Pointer(&data[0]), uint32(len(data))) {
		return fmt.Errorf("VmMemWrite: failed at GPA 0x%x", qwGPA)
	}
	return nil
}

// VmMemTranslateGPA translates a VM guest physical address (GPA) to a host
// physical address (PA) and/or a virtual address (VA) in the host 'vmmem'
// process. Pass nil for outputs you do not need.
func (vmm *Vmm) VmMemTranslateGPA(vm *VmEntry, qwGPA uint64) (pa uint64, va uint64, err error) {
	if !vmmVmMemTranslateGPA(vmm.vmmHandle, vm.Handle, qwGPA, &pa, &va) {
		return 0, 0, fmt.Errorf("VmMemTranslateGPA: failed for GPA 0x%x", qwGPA)
	}
	return pa, va, nil
}
