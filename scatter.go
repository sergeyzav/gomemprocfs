package memprocfs

import (
	"fmt"
	"unsafe"
)

// ScatterHandle is a handle for batched scatter read/write operations.
// Create via Vmm.ScatterInitialize; close with Close when done.
type ScatterHandle struct {
	handle uintptr
}

// ScatterInitialize creates a new scatter handle for the given PID and flags.
// Use pid = 0xFFFFFFFF to target physical memory.
// The caller must call Close() to release resources.
func (vmm *Vmm) ScatterInitialize(pid uint32, flags MemFlag) (*ScatterHandle, error) {
	h := vmmScatterInitialize(vmm.vmmHandle, pid, uint32(flags))
	if h == 0 {
		return nil, fmt.Errorf("failed to initialize scatter handle for PID %d", pid)
	}
	return &ScatterHandle{handle: h}, nil
}

// Prepare registers a virtual address range for reading.
// After Execute or ExecuteRead, retrieve the data with Read.
func (h *ScatterHandle) Prepare(va uint64, cb uint32) error {
	if !vmmScatterPrepare(h.handle, va, cb) {
		return fmt.Errorf("scatter prepare failed: va=0x%X cb=%d", va, cb)
	}
	return nil
}

// PrepareWrite registers a virtual address range for writing.
// Data is copied immediately, so the slice may be modified after this call.
// Writing takes place before reading during Execute.
// Note: requires a live/writable target.
func (h *ScatterHandle) PrepareWrite(va uint64, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if !vmmScatterPrepareWrite(h.handle, va, unsafe.Pointer(&data[0]), uint32(len(data))) {
		return fmt.Errorf("scatter prepare write failed: va=0x%X", va)
	}
	return nil
}

// Execute writes all ranges registered with PrepareWrite, then reads all
// ranges registered with Prepare.
func (h *ScatterHandle) Execute() error {
	if !vmmScatterExecute(h.handle) {
		return fmt.Errorf("scatter execute failed")
	}
	return nil
}

// ExecuteRead reads all ranges registered with Prepare.
func (h *ScatterHandle) ExecuteRead() error {
	if !vmmScatterExecuteRead(h.handle) {
		return fmt.Errorf("scatter execute read failed")
	}
	return nil
}

// Read retrieves data for a range previously registered with Prepare.
// Must be called after Execute or ExecuteRead.
func (h *ScatterHandle) Read(va uint64, cb uint32) ([]byte, error) {
	buf := make([]byte, cb)
	var cbRead uint32
	if !vmmScatterRead(h.handle, va, cb, unsafe.Pointer(&buf[0]), &cbRead) {
		return nil, fmt.Errorf("scatter read failed: va=0x%X", va)
	}
	return buf[:cbRead], nil
}

// Clear resets the handle for reuse in a subsequent scatter operation.
// Optionally change the target PID; pass 0 to keep the current PID.
func (h *ScatterHandle) Clear(pid uint32, flags MemFlag) error {
	if !vmmScatterClear(h.handle, pid, uint32(flags)) {
		return fmt.Errorf("scatter clear failed")
	}
	return nil
}

// Close releases all resources associated with the scatter handle.
func (h *ScatterHandle) Close() {
	vmmScatterCloseHandle(h.handle)
}
