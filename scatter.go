package memprocfs

import (
	"fmt"
	"unsafe"
)

// ScatterHandle is a handle for batched scatter read/write operations.
// Create via Vmm.ScatterInitialize; close with Close when done.
// A ScatterHandle is not safe for concurrent use.
type ScatterHandle struct {
	handle uintptr
}

// ScatterInitialize creates a new scatter handle for the given PID and flags.
// Use pid = PidPhysical to target physical memory.
// The caller must call Close() to release resources.
func (vmm *Vmm) ScatterInitialize(pid uint32, flags MemFlag) (*ScatterHandle, error) {
	h := vmmScatterInitialize(vmm.vmmHandle, pid, flags)
	if h == 0 {
		return nil, fmt.Errorf("%w: initialize for PID %d", ErrScatterFailed, pid)
	}
	return &ScatterHandle{handle: h}, nil
}

// Prepare registers a virtual address range for reading.
// After Execute or ExecuteRead, retrieve the data with Read or ReadInto.
func (h *ScatterHandle) Prepare(va uint64, cb uint32) error {
	if h.handle == 0 {
		return ErrClosed
	}
	if !vmmScatterPrepare(h.handle, va, cb) {
		return fmt.Errorf("%w: prepare va=0x%X cb=%d", ErrScatterFailed, va, cb)
	}
	return nil
}

// PrepareWrite registers a virtual address range for writing.
// Data is copied immediately, so the slice may be modified after this call.
// Writing takes place before reading during Execute.
// Note: requires a live/writable target.
func (h *ScatterHandle) PrepareWrite(va uint64, data []byte) error {
	if h.handle == 0 {
		return ErrClosed
	}
	if len(data) == 0 {
		return nil
	}
	if !vmmScatterPrepareWrite(h.handle, va, unsafe.Pointer(&data[0]), uint32(len(data))) {
		return fmt.Errorf("%w: prepare write va=0x%X", ErrScatterFailed, va)
	}
	return nil
}

// Execute writes all ranges registered with PrepareWrite, then reads all
// ranges registered with Prepare.
func (h *ScatterHandle) Execute() error {
	if h.handle == 0 {
		return ErrClosed
	}
	if !vmmScatterExecute(h.handle) {
		return fmt.Errorf("%w: execute", ErrScatterFailed)
	}
	return nil
}

// ExecuteRead reads all ranges registered with Prepare.
func (h *ScatterHandle) ExecuteRead() error {
	if h.handle == 0 {
		return ErrClosed
	}
	if !vmmScatterExecuteRead(h.handle) {
		return fmt.Errorf("%w: execute read", ErrScatterFailed)
	}
	return nil
}

// Read retrieves data for a range previously registered with Prepare.
// Must be called after Execute or ExecuteRead. It allocates a new slice on
// every call; use ReadInto to reuse a buffer.
func (h *ScatterHandle) Read(va uint64, cb uint32) ([]byte, error) {
	buf := make([]byte, cb)
	n, err := h.ReadInto(va, buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// ReadInto copies data for a range previously registered with Prepare into dst
// and returns the number of bytes read. len(dst) is the range size.
// Must be called after Execute or ExecuteRead. An empty dst reads nothing.
func (h *ScatterHandle) ReadInto(va uint64, dst []byte) (int, error) {
	if h.handle == 0 {
		return 0, ErrClosed
	}
	if len(dst) == 0 {
		return 0, nil
	}
	var cbRead uint32
	if !vmmScatterRead(h.handle, va, uint32(len(dst)), unsafe.Pointer(&dst[0]), &cbRead) {
		return 0, fmt.Errorf("%w: scatter read va=0x%X", ErrReadFailed, va)
	}
	return int(cbRead), nil
}

// Clear resets the handle for reuse in a subsequent scatter operation.
// Optionally change the target PID; pass 0 to keep the current PID.
func (h *ScatterHandle) Clear(pid uint32, flags MemFlag) error {
	if h.handle == 0 {
		return ErrClosed
	}
	if !vmmScatterClear(h.handle, pid, flags) {
		return fmt.Errorf("%w: clear", ErrScatterFailed)
	}
	return nil
}

// Close releases all resources associated with the scatter handle.
// It is safe to call Close more than once; later calls do nothing.
// Other methods return ErrClosed after Close.
func (h *ScatterHandle) Close() {
	if h.handle == 0 {
		return
	}
	vmmScatterCloseHandle(h.handle)
	h.handle = 0
}
