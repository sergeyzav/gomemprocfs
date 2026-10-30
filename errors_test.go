package memprocfs

import (
	"errors"
	"testing"
)

// Zero-size reads must return early, before touching the native handle.
func TestZeroSizeReads(t *testing.T) {
	vmm := &Vmm{}

	data, err := vmm.MemRead(0, 0x1000, 0)
	if err != nil || len(data) != 0 {
		t.Errorf("MemRead size 0: got %v, %v; want empty, nil", data, err)
	}

	data, n, err := vmm.MemReadEx(0, 0x1000, 0, MemFlagNone)
	if err != nil || len(data) != 0 || n != 0 {
		t.Errorf("MemReadEx size 0: got %v, %d, %v; want empty, 0, nil", data, n, err)
	}
}

func TestScatterClosedHandle(t *testing.T) {
	h := &ScatterHandle{}
	h.Close() // closing an already-closed handle must not call into the library

	checks := map[string]error{
		"Prepare":      h.Prepare(0x1000, 8),
		"PrepareWrite": h.PrepareWrite(0x1000, []byte{1}),
		"Execute":      h.Execute(),
		"ExecuteRead":  h.ExecuteRead(),
		"Clear":        h.Clear(0, MemFlagNone),
	}
	_, checks["Read"] = h.Read(0x1000, 8)
	_, checks["ReadInto"] = h.ReadInto(0x1000, make([]byte, 8))

	for name, err := range checks {
		if !errors.Is(err, ErrClosed) {
			t.Errorf("%s on closed handle: got %v, want ErrClosed", name, err)
		}
	}
}
