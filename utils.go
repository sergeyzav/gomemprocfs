package memprocfs

import "unsafe"

// cStringToGo converts a null-terminated C string to a Go string.
func cStringToGo(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	var length int
	for *(*byte)(unsafe.Pointer(ptr + uintptr(length))) != 0 {
		length++
	}
	return string(unsafe.Slice((*byte)(unsafe.Pointer(ptr)), length))
}
