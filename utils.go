package memprocfs

import (
	"unsafe"
)

// FAM is a helper function to access Flexible Array Members.
func FAM[P, T any](baseStruct *P, count int) []T {
	// This function assumes that the FAM immediately follows the struct P.
	headerSize := unsafe.Sizeof(*baseStruct)
	sliceStart := uintptr(unsafe.Pointer(baseStruct)) + headerSize
	return unsafe.Slice((*T)(unsafe.Pointer(sliceStart)), count)
}

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
