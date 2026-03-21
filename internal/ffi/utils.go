package ffi

import (
	"strings"
	"unsafe"
)

// FAM accesses a Flexible Array Member that immediately follows struct P in memory.
func FAM[P, T any](baseStruct *P, count int) []T {
	headerSize := unsafe.Sizeof(*baseStruct)
	sliceStart := uintptr(unsafe.Pointer(baseStruct)) + headerSize
	return unsafe.Slice((*T)(unsafe.Pointer(sliceStart)), count)
}

// CStringToGo converts a null-terminated C string pointer to a Go string.
func CStringToGo(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	var length int
	for *(*byte)(unsafe.Pointer(ptr + uintptr(length))) != 0 {
		length++
	}
	return string(unsafe.Slice((*byte)(unsafe.Pointer(ptr)), length))
}

// ByteSliceToString converts a null-padded byte slice to a Go string.
func ByteSliceToString(b []byte) string {
	return strings.TrimRight(string(b), "\x00")
}
