package memprocfs

import (
	"bytes"
	"fmt"
	"unsafe"
)

func cString(ptr unsafe.Pointer, size int) string {
	bytesArr := (*[1 << 20]byte)(ptr)[:size:size] // max 1 MB safety
	last := bytes.IndexByte(bytesArr, 0)
	if last == -1 {
		last = size
	}
	s1 := string(bytesArr[:last])

	s2 := unsafe.String((*byte)(ptr), size)

	if s1 != s2 {
		panic(fmt.Sprintf("%s vs %s", s1, s2))
	}
	return s1
}

func boolToInt(b bool) int {
	var i int
	if b {
		i = 1
	} else {
		i = 0
	}
	return i
}

func multiString(data []byte) []string {
	var result []string
	parts := bytes.Split(data, []byte{0})

	for _, part := range parts {
		if len(part) > 0 {
			result = append(result, string(part))
		}
	}
	return result
}

func cArray[T any](base unsafe.Pointer, count int) []*T {
	size := unsafe.Sizeof(*new(T))
	result := make([]*T, count)
	for i := 0; i < count; i++ {
		offset := uintptr(i) * size
		result[i] = (*T)(unsafe.Pointer(uintptr(base) + offset))
	}
	return result
}

func afterDWORD(ptr unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(uintptr(ptr) + unsafe.Sizeof(uint32(0)))
}

func afterField(base unsafe.Pointer, fieldOffset uintptr, fieldSize uintptr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(base) + fieldOffset + fieldSize)
}

/**
todo: VMMDLL_Log
*/
