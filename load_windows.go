//go:build windows

package memprocfs

import "golang.org/x/sys/windows"

func openLibrary(name string) (uintptr, error) {
	handle, err := windows.NewLazyDLL(name).Load()
	return uintptr(handle), err
}
