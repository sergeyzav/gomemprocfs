//go:build windows

package ffi

import "golang.org/x/sys/windows"

// OpenLibrary loads the shared library at the given path.
func OpenLibrary(name string) (uintptr, error) {
	handle, err := windows.NewLazyDLL(name).Load()
	return uintptr(handle), err
}
