//go:build windows

package ffi

import "golang.org/x/sys/windows"

// OpenLibrary loads the shared library at the given path.
func OpenLibrary(name string) (uintptr, error) {
	dll := windows.NewLazyDLL(name)
	if err := dll.Load(); err != nil {
		return 0, err
	}
	return dll.Handle(), nil
}
