//go:build !windows

package ffi

import "github.com/ebitengine/purego"

// OpenLibrary loads the shared library at the given path.
func OpenLibrary(name string) (uintptr, error) {
	return purego.Dlopen(name, purego.RTLD_NOW|purego.RTLD_GLOBAL)
}
