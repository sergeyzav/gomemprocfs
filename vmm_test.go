package memprocfs

import (
	"os"
	"testing"
)

// setupVmm is a helper function to initialize the Vmm instance for tests.
// It reads environment variables, initializes the Vmm, and handles errors/skips.
// It returns the Vmm instance, and the caller is responsible for closing it.
func setupVmm(t *testing.T) *Vmm {
	t.Helper()

	dllPath := os.Getenv("VMM_DLL_PATH")
	memdumpPath := os.Getenv("MEMDUMP_PATH")

	if dllPath == "" || memdumpPath == "" {
		t.Skip("Skipping test: VMM_DLL_PATH and/or MEMDUMP_PATH environment variables not set")
	}

	vmm, err := NewVmm(
		dllPath,
		WithDevice(memdumpPath),
		WithWaitInitialize(),
		WithVerbose(),
		WithPrintf(),
	)
	if err != nil {
		t.Fatalf("Failed to initialize Vmm: %v", err)
	}
	return vmm
}
