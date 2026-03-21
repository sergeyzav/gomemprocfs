package memprocfs

import (
	"testing"
)

func TestGetThreadCallstack(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	// 1. Get process (e.g., explorer.exe or svchost.exe)
	pid, err := vmm.GetPidByName("explorer.exe")
	if err != nil {
		// Try another common process if explorer is not found (e.g. in minimal dumps)
		pid, err = vmm.GetPidByName("svchost.exe")
		if err != nil {
			t.Skip("Could not find explorer.exe or svchost.exe to test thread callstack")
		}
	}

	t.Logf("Testing with PID: %d", pid)

	// 2. Get threads
	threads, err := vmm.GetThreadList(pid)
	if err != nil {
		t.Fatalf("Failed to get thread list: %v", err)
	}

	if threads == nil || len(threads.Threads) == 0 {
		t.Skip("No threads found for process")
	}

	// 3. Get callstack for the first thread
	tid := threads.Threads[0].TID
	t.Logf("Testing callstack for TID: %d", tid)

	callstack, err := vmm.GetThreadCallstack(pid, tid)
	if err != nil {
		t.Fatalf("Failed to get thread callstack: %v", err)
	}

	if callstack == nil {
		t.Log("Callstack is nil (might be empty or failed silently)")
		return
	}

	t.Logf("Callstack entries: %d", len(callstack.Entries))

	if len(callstack.Entries) > 0 {
		for i, entry := range callstack.Entries {
			t.Logf("#%d: 0x%x %s!%s (Disp: %d)", i, entry.RetAddr, entry.ModuleName, entry.FunctionName, entry.Displacement)
			if i >= 5 {
				break // Print only first 5 frames
			}
		}
	} else {
		t.Log("Callstack is empty")
	}
}
