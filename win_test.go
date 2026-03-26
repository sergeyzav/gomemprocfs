package memprocfs

import (
	"testing"
)

func TestGetIATThunkInfo(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	// Find a process that has a loaded IAT we can inspect.
	// Use the IAT map to locate a real pid/module/import triple.
	procs, err := vmm.GetProcessInfoAll()
	if err != nil || len(procs) == 0 {
		t.Skip("could not list processes")
	}

	// Walk processes until we find one whose IAT contains a usable entry.
	for _, p := range procs {
		if p.PID == 0 {
			continue
		}
		mods, err := vmm.GetModuleList(p.PID, ModuleFlagNone)
		if err != nil || mods == nil || len(mods.Modules) == 0 {
			continue
		}
		modName := mods.Modules[0].Name

		iat, err := vmm.GetIatList(p.PID, modName)
		if err != nil || iat == nil || len(iat.Entries) == 0 {
			continue
		}

		entry := iat.Entries[0]
		info, err := vmm.GetIATThunkInfo(p.PID, modName, entry.ModuleName, entry.FunctionName)
		if err != nil {
			t.Logf("PID %d %s: GetIATThunkInfo(%q, %q) => %v (skipping)", p.PID, modName, entry.ModuleName, entry.FunctionName, err)
			continue
		}

		t.Logf("PID %d %s imports %s!%s", p.PID, modName, entry.ModuleName, entry.FunctionName)
		t.Logf("  vaThunk=0x%X vaFunction=0x%X is32bit=%v", info.VaThunk, info.VaFunction, info.Is32Bit)
		if info.VaThunk == 0 {
			t.Error("expected non-zero VaThunk")
		}
		return // success — one entry is enough
	}

	t.Skip("no process with a queryable IAT entry found")
}
