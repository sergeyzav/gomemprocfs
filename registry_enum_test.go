package memprocfs

import (
	"strings"
	"testing"
)

func TestGetRegistrySubKeys(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	keyPath := `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	keys, err := vmm.GetRegistrySubKeys(keyPath)
	if err != nil {
		t.Fatalf("GetRegistrySubKeys failed: %v", err)
	}

	t.Logf("Found %d sub-keys under %s", len(keys), keyPath)
	if len(keys) == 0 {
		t.Fatal("Expected at least one sub-key")
	}

	for i, k := range keys {
		t.Logf("#%d: name=%s lastWrite=0x%X", i, k.Name, k.LastWriteTime)
		if strings.ContainsRune(k.Name, 0) {
			t.Errorf("sub-key name %q contains NUL", k.Name)
		}
	}

	// The names must match the sub-key directories MemProcFS shows in its VFS.
	entries, err := vmm.VfsList(`\registry\` + keyPath)
	if err != nil {
		t.Fatalf("VfsList failed: %v", err)
	}
	dirs := map[string]bool{}
	for _, e := range entries {
		if e.IsDirectory {
			dirs[e.Name] = true
		}
	}
	for _, k := range keys {
		if !dirs[k.Name] {
			t.Errorf("sub-key %q is not a directory in the VFS", k.Name)
		}
	}
}

func TestGetRegistryValues(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	keyPath := `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	values, err := vmm.GetRegistryValues(keyPath)
	if err != nil {
		t.Fatalf("GetRegistryValues failed: %v", err)
	}

	t.Logf("Found %d values under %s", len(values), keyPath)
	if len(values) == 0 {
		t.Fatal("Expected at least one value")
	}

	for i, v := range values {
		t.Logf("#%d: name=%s type=%d len=%d", i, v.Name, v.Type, len(v.Data))
		if strings.ContainsRune(v.Name, 0) {
			t.Errorf("value name %q contains NUL", v.Name)
		}
	}

	// A returned name must round-trip through RegQueryValueEx.
	v := values[0]
	vType, data, err := vmm.RegQueryValueEx(keyPath + `\` + v.Name)
	if err != nil {
		t.Fatalf("RegQueryValueEx(%q) failed: %v", v.Name, err)
	}
	if vType != v.Type || string(data) != string(v.Data) {
		t.Errorf("RegQueryValueEx(%q) = type %d len %d, want type %d len %d", v.Name, vType, len(data), v.Type, len(v.Data))
	}
}

func TestRegQueryValueEx(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	valuePath := `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName`
	vType, data, err := vmm.RegQueryValueEx(valuePath)
	if err != nil {
		t.Fatalf("RegQueryValueEx failed: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("Expected non-empty data for ProductName")
	}

	// REG_SZ = 1
	if vType != 1 {
		t.Errorf("Expected REG_SZ (1), got type %d", vType)
	}

	// Data is UTF-16LE; just check it's non-empty and starts with "Windows"
	t.Logf("ProductName raw bytes (%d): type=%d", len(data), vType)

	// Convert UTF-16LE to string for display
	utf16 := make([]uint16, len(data)/2)
	for i := range utf16 {
		utf16[i] = uint16(data[2*i]) | uint16(data[2*i+1])<<8
	}
	// Trim null terminator
	var runes []rune
	for _, u := range utf16 {
		if u == 0 {
			break
		}
		runes = append(runes, rune(u))
	}
	name := string(runes)
	t.Logf("ProductName: %s", name)

	if !strings.HasPrefix(name, "Windows") {
		t.Errorf("Expected ProductName to start with 'Windows', got: %s", name)
	}
}
