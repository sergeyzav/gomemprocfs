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
	name := string(rune(0))
	var runes []rune
	for _, u := range utf16 {
		if u == 0 {
			break
		}
		runes = append(runes, rune(u))
	}
	name = string(runes)
	t.Logf("ProductName: %s", name)

	if !strings.HasPrefix(name, "Windows") {
		t.Errorf("Expected ProductName to start with 'Windows', got: %s", name)
	}
}
