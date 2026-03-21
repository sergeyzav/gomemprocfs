package memprocfs

import (
	"strings"
	"testing"
)

func TestVfsList(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	// Root MemProcFS VFS uses backslash; VfsList converts "/" → "\" automatically.
	entries, err := vmm.VfsList(`\`)
	if err != nil {
		t.Fatalf("VfsList root failed: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one entry in root")
	}
	t.Logf("Root entries (%d):", len(entries))
	for _, e := range entries {
		kind := "file"
		if e.IsDirectory {
			kind = "dir"
		}
		t.Logf("  [%s] %s (size=%d)", kind, e.Name, e.Size)
	}

	found := map[string]bool{}
	for _, e := range entries {
		found[strings.ToLower(e.Name)] = true
	}
	if !found["sys"] {
		t.Errorf("expected 'sys' directory in root listing")
	}
}

func TestVfsListSubdir(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	// Both forward and backslash should work via automatic conversion.
	entries, err := vmm.VfsList("/sys")
	if err != nil {
		t.Fatalf("VfsList(\"/sys\") failed: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected entries in /sys")
	}
	t.Logf("/sys entries (%d):", len(entries))
	for _, e := range entries {
		kind := "file"
		if e.IsDirectory {
			kind = "dir"
		}
		t.Logf("  [%s] %s (size=%d)", kind, e.Name, e.Size)
	}
}

func TestVfsRead(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	// \sys\version.txt always contains the OS version string (e.g. "10.0.19041").
	data, err := vmm.VfsRead(`\sys\version.txt`, 64, 0)
	if err != nil {
		t.Fatalf("VfsRead failed: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty data from version.txt")
	}
	content := strings.TrimSpace(string(data))
	t.Logf("\\sys\\version.txt: %q", content)

	if !strings.Contains(content, ".") {
		t.Errorf("expected a version string like '10.0.19041', got: %q", content)
	}
}

func TestVfsReadOffset(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	all, err := vmm.VfsRead(`\sys\sysinfo\sysinfo.txt`, 512, 0)
	if err != nil || len(all) < 4 {
		t.Skipf("VfsRead base failed: %v", err)
	}

	// Read at offset 10 — should match all[10:10+len(partial)].
	partial, err := vmm.VfsRead(`\sys\sysinfo\sysinfo.txt`, uint32(len(all)-10), 10)
	if err != nil {
		t.Fatalf("VfsRead with offset failed: %v", err)
	}
	if string(partial) != string(all[10:10+len(partial)]) {
		t.Errorf("offset read mismatch")
	}
	t.Logf("offset read: %d bytes match ✓", len(partial))
}
