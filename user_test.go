package memprocfs

import "testing"

func TestGetUserList(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	users, err := vmm.GetUserList()
	if err != nil {
		t.Fatalf("GetUserList() failed: %v", err)
	}
	if users == nil || users.Count == 0 {
		t.Fatal("Expected non-empty user list")
	}
	t.Logf("Found %d users", users.Count)
	for _, u := range users.Entries {
		t.Logf("  User: %s  SID: %s  RegHive: 0x%X", u.Text, u.SID, u.VaRegHive)
	}
}
