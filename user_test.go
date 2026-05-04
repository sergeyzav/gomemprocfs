package memprocfs

import "testing"

func TestGetUserList(t *testing.T) {
	vmm := setupVmm(t)
	defer vmm.Close()

	users, err := vmm.GetUserList()
	if err != nil {
		t.Fatalf("GetUserList() failed: %v", err)
	}
	if users == nil {
		t.Fatalf("GetUserList() returned nil users object")
	}
	if users.Count == 0 {
		t.Logf("Expected non-empty user list, but got Count = 0. This can happen on minimal dumps. Skipping user count check.")
	} else {
		t.Logf("Found %d users", users.Count)
		for _, u := range users.Entries {
			t.Logf("  User: %s  SID: %s  RegHive: 0x%X", u.Text, u.SID, u.VaRegHive)
		}
	}
}
