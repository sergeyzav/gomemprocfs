package memprocfs

import "unsafe"

// UserEntry represents a single user entry.
type UserEntry struct {
	Text      string
	VaRegHive uint64
	SID       string
}

// UserList contains a list of system users.
type UserList struct {
	Version uint32
	Count   uint32
	Entries []UserEntry
}

// userEntryInternal mirrors the C struct VMMDLL_MAP_USERENTRY.
type userEntryInternal struct {
	_FutureUse1 [2]uint32
	UszText     uintptr
	VaRegHive   uint64
	UszSID      uintptr
	_FutureUse2 [2]uint32
}

// userListInternal mirrors the C struct VMMDLL_MAP_USER.
type userListInternal struct {
	DwVersion   uint32
	_           [5]uint32
	PbMultiText uintptr
	CbMultiText uint32
	CMap        uint32
	// FAM entries follow
}

// GetUserList retrieves the list of users from the system.
func (vmm *Vmm) GetUserList() (*UserList, error) {
	var pUserMap *userListInternal
	if !vmmMapGetUsersU(vmm.vmmHandle, &pUserMap) {
		return nil, nil
	}
	if pUserMap == nil {
		return nil, nil
	}
	defer vmm.free(uintptr(unsafe.Pointer(pUserMap)))

	if pUserMap.CMap == 0 {
		return &UserList{Version: pUserMap.DwVersion}, nil
	}

	entriesInternal := FAM[userListInternal, userEntryInternal](pUserMap, int(pUserMap.CMap))
	entries := make([]UserEntry, pUserMap.CMap)
	for i, e := range entriesInternal {
		entries[i] = UserEntry{
			Text:      cStringToGo(e.UszText),
			VaRegHive: e.VaRegHive,
			SID:       cStringToGo(e.UszSID),
		}
	}

	return &UserList{
		Version: pUserMap.DwVersion,
		Count:   pUserMap.CMap,
		Entries: entries,
	}, nil
}
