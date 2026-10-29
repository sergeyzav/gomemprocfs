package memprocfs

import (
	"fmt"
	"unsafe"

	"github.com/sergeyzav/gomemprocfs/internal/ffi"
)

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
	_         [2]uint32 // FutureUse1
	UszText   uintptr
	VaRegHive uint64
	UszSID    uintptr
	_         [2]uint32 // FutureUse2
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

// GetUserList retrieves the list of user accounts found in the memory image.
// Each entry includes the account name (text), registry hive address, and SID.
func (vmm *Vmm) GetUserList() (*UserList, error) {
	var pUserMap *userListInternal
	if !vmmMapGetUsersU(vmm.vmmHandle, &pUserMap) || pUserMap == nil {
		return nil, fmt.Errorf("VMMDLL_Map_GetUsersU failed")
	}
	defer vmm.free(uintptr(unsafe.Pointer(pUserMap)))

	if pUserMap.CMap == 0 {
		return &UserList{Version: pUserMap.DwVersion}, nil
	}

	entriesInternal := ffi.FAM[userListInternal, userEntryInternal](pUserMap, int(pUserMap.CMap))
	entries := make([]UserEntry, pUserMap.CMap)
	for i, e := range entriesInternal {
		entries[i] = UserEntry{
			Text:      ffi.CStringToGo(e.UszText),
			VaRegHive: e.VaRegHive,
			SID:       ffi.CStringToGo(e.UszSID),
		}
	}

	return &UserList{
		Version: pUserMap.DwVersion,
		Count:   pUserMap.CMap,
		Entries: entries,
	}, nil
}
