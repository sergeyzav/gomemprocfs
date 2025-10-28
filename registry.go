package memprocfs

import (
	"fmt"
)

// RegistryHive represents a single registry hive.
type RegistryHive struct {
	BaseAddress uint64
	Name        string
	ShortName   string
	Path        string
}

// registryHiveInfoInternal mirrors the C struct VMMDLL_REGISTRY_HIVE_INFORMATION.
// Note: MAX_PATH is 260.
type registryHiveInfoInternal struct {
	Magic         uint64
	Version       uint16
	Size          uint16
	_             [0x34]byte
	VaCMHIVE      uint64
	VaHBASE_BLOCK uint64
	Length        uint32
	NameRaw       [128]byte
	NameShortRaw  [33]byte
	PathRaw       [260]byte
	_             [0x10]uint64
}

func (vmm *Vmm) GetRegistryHives() ([]RegistryHive, error) {
	var requiredHives uint32
	// First call to get the number of hives.
	success := vmmWinRegHiveList(vmm.vmmHandle, nil, 0, &requiredHives)
	if !success || requiredHives == 0 {
		return nil, fmt.Errorf("failed to get the required number of registry hives (required: %d, success: %v)", requiredHives, success)
	}

	hivesInternal := make([]registryHiveInfoInternal, requiredHives)
	var retrievedHives uint32
	// Second call to get the actual hive data.
	success = vmmWinRegHiveList(vmm.vmmHandle, &hivesInternal[0], requiredHives, &retrievedHives)
	if !success {
		return nil, fmt.Errorf("failed to retrieve registry hives on the second call")
	}

	result := make([]RegistryHive, retrievedHives)
	for i := 0; i < int(retrievedHives); i++ {
		result[i] = RegistryHive{
			BaseAddress: hivesInternal[i].VaCMHIVE,
			Name:        byteSliceToString(hivesInternal[i].NameRaw[:]),
			Path:        byteSliceToString(hivesInternal[i].PathRaw[:]),
			ShortName:   byteSliceToString(hivesInternal[i].NameShortRaw[:]),
		}
	}

	return result, nil
}
