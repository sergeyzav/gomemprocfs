package memprocfs

import (
	"fmt"
	"unsafe"
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

// RegistryKey represents a single registry sub-key entry.
type RegistryKey struct {
	Name          string
	LastWriteTime uint64 // FILETIME: 100-nanosecond intervals since Jan 1, 1601
}

// RegistryValue represents a single registry value entry.
type RegistryValue struct {
	Name string
	Type uint32
	Data []byte
}

// GetRegistrySubKeys enumerates all sub-keys of the given registry key path.
// keyPath examples: "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
func (vmm *Vmm) GetRegistrySubKeys(keyPath string) ([]RegistryKey, error) {
	const nameBufSize = 512
	var keys []RegistryKey
	for index := uint32(0); ; index++ {
		nameBuf := make([]byte, nameBufSize)
		cchName := uint32(nameBufSize)
		var lastWrite uint64
		ok := vmmWinRegEnumKeyExU(vmm.vmmHandle, keyPath, index,
			unsafe.Pointer(&nameBuf[0]), &cchName, &lastWrite)
		if !ok {
			break
		}
		keys = append(keys, RegistryKey{
			Name:          string(nameBuf[:cchName]),
			LastWriteTime: lastWrite,
		})
	}
	return keys, nil
}

// GetRegistryValues enumerates all values of the given registry key path.
func (vmm *Vmm) GetRegistryValues(keyPath string) ([]RegistryValue, error) {
	const nameBufSize = 512
	var values []RegistryValue
	for index := uint32(0); ; index++ {
		nameBuf := make([]byte, nameBufSize)
		cchName := uint32(nameBufSize)
		var vType uint32
		var cbData uint32
		// First call: nil data to get required data size.
		ok := vmmWinRegEnumValueU(vmm.vmmHandle, keyPath, index,
			unsafe.Pointer(&nameBuf[0]), &cchName, &vType, nil, &cbData)
		if !ok {
			break
		}
		var data []byte
		if cbData > 0 {
			data = make([]byte, cbData)
			cchName2 := uint32(nameBufSize)
			vmmWinRegEnumValueU(vmm.vmmHandle, keyPath, index,
				unsafe.Pointer(&nameBuf[0]), &cchName2, &vType,
				unsafe.Pointer(&data[0]), &cbData)
			data = data[:cbData]
		}
		values = append(values, RegistryValue{
			Name: string(nameBuf[:cchName]),
			Type: vType,
			Data: data,
		})
	}
	return values, nil
}

// RegQueryValueEx queries a specific registry value by full path.
// keyValuePath example: "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName"
func (vmm *Vmm) RegQueryValueEx(keyValuePath string) (uint32, []byte, error) {
	var vType uint32
	var cbData uint32
	// First call: nil data to get required size.
	vmmWinRegQueryValueExU(vmm.vmmHandle, keyValuePath, &vType, nil, &cbData)
	if cbData == 0 {
		return vType, nil, nil
	}
	data := make([]byte, cbData)
	if !vmmWinRegQueryValueExU(vmm.vmmHandle, keyValuePath, &vType, unsafe.Pointer(&data[0]), &cbData) {
		return 0, nil, fmt.Errorf("failed to query registry value: %s", keyValuePath)
	}
	return vType, data[:cbData], nil
}
