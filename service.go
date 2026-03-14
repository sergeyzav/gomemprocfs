package memprocfs

import (
	"fmt"
	"unsafe"
)

// ServiceStatus mirrors the Windows SERVICE_STATUS structure.
type ServiceStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

// ServiceEntry represents a single service entry.
type ServiceEntry struct {
	Object      uint64
	Ordinal     uint32
	StartType   uint32
	Status      ServiceStatus
	ServiceName string
	DisplayName string
	Path        string
	UserType    string
	UserAccount string
	ImagePath   string
	PID         uint32
}

// serviceEntryInternal mirrors the C struct VMMDLL_MAP_SERVICEENTRY.
type serviceEntryInternal struct {
	VaObj          uint64
	DwOrdinal      uint32
	DwStartType    uint32
	ServiceStatus  ServiceStatus
	_Padding       uint32 // Padding for alignment before pointers
	UszServiceName uintptr
	UszDisplayName uintptr
	UszPath        uintptr
	UszUserTp      uintptr
	UszUserAcct    uintptr
	UszImagePath   uintptr
	DwPID          uint32
	_FutureUse1    uint32
	_FutureUse2    uint64
}

// serviceListInternal mirrors the C struct VMMDLL_MAP_SERVICE.
type serviceListInternal struct {
	DwVersion   uint32
	_           [5]uint32 // Reserved
	PbMultiText uintptr
	CbMultiText uint32
	CMap        uint32
	// pMap (FAM) starts here
}

// ServiceList contains a list of services.
type ServiceList struct {
	Version   uint32
	Count     uint32
	MultiText string
	Entries   []ServiceEntry
}

// GetServiceList retrieves the list of services from the system.
func (vmm *Vmm) GetServiceList() (*ServiceList, error) {
	var pServiceMap *serviceListInternal
	success := vmmMapGetServicesU(vmm.vmmHandle, &pServiceMap)
	if !success {
		return nil, fmt.Errorf("GetServiceList: failed")
	}
	if pServiceMap == nil {
		return nil, fmt.Errorf("GetServiceList: nil map returned")
	}
	defer vmm.free(uintptr(unsafe.Pointer(pServiceMap)))

	if pServiceMap.CMap == 0 {
		return &ServiceList{
			Version:   pServiceMap.DwVersion,
			MultiText: string(unsafe.Slice((*byte)(unsafe.Pointer(pServiceMap.PbMultiText)), pServiceMap.CbMultiText)),
		}, nil
	}

	entriesInternal := FAM[serviceListInternal, serviceEntryInternal](pServiceMap, int(pServiceMap.CMap))

	entries := make([]ServiceEntry, pServiceMap.CMap)
	for i, entry := range entriesInternal {
		entries[i] = ServiceEntry{
			Object:      entry.VaObj,
			Ordinal:     entry.DwOrdinal,
			StartType:   entry.DwStartType,
			Status:      entry.ServiceStatus,
			ServiceName: cStringToGo(entry.UszServiceName),
			DisplayName: cStringToGo(entry.UszDisplayName),
			Path:        cStringToGo(entry.UszPath),
			UserType:    cStringToGo(entry.UszUserTp),
			UserAccount: cStringToGo(entry.UszUserAcct),
			ImagePath:   cStringToGo(entry.UszImagePath),
			PID:         entry.DwPID,
		}
	}

	return &ServiceList{
		Version:   pServiceMap.DwVersion,
		Count:     pServiceMap.CMap,
		MultiText: string(unsafe.Slice((*byte)(unsafe.Pointer(pServiceMap.PbMultiText)), pServiceMap.CbMultiText)),
		Entries:   entries,
	}, nil
}
