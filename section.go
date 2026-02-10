package memprocfs

import "unsafe"

// ImageSectionHeader mirrors the Windows IMAGE_SECTION_HEADER structure.
type ImageSectionHeader struct {
	Name                 [8]byte
	VirtualSize          uint32 // Also PhysicalAddress
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

// GetProcessSections retrieves the sections of a module in a process.
func (vmm *Vmm) GetProcessSections(pid uint32, moduleName string) ([]ImageSectionHeader, error) {
	var count uint32
	// First call to get the number of sections.
	// Note: According to docs, we pass NULL for buffer and 0 for size to get count in pcSections.
	success := vmmProcessGetSectionsU(vmm.vmmHandle, pid, moduleName, nil, 0, &count)
	if !success {
		// It might fail if module not found, or other errors.
		return nil, nil
	}

	if count == 0 {
		return []ImageSectionHeader{}, nil
	}

	sections := make([]ImageSectionHeader, count)
	// Second call to fill the buffer.
	success = vmmProcessGetSectionsU(vmm.vmmHandle, pid, moduleName, unsafe.Pointer(&sections[0]), count, &count)
	if !success {
		return nil, nil
	}

	return sections, nil
}
