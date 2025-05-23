package memprocfs

import "errors"

// Map structure versions
const (
	MapPTEVersion             = 2
	MapVADVersion             = 6
	MapVADExVersion           = 4
	MapModuleVersion          = 6
	MapUnloadedModuleVersion  = 2
	MapEATVersion             = 3
	MapIATVersion             = 2
	MapHeapVersion            = 4
	MapHeapAllocVersion       = 1
	MapThreadVersion          = 4
	MapThreadCallstackVersion = 1
	MapHandleVersion          = 3
	MapPoolVersion            = 2
	MapKObjectVersion         = 1
	MapKDriverVersion         = 1
	MapKDeviceVersion         = 1
	MapNetVersion             = 3
	MapPhysMemVersion         = 2
	MapUserVersion            = 2
	MapVMVersion              = 2
	MapServiceVersion         = 3
)

var (
	ErrUnsupportedPTEVersion             = errors.New("unsupported PTE version")
	ErrUnsupportedVADVersion             = errors.New("unsupported VAD version")
	ErrUnsupportedVADExVersion           = errors.New("unsupported VADEx version")
	ErrUnsupportedModuleVersion          = errors.New("unsupported Module version")
	ErrUnsupportedUnloadedModuleVersion  = errors.New("unsupported UnloadedModule version")
	ErrUnsupportedEATVersion             = errors.New("unsupported EAT version")
	ErrUnsupportedIATVersion             = errors.New("unsupported IAT version")
	ErrUnsupportedHeapVersion            = errors.New("unsupported Heap version")
	ErrUnsupportedHeapAllocVersion       = errors.New("unsupported HeapAlloc version")
	ErrUnsupportedThreadVersion          = errors.New("unsupported Thread version")
	ErrUnsupportedThreadCallstackVersion = errors.New("unsupported ThreadCallstack version")
	ErrUnsupportedHandleVersion          = errors.New("unsupported Handle version")
	ErrUnsupportedPoolVersion            = errors.New("unsupported Pool version")
	ErrUnsupportedKObjectVersion         = errors.New("unsupported KObject version")
	ErrUnsupportedKDriverVersion         = errors.New("unsupported KDriver version")
	ErrUnsupportedKDeviceVersion         = errors.New("unsupported KDevice version")
	ErrUnsupportedNetVersion             = errors.New("unsupported Net version")
	ErrUnsupportedPhysMemVersion         = errors.New("unsupported PhysMem version")
	ErrUnsupportedUserVersion            = errors.New("unsupported User version")
	ErrUnsupportedVMVersion              = errors.New("unsupported VM version")
	ErrUnsupportedServiceVersion         = errors.New("unsupported Service version")
)
