package memprocfs

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/sergeyzav/memprocfs/internal/ffi"
)

// vfsPath normalises a path for VfsListBlobU which requires backslash separators.
func vfsPath(path string) string {
	return strings.ReplaceAll(path, "/", `\`)
}

// VfsEntry represents a single file or directory in the MemProcFS virtual filesystem.
type VfsEntry struct {
	Name           string
	Size           uint64 // file size in bytes; ^uint64(0) means directory
	IsDirectory    bool
	CreationTime   uint64 // FILETIME
	LastAccessTime uint64 // FILETIME
	LastWriteTime  uint64 // FILETIME
}

// vfsFileListBlobInternal mirrors the C struct VMMDLL_VFS_FILELISTBLOB.
type vfsFileListBlobInternal struct {
	DwVersion    uint32
	CbStruct     uint32
	CFileEntry   uint32
	CbMultiText  uint32
	UszMultiText uintptr   // pointer to char — within the same allocation
	_            [8]uint32 // _FutureUse
	// VMMDLL_VFS_FILELISTBLOB_ENTRY FileEntry[0] follows (FAM)
}

// vfsFileListExInfoInternal mirrors VMMDLL_VFS_FILELIST_EXINFO.
type vfsFileListExInfoInternal struct {
	DwVersion        uint32
	FCompressed      uint32 // BOOL
	QwCreationTime   uint64
	QwLastAccessTime uint64
	QwLastWriteTime  uint64
}

// vfsFileListBlobEntryInternal mirrors VMMDLL_VFS_FILELISTBLOB_ENTRY.
type vfsFileListBlobEntryInternal struct {
	OuszName   uint64 // byte offset into UszMultiText
	CbFileSize uint64 // ^uint64(0) == directory
	ExInfo     vfsFileListExInfoInternal
}

// VfsList lists entries in the given MemProcFS virtual path.
// Path examples: "/", "/sys", "/pid/4/modules"
func (vmm *Vmm) VfsList(path string) ([]VfsEntry, error) {
	blob := vmmVfsListBlobU(vmm.vmmHandle, vfsPath(path))
	if blob == 0 {
		return nil, fmt.Errorf("VfsList failed for path %q", path)
	}
	defer vmm.free(blob)

	hdr := (*vfsFileListBlobInternal)(unsafe.Pointer(blob))
	count := int(hdr.CFileEntry)
	if count == 0 {
		return nil, nil
	}

	entries := ffi.FAM[vfsFileListBlobInternal, vfsFileListBlobEntryInternal](hdr, count)
	result := make([]VfsEntry, count)
	for i, e := range entries {
		// Name is a null-terminated string at UszMultiText + OuszName.
		namePtr := hdr.UszMultiText + uintptr(e.OuszName)
		name := ffi.CStringToGo(namePtr)
		isDir := e.CbFileSize == ^uint64(0)
		result[i] = VfsEntry{
			Name:           name,
			Size:           e.CbFileSize,
			IsDirectory:    isDir,
			CreationTime:   e.ExInfo.QwCreationTime,
			LastAccessTime: e.ExInfo.QwLastAccessTime,
			LastWriteTime:  e.ExInfo.QwLastWriteTime,
		}
	}
	return result, nil
}

// VfsRead reads up to cb bytes from a MemProcFS virtual file at the given offset.
// Returns the data actually read; a short read is not an error.
func (vmm *Vmm) VfsRead(path string, cb uint32, offset uint64) ([]byte, error) {
	if cb == 0 {
		return nil, nil
	}
	buf := make([]byte, cb)
	var cbRead uint32
	status := vmmVfsReadU(vmm.vmmHandle, path, unsafe.Pointer(&buf[0]), cb, &cbRead, offset)
	// NTSTATUS: 0 = STATUS_SUCCESS, 0x80000005 = STATUS_BUFFER_OVERFLOW (partial), others = error
	if status != 0 && cbRead == 0 {
		return nil, fmt.Errorf("VfsRead failed for %q: NTSTATUS=0x%X", path, status)
	}
	return buf[:cbRead], nil
}

// VfsWrite writes data to a MemProcFS virtual file at the given offset.
// Note: requires a live/writable target — will fail on a read-only dump.
func (vmm *Vmm) VfsWrite(path string, data []byte, offset uint64) error {
	if len(data) == 0 {
		return nil
	}
	var cbWrite uint32
	status := vmmVfsWriteU(vmm.vmmHandle, path, unsafe.Pointer(&data[0]), uint32(len(data)), &cbWrite, offset)
	if status != 0 {
		return fmt.Errorf("VfsWrite failed for %q: NTSTATUS=0x%X", path, status)
	}
	return nil
}
