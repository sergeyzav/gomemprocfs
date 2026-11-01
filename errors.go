package memprocfs

import "errors"

// Sentinel errors for memory and scatter operations. Errors returned by those
// operations wrap one of these, so callers can match them with errors.Is.
//
// The native library only reports success or failure, so ErrReadFailed does not
// say why a read failed (e.g. unreadable page vs. invalid address).
var (
	// ErrClosed is returned when a method is called on a closed handle.
	ErrClosed = errors.New("handle is closed")
	// ErrReadFailed is returned when the native library fails to read memory.
	ErrReadFailed = errors.New("memory read failed")
	// ErrWriteFailed is returned when the native library fails to write memory.
	ErrWriteFailed = errors.New("memory write failed")
	// ErrScatterFailed is returned when a scatter prepare, execute or clear fails.
	ErrScatterFailed = errors.New("scatter operation failed")
	// ErrSearchFailed is returned when the native library fails a memory or
	// YARA search, e.g. because of invalid rules or a missing vmmyara library.
	ErrSearchFailed = errors.New("search failed")
)
