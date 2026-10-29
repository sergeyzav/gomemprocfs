package memprocfs

// Regenerates layout_test.go from libs/vmmdll.h. Needs clang and leechcore.h
// in libs/; see internal/cmd/layoutgen for details.
//go:generate go run ./internal/cmd/layoutgen
