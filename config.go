package memprocfs

/*
#include "vmmdll.h"
#include "leechcore.h"
*/
import "C"
import (
	"context"
	"errors"
	"unsafe"
)

// Core options
const (
	OptCorePrintfEnable     = 0x4000000100000000 // RW
	OptCoreVerbose          = 0x4000000200000000 // RW
	OptCoreVerboseExtra     = 0x4000000300000000 // RW
	OptCoreVerboseExtraTLP  = 0x4000000400000000 // RW
	OptCoreMaxNativeAddress = 0x4000000800000000 // R
	OptCoreLeechcoreHandle  = 0x4000001000000000 // R - underlying leechcore handle (do not close)
	OptCoreVmmID            = 0x4000002000000000 // R - use with startup option '-create-from-vmmid' to create a thread-safe duplicate VMM instance
)

// System options
const (
	OptCoreSystem      = 0x2000000100000000 // R
	OptCoreMemoryModel = 0x2000000200000000 // R
)

// Config options
const (
	OptConfigIsRefreshEnabled      = 0x2000000300000000 // R - 1/0
	OptConfigTickPeriod            = 0x2000000400000000 // RW - base tick period in ms
	OptConfigReadCacheTicks        = 0x2000000500000000 // RW - memory cache validity period (in ticks)
	OptConfigTlbCacheTicks         = 0x2000000600000000 // RW - page table (tlb) cache validity period (in ticks)
	OptConfigProcCacheTicksPartial = 0x2000000700000000 // RW - process refresh (partial) period (in ticks)
	OptConfigProcCacheTicksTotal   = 0x2000000800000000 // RW - process refresh (full) period (in ticks)
	OptConfigVmmVersionMajor       = 0x2000000900000000 // R
	OptConfigVmmVersionMinor       = 0x2000000A00000000 // R
	OptConfigVmmVersionRevision    = 0x2000000B00000000 // R
	OptConfigStatisticsFuncCall    = 0x2000000C00000000 // RW - enable function call statistics (.status/statistics_fncall file)
	OptConfigIsPagingEnabled       = 0x2000000D00000000 // RW - 1/0
	OptConfigDebug                 = 0x2000000E00000000 // W
	OptConfigYaraRules             = 0x2000000F00000000 // R
)

// Windows options
const (
	OptWinVersionMajor   = 0x2000010100000000 // R
	OptWinVersionMinor   = 0x2000010200000000 // R
	OptWinVersionBuild   = 0x2000010300000000 // R
	OptWinSystemUniqueID = 0x2000010400000000 // R
)

// Forensic options
const (
	OptForensicMode = 0x2000020100000000 // RW - enable/retrieve forensic mode type [0-4]
)

// Refresh options
const (
	OptRefreshAll            = 0x2001ffff00000000 // W - refresh all caches
	OptRefreshFreqMem        = 0x2001100000000000 // W - refresh memory cache (excl. TLB) [fully]
	OptRefreshFreqMemPartial = 0x2001000200000000 // W - refresh memory cache (excl. TLB) [partial 33%/call]
	OptRefreshFreqTLB        = 0x2001080000000000 // W - refresh page table (TLB) cache [fully]
	OptRefreshFreqTLBPartial = 0x2001000400000000 // W - refresh page table (TLB) cache [partial 33%/call]
	OptRefreshFreqFast       = 0x2001040000000000 // W - refresh fast frequency incl. partial process refresh
	OptRefreshFreqMedium     = 0x2001000100000000 // W - refresh medium frequency incl. full process refresh
	OptRefreshFreqSlow       = 0x2001001000000000 // W - refresh slow frequency
)

// Process options (Lo-DWORD: Process PID)
const (
	OptProcessDTB                 = 0x2002000100000000 // W - force set process directory table base
	OptProcessDTBFastLowIntegrity = 0x2002000200000000 // W - force set process DTB (fast, low integrity mode) - use at own risk!
)

func (vmm *Vmm) ConfigGet(ctx context.Context, option uint64) (uint64, error) {
	respChan := make(chan struct {
		value uint64
		err   error
	})

	go func() {
		var value uint64
		success := C.VMMDLL_ConfigGet(C.VMM_HANDLE(vmm.handle), C.ULONG64(option), (*C.ULONG64)(unsafe.Pointer(&value)))
		if success == 0 {
			respChan <- struct {
				value uint64
				err   error
			}{0, errors.New("VMMDLL_ConfigGet: failed to get config")}
			return
		}

		respChan <- struct {
			value uint64
			err   error
		}{value, nil}
	}()

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case resp := <-respChan:
		return resp.value, resp.err
	}
}

func (vmm *Vmm) ConfigSet(ctx context.Context, option uint64, value uint64) error {
	errChan := make(chan error, 1)

	go func() {
		success := C.VMMDLL_ConfigSet(C.VMM_HANDLE(vmm.handle), C.ULONG64(option), C.ULONG64(value))
		if success == 0 {
			errChan <- errors.New("VMMDLL_ConfigGet: failed to set config")
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errChan:
		return err
	}
}
