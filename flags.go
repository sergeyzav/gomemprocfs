package memprocfs

// MemFlag is a bitmask of memory read/write flags (VMMDLL_FLAG_*).
type MemFlag uint32

const (
	// MemFlagNone is the default — no special flags.
	MemFlagNone MemFlag = 0

	// MemFlagNoCache forces reading from the acquisition device, bypassing cache.
	MemFlagNoCache MemFlag = 0x0001

	// MemFlagZeroPadOnFail zero-pads failed physical memory reads and reports
	// success if the read is within range of physical memory.
	MemFlagZeroPadOnFail MemFlag = 0x0002

	// MemFlagForceCacheRead forces use of cache; fails non-cached pages.
	// Invalid combined with MemFlagNoCache or MemFlagZeroPadOnFail.
	MemFlagForceCacheRead MemFlag = 0x0008

	// MemFlagNoPaging skips retrieval of paged-out memory from pagefile/compressed.
	MemFlagNoPaging MemFlag = 0x0010

	// MemFlagNoPagingIO skips retrieval of paged-out memory if it would incur I/O.
	MemFlagNoPagingIO MemFlag = 0x0020

	// MemFlagNoCachePut prevents writing back to the data cache after a successful read.
	MemFlagNoCachePut MemFlag = 0x0100

	// MemFlagCacheRecentOnly fetches only from the most recent active cache region.
	MemFlagCacheRecentOnly MemFlag = 0x0200

	// MemFlagForceCacheReadDisable disables VMMDLL_FLAG_FORCECACHE_READ.
	// Recommended for local files to improve forensic artifact ordering.
	MemFlagForceCacheReadDisable MemFlag = 0x0800

	// MemFlagScatterPrepareExNoMemZero skips zero-ing the buffer when
	// preparing a scatter read.
	MemFlagScatterPrepareExNoMemZero MemFlag = 0x1000

	// MemFlagNoMemCallback suppresses user-set memory callback functions.
	MemFlagNoMemCallback MemFlag = 0x2000

	// MemFlagScatterForcePageRead forces page-sized reads in scatter operations.
	MemFlagScatterForcePageRead MemFlag = 0x4000
)
