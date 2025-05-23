package memprocfs

// FLAG used to supress the default read cache in calls to VMM_MemReadEx()
// which will lead to the read being fetched from the target system always.
// Cached page tables (used for translating virtual2physical) are still used.
type VMMFlag uint32

const (
	// FlagNoCache suppresses the default read cache in calls to VMM_MemReadEx.
	// This will lead to the read being fetched from the target system always.
	// Cached page tables (used for translating virtual2physical) are still used.
	FlagNoCache VMMFlag = 0x0001

	// FlagZeroPadOnFail zero pads failed physical memory reads and reports success if read within range of physical memory.
	FlagZeroPadOnFail VMMFlag = 0x0002

	// FlagForceCacheRead forces use of cache - fail non-cached pages.
	// Only valid for reads, invalid with FlagNoCache/FlagZeroPadOnFail.
	FlagForceCacheRead VMMFlag = 0x0008

	// FlagNoPaging does not try to retrieve memory from paged out memory from pagefile/compressed (even if possible).
	FlagNoPaging VMMFlag = 0x0010

	// FlagNoPagingIO does not try to retrieve memory from paged out memory if read would incur additional I/O (even if possible).
	FlagNoPagingIO VMMFlag = 0x0020

	// FlagNoCachePut does not write back to the data cache upon successful read from memory acquisition device.
	FlagNoCachePut VMMFlag = 0x0100

	// FlagCacheRecentOnly only fetches from the most recent active cache region when reading.
	FlagCacheRecentOnly VMMFlag = 0x0200

	// FlagNoPredictiveRead is deprecated/unused.
	FlagNoPredictiveRead VMMFlag = 0x0400

	// FlagForceCacheReadDisable disables/overrides any use of FlagForceCacheRead.
	// Only recommended for local files. Improves forensic artifact order.
	FlagForceCacheReadDisable VMMFlag = 0x0800

	// FlagScatterPrepareExNoMemZero does not zero out the memory buffer when preparing a scatter read.
	FlagScatterPrepareExNoMemZero VMMFlag = 0x1000

	// FlagNoMemCallback does not call user-set memory callback functions when reading memory (even if active).
	FlagNoMemCallback VMMFlag = 0x2000

	// FlagScatterForcePageRead forces page-sized reads when using scatter functionality.
	FlagScatterForcePageRead VMMFlag = 0x4000
)
