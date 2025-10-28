package memprocfs

import "fmt"

// ConfigOpt defines the type for VMM configuration options used with ConfigGet/ConfigSet.
type ConfigOpt uint64

const (
	// Core Options
	OptCorePrintfEnable     ConfigOpt = 0x4000000100000000 // RW
	OptCoreVerbose          ConfigOpt = 0x4000000200000000 // RW
	OptCoreVerboseExtra     ConfigOpt = 0x4000000300000000 // RW
	OptCoreVerboseExtraTlp  ConfigOpt = 0x4000000400000000 // RW
	OptCoreMaxNativeAddress ConfigOpt = 0x4000000800000000 // R
	OptCoreLeechcoreHandle  ConfigOpt = 0x4000001000000000 // R
	OptCoreVmmId            ConfigOpt = 0x4000002000000000 // R
	OptCoreSystem           ConfigOpt = 0x2000000100000000 // R
	OptCoreMemoryModel      ConfigOpt = 0x2000000200000000 // R

	// Config Options
	OptConfigIsRefreshEnabled       ConfigOpt = 0x2000000300000000 // R
	OptConfigTickPeriod             ConfigOpt = 0x2000000400000000 // RW
	OptConfigReadCacheTicks         ConfigOpt = 0x2000000500000000 // RW
	OptConfigTlpCacheTicks          ConfigOpt = 0x2000000600000000 // RW
	OptConfigProcCacheTicksPartial  ConfigOpt = 0x2000000700000000 // RW
	OptConfigProcCacheTicksTotal    ConfigOpt = 0x2000000800000000 // RW
	OptConfigVmmVersionMajor        ConfigOpt = 0x2000000900000000 // R
	OptConfigVmmVersionMinor        ConfigOpt = 0x2000000A00000000 // R
	OptConfigVmmVersionRevision     ConfigOpt = 0x2000000B00000000 // R
	OptConfigStatisticsFunctionCall ConfigOpt = 0x2000000C00000000 // RW
	OptConfigIsPagingEnabled        ConfigOpt = 0x2000000D00000000 // RW
	OptConfigDebug                  ConfigOpt = 0x2000000E00000000 // W
	OptConfigYaraRules              ConfigOpt = 0x2000000F00000000 // R

	// Windows Specific Options
	OptWinVersionMajor   ConfigOpt = 0x2000010100000000 // R
	OptWinVersionMinor   ConfigOpt = 0x2000010200000000 // R
	OptWinVersionBuild   ConfigOpt = 0x2000010300000000 // R
	OptWinSystemUniqueId ConfigOpt = 0x2000010400000000 // R

	// Forensic Mode Options
	OptForensicMode ConfigOpt = 0x2000020100000000 // RW

	// Refresh Options
	OptRefreshAll            ConfigOpt = 0x2001ffff00000000 // W
	OptRefreshFreqMem        ConfigOpt = 0x2001100000000000 // W
	OptRefreshFreqMemPartial ConfigOpt = 0x2001000200000000 // W
	OptRefreshFreqTlb        ConfigOpt = 0x2001080000000000 // W
	OptRefreshFreqTlbPartial ConfigOpt = 0x2001000400000000 // W
	OptRefreshFreqFast       ConfigOpt = 0x2001040000000000 // W
	OptRefreshFreqMedium     ConfigOpt = 0x2001000100000000 // W
	OptRefreshFreqSlow       ConfigOpt = 0x2001001000000000 // W

	// Process Specific Options (PID in lower DWORD)
	OptProcessDtb                 ConfigOpt = 0x2002000100000000 // W
	OptProcessDtbFastLowIntegrity ConfigOpt = 0x2002000200000000 // W
)

// ConfigGet retrieves a configuration value from the VMM.
func (vmm *Vmm) ConfigGet(option ConfigOpt) (uint64, error) {
	var value uint64
	success := vmmConfigGet(vmm.vmmHandle, uint64(option), &value)
	if !success {
		return 0, fmt.Errorf("failed to get config option %X", option)
	}
	return value, nil
}

// ConfigSet sets a configuration value in the VMM.
func (vmm *Vmm) ConfigSet(option ConfigOpt, value uint64) error {
	success := vmmConfigSet(vmm.vmmHandle, uint64(option), value)
	if !success {
		return fmt.Errorf("failed to set config option %X", option)
	}
	return nil
}
