# go-memprocfs

[![Build](https://github.com/sergeyzav/gomemprocfs/actions/workflows/build.yml/badge.svg)](https://github.com/sergeyzav/gomemprocfs/actions/workflows/build.yml)
[![Test](https://github.com/sergeyzav/gomemprocfs/actions/workflows/test.yml/badge.svg)](https://github.com/sergeyzav/gomemprocfs/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/sergeyzav/gomemprocfs.svg)](https://pkg.go.dev/github.com/sergeyzav/gomemprocfs)

Go bindings for [MemProcFS](https://github.com/ufrisk/MemProcFS), providing live memory analysis and forensics capabilities via a pure Go API without CGo.

## Compatibility

[![MemProcFS latest](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fsergeyzav%2Fgomemprocfs%2Fbadges%2Fmemprocfs-0.json)](https://github.com/sergeyzav/gomemprocfs/actions/workflows/test.yml?query=branch%3Amain)
[![MemProcFS previous](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fsergeyzav%2Fgomemprocfs%2Fbadges%2Fmemprocfs-1.json)](https://github.com/sergeyzav/gomemprocfs/actions/workflows/test.yml?query=branch%3Amain)

## Requirements

This library wraps the native `vmmdll` shared library using [purego](https://github.com/ebitengine/purego). The native libraries must be present on the system:

| Platform | Libraries needed |
|----------|-----------------|
| macOS    | `vmm.dylib`, `leechcore.dylib` |
| Windows  | `vmm.dll`, `leechcore.dll` |
| Linux    | `vmm.so`, `leechcore.so` |

Download the native libraries from the [MemProcFS releases page](https://github.com/ufrisk/MemProcFS/releases) and place them in a directory accessible at runtime (e.g. next to the binary, or in `libs/`).

## Installation

```sh
go get github.com/sergeyzav/gomemprocfs
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    "github.com/sergeyzav/gomemprocfs"
)

func main() {
    // Open a memory dump file
    vmm, err := memprocfs.NewVmm("./libs/vmm.dylib",
        memprocfs.WithDevice("./dumps/memdump.raw"),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer vmm.Close()

    // List all running processes
    pids, err := vmm.GetPidList()
    if err != nil {
        log.Fatal(err)
    }

    for _, pid := range pids {
        info, err := vmm.GetProcessInfo(pid)
        if err != nil {
            continue
        }
        fmt.Printf("PID %d: %s\n", pid, info.Name())
    }
}
```

### Reading process memory

```go
pid, err := vmm.GetPidByName("notepad.exe")
if err != nil {
    log.Fatal(err)
}

data, err := vmm.MemRead(pid, 0x7FF000000000, 0x100)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("% x\n", data)
```

### Scatter (batched) reads

```go
scatter, err := vmm.ScatterInitialize(pid, 0)
if err != nil {
    log.Fatal(err)
}
defer scatter.Close()

scatter.Prepare(0x7FF000000000, 0x100)
scatter.Prepare(0x7FF000001000, 0x100)
scatter.ExecuteRead()

data, _ := scatter.Read(0x7FF000000000, 0x100)
```

### Searching memory

```go
ctx := context.Background()

// Byte patterns, with an optional per-bit wildcard mask ("M?" here).
hits, err := vmm.MemSearch(ctx, pid, []memprocfs.SearchPattern{
    {Bytes: []byte{'M', 0}, Mask: []byte{0, 0xFF}, Align: 0x1000},
}, nil)

// Or get hits one by one; return false to stop.
err = vmm.MemSearchFunc(ctx, pid, patterns, nil, func(va uint64, pattern int) bool {
    fmt.Printf("pattern %d at %#x\n", pattern, va)
    return true
})

// YARA rules (source text, rule files or one compiled file).
// Needs the vmmyara library next to vmm.dylib / vmm.dll / vmm.so.
hits, err = vmm.YaraSearch(ctx, pid, []string{`rule mz { strings: $a = "MZ" condition: $a }`}, nil)
```

Pass `memprocfs.PidPhysical` as `pid` to search physical memory. `SearchOptions` limits the address range and number of results, and its `Filter` decides which memory regions to read. Cancel `ctx` to stop a long search.

## Initialization options

| Option | Description |
|--------|-------------|
| `WithDevice(path)` | Target device or file path |
| `WithDeviceFPGA()` | Use FPGA hardware target |
| `WithRemote(dsn)` | Connect to a remote LeechAgent |
| `WithPageFile(id, path)` | Attach a Windows page file |
| `WithMemMap(path)` | Provide a physical memory map |
| `WithForensic(lvl)` | Enable forensic mode (0–4) |
| `WithVM()` | Enable virtual machine parsing |
| `WithNorefresh()` | Disable background refresh |
| `WithDisableSymbols()` | Skip PDB symbol loading |
| `WithVerbose()` | Enable verbose output |
| `WithPrintf()` | Enable native library stdout output |

## Supported platforms

- macOS (arm64, amd64)
- Windows (amd64)
- Linux (amd64) — experimental
