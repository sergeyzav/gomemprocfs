# go-memprocfs

Go bindings for [MemProcFS](https://github.com/ufrisk/MemProcFS) (`vmmdll`), providing live memory analysis and forensics capabilities via a pure Go API without CGo.

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
