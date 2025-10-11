package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sergeyzav/memprocfs"
	"github.com/sergeyzav/memprocfs/memory"
)

func main() {
	vmm, err := memprocfs.NewVmm(
		memprocfs.WithDevice("/Users/user/projects/memprocfs/examples/memdump.raw"),
		memprocfs.WithVerbose(),
		memprocfs.WithPrintf(),
		memprocfs.WithMemMap("/Users/user/GolandProjects/MemProcFsGolang/libs/memmap.txt"),
	)
	//vmm, err := memprocfs.NewVmm("-device", "/Users/user/projects/memprocfs/examples/memdump.raw", "-v", "-printf", "-memmap", "/Users/user/GolandProjects/MemProcFsGolang/libs/memmap.txt")
	//vmm, err := memprocfs.NewVmm("-device", "/Users/user/Downloads/memdump.raw")
	//vmm, err := memprocfs.NewVmm("-device", "/Users/user/Downloads/memdump.raw", "-v", "-vv", "-vvv", "-printf")

	if err != nil {
		fmt.Println(err)
		return
	}

	defer vmm.Close()

	pid, err := vmm.GetPidByName(context.TODO(), "explorer.exe")

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("pid: ", pid)

	infoString, err := vmm.GetProcessInfoString(context.TODO(), pid, memprocfs.ProcessInformationOptStringPathKernel)
	if err != nil {
		fmt.Println(err)
		return
	}
	infoProc, err := vmm.GetProcessInfo(context.TODO(), pid)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("info string path kernel: ", prettyPrint(infoProc))

	infoString, err = vmm.GetProcessInfoString(context.TODO(), pid, memprocfs.ProcessInformationOptStringPathUserImage)
	if err != nil {
		fmt.Println(err)
		//return
	}

	fmt.Println("info string user image: ", infoString)

	infoString, err = vmm.GetProcessInfoString(context.TODO(), pid, memprocfs.ProcessInformationOptStringCmdline)
	if err != nil {
		fmt.Println(err)
		//return
	}

	fmt.Println("info string cmd line: ", infoString)

	explorerPid, err := vmm.GetPidByName(context.TODO(), "explorer.exe")

	if err != nil {
		fmt.Println(err)
		//return
	} else {
		fmt.Println("explorer pid: ", explorerPid)
	}

	directories, err := vmm.GetProcessDirectories(context.TODO(), explorerPid, "kernel32.dll")
	if err != nil {
		fmt.Println(err)
		//return
	}

	for _, dictionary := range directories {
		fmt.Printf("dic: 0x%x, size: 0x%x\n", dictionary.VirtualAddress, dictionary.Size)
	}

	sections, err := vmm.GetProcessSections(context.TODO(), explorerPid, "kernel32.dll")
	if err != nil {
		fmt.Println(err)
		//return
	}

	for _, section := range sections {
		j, _ := json.Marshal(section)
		fmt.Printf("section: %s\n", j)
		//fmt.Printf("section: 0x%x, characteristics: 0x%x\n", section.VirtualAddress, section.Characteristics)
	}

	addr, err := vmm.GetProcessAddress(context.TODO(), explorerPid, "kernel32.dll", "LoadLibraryW")

	if err != nil {
		fmt.Println(err)
		//return
	} else {
		fmt.Printf("addr: 0x%x\n", addr)
	}

	addr, err = vmm.GetProcessModule(context.TODO(), explorerPid, "kernel32.dll")

	if err != nil {
		fmt.Println(err)
		//return
	} else {
		fmt.Printf("addr: 0x%x\n", addr)
	}

	pte, err := vmm.GetProcessMapPTE(context.TODO(), pid, true)

	if err != nil {
		fmt.Println(err)
		//return
	} else {
		for _, s := range pte.MultiText {
			fmt.Printf("text: %s\n", s)
		}

		for _, entry := range pte.MapEntries {
			fmt.Printf("entry: %s\n", entry.Text)
		}
	}

	fmt.Println("===== PTE STRUCT =====")
	fmt.Printf("Version      : %d\n", pte.Version)
	fmt.Printf("MultiText    : %s\n", pte.MultiText)
	fmt.Printf("Entries count: %d\n", len(pte.MapEntries))
	fmt.Println("---------------------------")

	//for i, entry := range pte.MapEntries {
	//	fmt.Printf("Entry #%d:\n", i+1)
	//	//fmt.Printf("  VaBase     : 0x%X\n", entry.VABase)
	//	//fmt.Printf("  CPages     : %d\n", entry.Pages)
	//	//fmt.Printf("  FPage      : 0x%X\n", entry.PageFlags)
	//	//fmt.Printf("  IsWow64    : %t\n", entry.IsWoW64)
	//	//fmt.Printf("  Text       : %s\n", entry.Text)
	//	//fmt.Printf("  CSoftware  : %d\n", entry.SoftCount)
	//	fmt.Printf("  F  : %d\n", entry.FutureUse1)
	//	fmt.Printf("  R  : %d\n", entry.Reserved1)
	//	fmt.Println("---------------------------")
	//}

	//fmt.Println(prettyPrint(pte))

	vad, err := vmm.GetProcessMapVAD(context.TODO(), pid, true)

	if err != nil {
		fmt.Println(err)
		//return
	} else {
		fmt.Println("===== VAD STRUCT =====", prettyPrint(vad))
	}

	module, err := vmm.GetProcessModuleList(context.TODO(), pid, 1)

	if err != nil {
		fmt.Println(err)
		//return
	} else {
		fmt.Println("===== MODULE STRUCT =====", prettyPrint(module))
	}

	mem := make([]byte, 40)
	err = vmm.MemRead(explorerPid, 140733155704832, mem)

	if err != nil {
		fmt.Println(err)
		//return
	} else {
		fmt.Println("===== MEM READ =====", prettyPrint(mem))
	}

	task, err := vmm.NewScatterTask(explorerPid, 0x3)
	defer task.Close(context.TODO())
	if err != nil {
		fmt.Println(err)
	}
	buff := make([]byte, 40)
	err = task.PrepareRead(context.TODO(), 140733155704832, buff[0:5])
	if err != nil {
		fmt.Println(err)
	}
	err = task.PrepareRead(context.TODO(), 140733155704832+5, buff[5:20])
	if err != nil {
		fmt.Println(err)
	}
	err = task.PrepareRead(context.TODO(), 140733155704832+20, buff[20:40])
	if err != nil {
		fmt.Println(err)
	}

	err = task.ExecuteRead(context.TODO())
	if err != nil {
		fmt.Println(err)
	}

	err = task.Clear(context.TODO())
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("===== MEM SCATTER READ =====", prettyPrint(buff))

	task1, err := vmm.NewScatterTask(explorerPid, 0x3)
	defer task1.Close(context.TODO())

	m := memory.NewMemory(task1, 3)

	r1, _ := m.Read(context.TODO(), 140733155704832, 40, time.Second*10)
	r2, _ := m.Read(context.TODO(), 140733155704832, 40, time.Second*2)

	fmt.Println("===== MEMORY READ =====", prettyPrint(<-r1))
	fmt.Println("===== MEMORY READ =====", prettyPrint(<-r2))

	unloadedModules, err := vmm.GetUnloadedModules(context.TODO(), pid)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("===== UNLOADED MODULES =====", prettyPrint(unloadedModules))
	}

	eat, err := vmm.GetEat(context.TODO(), explorerPid, "kernel32.dll")
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("===== EAT (kernel32.dll) ====", prettyPrint(eat))
	}

	iat, err := vmm.GetIat(context.TODO(), explorerPid, "kernel32.dll")
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("===== IAT (kernel32.dll) ====", prettyPrint(iat))
	}

	threads, err := vmm.GetThreads(context.TODO(), explorerPid)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("===== THREADS (explorer.exe) ====", prettyPrint(threads))
		if len(threads.Entries) > 0 {
			firstThread := threads.Entries[0]
			callstack, err := vmm.GetThreadCallstack(context.TODO(), explorerPid, firstThread.TID, 0)
			if err != nil {
				fmt.Println(err)
			} else {
				fmt.Printf("===== CALLSTACK (explorer.exe, TID: %d) =====\n", firstThread.TID)
				fmt.Println(prettyPrint(callstack))
			}
		}
	}

	handles, err := vmm.GetHandles(context.TODO(), explorerPid)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("===== HANDLES (explorer.exe) ====", prettyPrint(handles))
	}

	net, err := vmm.GetNet(context.TODO())
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("===== NETWORK CONNECTIONS =====", prettyPrint(net))
	}

	services, err := vmm.GetServices(context.TODO())
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("===== SERVICES =====", prettyPrint(services))
	}

	heap, err := vmm.GetHeap(context.TODO(), explorerPid)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("===== HEAP (explorer.exe) =====", prettyPrint(heap))
		if len(heap.Entries) > 0 {
			firstHeap := heap.Entries[0]
			heapAllocs, err := vmm.GetHeapAlloc(context.TODO(), explorerPid, firstHeap.Va)
			if err != nil {
				fmt.Println(err)
			} else {
				fmt.Printf("===== HEAP ALLOCS (explorer.exe, heap: 0x%x) =====\n", firstHeap.Va)
				fmt.Println(prettyPrint(heapAllocs))
			}
		}
	}

	physMem, err := vmm.GetPhysMem(context.TODO())
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("===== PHYSICAL MEMORY MAP =====", prettyPrint(physMem))
	}
}

func prettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}
