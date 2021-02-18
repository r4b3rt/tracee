package main

import "C"

import (
	"os"
	bpf "github.com/aquasecurity/tracee/libbpfgo"
)

func main() {

	bpfModule, err := bpf.NewModuleFromFile("self.bpf.o")
	if err != nil {
		os.Exit(-1)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()
	prog, err := bpfModule.GetProgram("kprobe__sys_mmap")
	if err != nil {
		os.Exit(-1)
	}

	_, err = prog.AttachKprobe("__x64_sys_mmap")
	if err != nil {
		os.Exit(-1)
	}

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		os.Exit(-1)
	}

	rb.Start()

	numberOfEventsReceived := 0
	
	theloop:
	for {
		_ = <-eventsChannel
		numberOfEventsReceived++ 
		if numberOfEventsReceived > 5 {
			break theloop	
		}
	}

}
