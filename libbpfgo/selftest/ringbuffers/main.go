package main

import "C"

import (
	"os"
	"os/signal"

	bpf "github.com/aquasecurity/tracee/libbpfgo"
)

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	bpfModule, err := bpf.NewModuleFromFile("self.bpf.o")
	if err != nil {
		panic(err)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()
	prog, err := bpfModule.GetProgram("kprobe__sys_mmap")
	if err != nil {
		panic(err)
	}

	_, err = prog.AttachKprobe("__x64_sys_mmap")
	if err != nil {
		panic(err)
	}

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		panic(err)
	}
	rb.Start()

	numberOfEventsReceived := 0

	go func() {
		for {
			select {
			case <-eventsChannel:
				numberOfEventsReceived++ 
				if numberOfEventsReceived > 5 {
					rb.Stop()
					rb.Close()	
					os.Exit(0)	
				}
			case <-sig:
				rb.Stop()
				rb.Close()
			}
		}
	}()

	<-sig
	rb.Stop()
	rb.Close()
}
