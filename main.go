package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"strings"
	"sync"
	"time"
	"bufio"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf bpf/file_monitor.c

type Event struct {
	Pid      uint32
	Command  [16]byte
	Filename [256]byte
	Op       [10]byte
}
var (
	allowedFiles []string
	mu           sync.RWMutex
)
func main() {

    
	updateAllowedFiles()
	go func() {
		for {
			time.Sleep(10 * time.Second)
			updateAllowedFiles()
		}
	}()

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	openatTracepoint, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpenat, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer openatTracepoint.Close()

	unlinkatTracepoint, err := link.Tracepoint("syscalls", "sys_enter_unlinkat", objs.TraceUnlinkat, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer unlinkatTracepoint.Close()

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	fmt.Println("Monitoring file operartions...")

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				log.Printf("reading from perf event reader: %s", err)
				continue
			}

			if record.LostSamples != 0 {
				log.Printf("lost %d samples", record.LostSamples)
				continue
			}

			var event Event
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("parsing perf event: %s", err)
				continue
			}

			command := string(bytes.TrimRight(event.Command[:], "\x00"))
			filename := string(bytes.TrimRight(event.Filename[:], "\x00"))
			operation := string(bytes.TrimRight(event.Op[:], "\x00"))
            
			if !isAllowedFile(filename) {
				continue
			}
			log.Printf("PID: %d, Process: %s, Operation: %s, File: %s\n", event.Pid, command, operation, filename)
		}
	}()

	<-sig
	fmt.Println("\nExiting...")
}

func updateAllowedFiles() {
    file, err := os.Open("allowed_files.txt")
    if err != nil {
        log.Printf("Error opening allowed_files.txt: %v", err)
        return
    }
    defer file.Close()

    var files []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line != "" {
            files = append(files, line)
        }
    }
    if err := scanner.Err(); err != nil {
        log.Printf("Error reading allowed_files.txt: %v", err)
        return
    }

    mu.Lock()
    allowedFiles = files
    mu.Unlock()
}

func isAllowedFile(filename string) bool {
    mu.RLock()
    defer mu.RUnlock()

    for _, allowed := range allowedFiles {
        if strings.HasPrefix(filename, allowed) {
            return true
        }
    }
    return false
}