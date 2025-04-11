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
	"encoding/json"
	"path/filepath"

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
    
	writeTracepoint, err := link.Tracepoint("syscalls", "sys_enter_write", objs.TraceWrite, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer writeTracepoint.Close()
    
	renameat2Tracepoint, err := link.Tracepoint("syscalls", "sys_enter_renameat2", objs.TraceRenameat2, nil)	
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer renameat2Tracepoint.Close()
	
	fchmodatTracepoint, err := link.Tracepoint("syscalls", "sys_enter_fchmodat", objs.TraceFchmodat, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer fchmodatTracepoint.Close()
	
	fchownatTracepoint, err := link.Tracepoint("syscalls", "sys_enter_fchownat", objs.TraceFchownat, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer fchownatTracepoint.Close()
	

	closeTracepoint, err := link.Tracepoint("syscalls", "sys_exit_close", objs.TraceClose, nil)
	if err != nil {
    	log.Fatalf("opening tracepoint: %s", err)
	}
	defer closeTracepoint.Close()

	rd, err := perf.NewReader(objs.Events, 4096*8)
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
            
			if operation == "CHMOD"|| operation == "DELETE" || operation == "CHOWN" {
				filename = resolvePathFromPid(event.Pid, filename)
				//log.Printf("PID: %d, Process: %s, Operation: %s, File: %s\n", event.Pid, command, operation, filename)
			}
			// if operation == "DELETE" && isAllowedFile(filename) {
			// 	log.Printf("PID: %d, Process: %s, Operation: %s, File: %s\n", event.Pid, command, operation, filename)
			// 	removeFromAllowedFiles(filename)
			// 	continue
			// }
			if operation == "RENAMED" {
				filename = resolvePathFromPid(event.Pid, filename)
			//	log.Printf("PID: %d, Process: %s, Operation: %s, File: %s\n", event.Pid, command, operation, filename)
				appendToAllowedFiles(filename)
			}
			if operation == "RENAME" {
				filename = resolvePathFromPid(event.Pid, filename)
				if isAllowedFile(filename) {
				//removeFromAllowedFiles(filename)
				log.Printf("PID: %d, Process: %s, Operation: %s, File: %s\n", event.Pid, command, operation, filename)
				continue
			}
			}

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
    file, err := os.Open("./allowed_files.json")
    if err != nil {
        log.Printf("Error opening allowed_files.json: %v", err)
        return
    }
    defer file.Close()

    var files []string
    decoder := json.NewDecoder(file)
    if err := decoder.Decode(&files); err != nil {
        log.Printf("Error decoding allowed_files.json: %v", err)
        return
    }

    mu.Lock()
    allowedFiles = files
    mu.Unlock()
}

func isAllowedFile(filename string) bool {
    mu.RLock()
    defer mu.RUnlock()

    if len(allowedFiles) == 0 {
        return false
    }

    normalizedFilename := filepath.Clean(strings.ToLower(filename))

    for _, allowed := range allowedFiles {
        normalizedAllowed := filepath.Clean(strings.ToLower(allowed))
        if strings.HasPrefix(normalizedFilename, normalizedAllowed) {
            return true
        }
    }

    return false
}

func resolvePathFromPid(pid uint32, rawFilename string) string {
    // If rawFilename is already an absolute path, return it as is
    if filepath.IsAbs(rawFilename) {
        return filepath.Clean(rawFilename)
    }

    // Attempt to resolve the current working directory of the process
    cwd := fmt.Sprintf("/proc/%d/cwd", pid)
    link, err := os.Readlink(cwd)
    if err != nil {
        log.Printf("Failed to resolve /proc/%d/cwd: %v. Falling back to raw filename: %s", pid, err, rawFilename)
        return filepath.Clean(rawFilename) // Fallback to raw filename
    }

    // Join the resolved cwd with the raw filename
    resolvedPath := filepath.Clean(filepath.Join(link, rawFilename))
    log.Printf("Resolved path for PID %d: %s", pid, resolvedPath)
    return resolvedPath
}

func appendToAllowedFiles(path string) error {
    mu.Lock()
    defer mu.Unlock()

    path = filepath.Clean(path)

    // Check if the path already exists
    for _, allowed := range allowedFiles {
        if allowed == path {
            return nil // Path already exists
        }
    }

    // Add the new path to the in-memory list
    allowedFiles = append(allowedFiles, path)

    // Write the updated list to the text file
    return writeAllowedFilesToFile()
}

func removeFromAllowedFiles(pathToRemove string) error {
    mu.Lock()
    defer mu.Unlock()

    pathToRemove = filepath.Clean(pathToRemove)

    // Filter out the path to remove
    var newAllowedFiles []string
    for _, allowed := range allowedFiles {
        if allowed != pathToRemove {
            newAllowedFiles = append(newAllowedFiles, allowed)
        }
    }

    allowedFiles = newAllowedFiles

    // Write the updated list to the text file
    return writeAllowedFilesToFile()
}

func writeAllowedFilesToFile() error {
    file, err := os.OpenFile("allowed_files.json", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
    if err != nil {
        return err
    }
    defer file.Close()

    encoder := json.NewEncoder(file)
    encoder.SetIndent("", "  ") // Pretty-print the JSON
    return encoder.Encode(allowedFiles)
}