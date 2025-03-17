# Argus
Argus is an eBPF-based File Integrity Monitoring (FIM) tool that provides real-time detection of unauthorized file modifications by leveraging eBPF to efficiently track file system events at the kernel level. 

## Prerequisites:
- Linux kernel version 5.7 or later
- LLVM 11 or later
- libbpf headers
- Linux kernel headers
- Go compiler version supported by ebpf-go's Go module
- [ebpf-go library](https://github.com/cilium/ebpf)


## How to run:
```
go generate
go build (An executable named filemon will be generated if the build succeeds)
sudo ./filemon
```

## Features:
- Monitors file operations by tracing syscalls using eBPF
- Currently traces openat and unlinkat syscalls
- Reports PID, process name, operation type, and filename for each event
