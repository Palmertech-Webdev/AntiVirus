.PHONY: all generate build clean

all: generate build

generate:
	# Requires clang, llvm, and linux headers (or vmlinux.h for BTF)
	go generate ./cmd/fenrir-linux-agent/...

build:
	CGO_ENABLED=1 go build -o fenrir-linux-agent ./cmd/fenrir-linux-agent/

clean:
	rm -f fenrir-linux-agent
	rm -f cmd/fenrir-linux-agent/bpf_bpfel.go cmd/fenrir-linux-agent/bpf_bpfel.o
