.PHONY: all generate build clean

all: generate build

generate:
	# Requires clang, llvm, and linux headers (or vmlinux.h for BTF)
	go generate ./...

build:
	go build -o fenrir-linux-agent main.go bpf_bpfel.go

clean:
	rm -f fenrir-linux-agent
	rm -f bpf_bpfel.go bpf_bpfel.o
