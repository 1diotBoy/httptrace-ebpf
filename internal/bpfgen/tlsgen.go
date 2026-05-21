package bpfgen

//go:generate env GOPROXY=off GOSUMDB=off go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64 -cc clang -strip llvm-strip -no-global-types TlsTrace ../../bpf/tls_trace.bpf.c -- -O2 -Wall -Werror -I../../bpf/include -I/usr/include/x86_64-linux-gnu
//go:generate ../../scripts/strip-bpf.sh tlstrace_x86_bpfel.o
//go:generate env GOPROXY=off GOSUMDB=off go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target arm64 -cc clang -strip llvm-strip -no-global-types TlsTrace ../../bpf/tls_trace.bpf.c -- -O2 -Wall -Werror -I../../bpf/include -I/usr/aarch64-linux-gnu/include
//go:generate ../../scripts/strip-bpf.sh tlstrace_arm64_bpfel.o
