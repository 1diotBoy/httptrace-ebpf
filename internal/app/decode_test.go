package app

import (
	"testing"
	"unsafe"

	"power-ebpf/internal/bpfgen"
)

func TestGeneratedEventPayloadSizeMatchesBPFLayout(t *testing.T) {
	var event bpfgen.HttpTraceHttpEvent

	if got, want := len(event.Payload), 1024; got != want {
		t.Fatalf("payload size mismatch: got %d want %d", got, want)
	}
	if got := unsafe.Sizeof(event); got < 256 {
		t.Fatalf("event struct size too small: got %d", got)
	}
}
