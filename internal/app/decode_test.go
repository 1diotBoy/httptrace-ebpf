package app

import (
	"testing"
	"unsafe"

	"power-ebpf/internal/bpfgen"
)

func TestGeneratedEventPayloadSizeMatchesBPFLayout(t *testing.T) {
	var event bpfgen.HttpTraceHttpEvent

	if got, want := len(event.Payload), 4096; got != want {
		t.Fatalf("payload size mismatch: got %d want %d", got, want)
	}
	if got := unsafe.Sizeof(event); got < 4096 {
		t.Fatalf("event struct size too small: got %d", got)
	}
}

// 测试 decodeRawEvent 是否能接受变长的样本。
func TestDecodeRawEventAcceptsVariableLengthSample(t *testing.T) {
	var raw bpfgen.HttpTraceHttpEvent
	raw.ChainId = 42
	raw.PayloadLen = 3
	copy(raw.Payload[:], []byte("GET"))

	headerSize := int(unsafe.Offsetof(raw.Payload))
	fullSize := int(unsafe.Sizeof(raw))
	full := unsafe.Slice((*byte)(unsafe.Pointer(&raw)), fullSize)

	got, err := decodeRawEvent(full[:headerSize+int(raw.PayloadLen)])
	if err != nil {
		t.Fatalf("decode variable length sample: %v", err)
	}
	if got.ChainId != raw.ChainId {
		t.Fatalf("chain id mismatch: got %d want %d", got.ChainId, raw.ChainId)
	}
	if got.PayloadLen != raw.PayloadLen || string(got.Payload[:got.PayloadLen]) != "GET" {
		t.Fatalf("payload mismatch: len=%d payload=%q", got.PayloadLen, got.Payload[:got.PayloadLen])
	}
}

func TestDecodeRawEventRejectsTruncatedPayload(t *testing.T) {
	var raw bpfgen.HttpTraceHttpEvent
	raw.PayloadLen = 4

	headerSize := int(unsafe.Offsetof(raw.Payload))
	fullSize := int(unsafe.Sizeof(raw))
	full := unsafe.Slice((*byte)(unsafe.Pointer(&raw)), fullSize)

	if _, err := decodeRawEvent(full[:headerSize+3]); err == nil {
		t.Fatal("expected truncated payload error")
	}
}

func TestDecodeRawEventAcceptsPerfAlignmentBytes(t *testing.T) {
	var raw bpfgen.HttpTraceHttpEvent
	raw.ChainId = 42
	raw.PayloadLen = uint16(len(raw.Payload))
	raw.Payload[0] = 'G'

	fullSize := int(unsafe.Sizeof(raw))
	full := unsafe.Slice((*byte)(unsafe.Pointer(&raw)), fullSize)
	sample := append(append([]byte(nil), full...), 0, 0, 0, 0)

	got, err := decodeRawEvent(sample)
	if err != nil {
		t.Fatalf("decode sample with perf alignment bytes: %v", err)
	}
	if got.ChainId != raw.ChainId || got.PayloadLen != raw.PayloadLen || got.Payload[0] != 'G' {
		t.Fatalf("decoded event mismatch: %+v", got)
	}
}
