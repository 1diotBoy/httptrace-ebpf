package app

import (
	"log"
	"testing"

	"power-ebpf/internal/httptrace"
)

func TestFormatIPv4FromKernelNetworkOrderValue(t *testing.T) {
	const raw uint32 = 0xA104A8C0
	log.Println(raw)
	log.Println(formatIPv4(raw))

	if got, want := formatIPv4(raw), "192.168.4.161"; got != want {
		t.Fatalf("formatIPv4 mismatch: got %q want %q", got, want)
	}
}

func TestCaptureSourceName(t *testing.T) {
	cases := map[uint8]string{
		0: "unknown",
		1: "sock_sendmsg",
		2: "tcp_sendmsg",
		3: "sock_recvmsg",
		4: "tcp_recvmsg",
		5: "tcp_close",
	}

	for raw, want := range cases {
		if got := captureSourceName(raw); got != want {
			t.Fatalf("captureSourceName(%d) = %q want %q", raw, got, want)
		}
	}
}

func TestShouldRetryResolve(t *testing.T) {
	if !shouldRetryResolve(httptrace.Event{
		Direction: httptrace.DirectionRequest,
		FD:        12,
		SrcIP:     "0.0.0.0",
		DstIP:     "0.0.0.0",
	}) {
		t.Fatalf("request event with missing tuple should enter retry path")
	}

	if shouldRetryResolve(httptrace.Event{
		Direction: httptrace.DirectionUnknown,
		FD:        12,
		SrcIP:     "0.0.0.0",
		DstIP:     "0.0.0.0",
	}) {
		t.Fatalf("unknown direction should not enter retry path")
	}

	if shouldRetryResolve(httptrace.Event{
		Direction: httptrace.DirectionResponse,
		FD:        -1,
		SrcIP:     "0.0.0.0",
		DstIP:     "0.0.0.0",
	}) {
		t.Fatalf("invalid fd should not enter retry path")
	}
}
