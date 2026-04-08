package app

import (
	"context"
	"log"
	"testing"
	"time"

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

func TestDispatchEventPassesThroughMissingTupleRequest(t *testing.T) {
	svc := &Service{
		cfg:    DefaultConfig(),
		filter: ResolvedFilter{DstPort: 16210},
		stats:  &stats{},
	}
	ch := make(chan httptrace.Event, 1)
	event := httptrace.Event{
		ChainID:   1,
		FD:        10,
		Direction: httptrace.DirectionRequest,
		SrcIP:     "0.0.0.0",
		DstIP:     "0.0.0.0",
		SrcPort:   0,
		DstPort:   0,
	}

	if err := svc.dispatchEvent(context.Background(), event, ch); err != nil {
		t.Fatalf("dispatchEvent returned error: %v", err)
	}

	select {
	case got := <-ch:
		if got.ChainID != event.ChainID {
			t.Fatalf("unexpected event delivered: %#v", got)
		}
	default:
		t.Fatalf("expected unresolved request to be passed through")
	}

	if svc.stats.tuplePassThrough.Load() != 1 {
		t.Fatalf("tuple pass-through counter should increase")
	}
	if svc.stats.userFiltered.Load() != 0 {
		t.Fatalf("event should not be counted as filtered")
	}
}

func TestDispatchEventPassesThroughLegacyExistingChainFragment(t *testing.T) {
	svc := &Service{
		cfg:       DefaultConfig(),
		filter:    ResolvedFilter{DstPort: 16210},
		assembler: httptrace.NewAssembler(1<<20, time.Minute, 500*time.Millisecond),
		stats:     &stats{},
	}

	_, err := svc.assembler.Process(httptrace.Event{
		ChainID:   99,
		FD:        10,
		Direction: httptrace.DirectionRequest,
		Payload:   []byte("GET /x HTTP/1.1\r\nHost: example.com\r\n"),
	})
	if err != nil {
		t.Fatalf("seed assembler state failed: %v", err)
	}

	ch := make(chan httptrace.Event, 1)
	event := httptrace.Event{
		ChainID:   99,
		FD:        10,
		Direction: httptrace.DirectionResponse,
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   50000,
		DstPort:   50001,
	}

	if err := svc.dispatchEvent(context.Background(), event, ch); err != nil {
		t.Fatalf("dispatchEvent returned error: %v", err)
	}

	select {
	case <-ch:
	default:
		t.Fatalf("expected existing-chain fragment to pass through")
	}
}

func TestResolveEventBypassesUserTuplePipeline(t *testing.T) {
	svc := &Service{
		cfg:      Config{DisableUserTuple: true},
		resolver: newSocketResolver(time.Second),
		stats:    &stats{},
	}

	event := httptrace.Event{
		PID:       123,
		FD:        7,
		Direction: httptrace.DirectionRequest,
		SrcIP:     "0.0.0.0",
		DstIP:     "0.0.0.0",
	}

	got, source := svc.resolveEvent(event)
	if source != resolveBypass {
		t.Fatalf("expected resolveBypass, got %v", source)
	}
	if got.PID != event.PID || got.FD != event.FD || got.Direction != event.Direction || got.SrcIP != event.SrcIP || got.DstIP != event.DstIP {
		t.Fatalf("event should stay unchanged when tuple pipeline disabled: got=%#v want=%#v", got, event)
	}
}

func TestSanitizeTraceForOutputHidesTuple(t *testing.T) {
	svc := &Service{cfg: Config{DisableUserTuple: true}}
	trace := httptrace.TraceDocument{
		ChainID: 1,
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 1234,
		DstPort: 80,
	}

	got := svc.sanitizeTraceForOutput(trace)
	if got.SrcIP != "" || got.DstIP != "" || got.SrcPort != 0 || got.DstPort != 0 {
		t.Fatalf("tuple fields should be cleared, got %#v", got)
	}
}
