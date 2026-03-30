package httptrace

import (
	"testing"
	"time"
)

func TestAssemblerEmitsPartialResponseOnClose(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute)
	now := time.Unix(1711717000, 0)

	reqUpdates, err := asm.Process(Event{
		Timestamp: now,
		ChainID:   1001,
		PID:       42,
		FD:        7,
		SrcIP:     "192.168.4.161",
		DstIP:     "192.168.4.1",
		SrcPort:   12581,
		DstPort:   51060,
		FragIdx:   0,
		Direction: DirectionRequest,
		Payload:   []byte("GET /api/module HTTP/1.1\r\nHost: 192.168.4.161:12581\r\n\r\n"),
	})
	if err != nil {
		t.Fatalf("process request: %v", err)
	}
	if len(reqUpdates) != 1 || reqUpdates[0].Kind != "request" {
		t.Fatalf("expected one request update, got %#v", reqUpdates)
	}

	respUpdates, err := asm.Process(Event{
		Timestamp: now.Add(12 * time.Millisecond),
		ChainID:   1001,
		PID:       42,
		FD:        7,
		SrcIP:     "192.168.4.161",
		DstIP:     "192.168.4.1",
		SrcPort:   12581,
		DstPort:   51060,
		FragIdx:   0,
		Direction: DirectionResponse,
		Payload:   []byte("HTTP/1.1 200 OK\r\nContent-Length: 12\r\nContent-Type: application/json\r\n\r\n{\"ok\""),
	})
	if err != nil {
		t.Fatalf("process response: %v", err)
	}
	if len(respUpdates) != 0 {
		t.Fatalf("partial response should wait for eof/truncation, got %#v", respUpdates)
	}

	respUpdates, err = asm.Process(Event{
		Timestamp: now.Add(20 * time.Millisecond),
		ChainID:   1001,
		Flags:     (1 << 4) | (1 << 5),
	})
	if err != nil {
		t.Fatalf("finalize response: %v", err)
	}
	if len(respUpdates) != 1 || respUpdates[0].Kind != "response" {
		t.Fatalf("expected one response update after close, got %#v", respUpdates)
	}
	if respUpdates[0].Trace.Response == nil {
		t.Fatalf("response payload should be present")
	}
	if respUpdates[0].Trace.Request != nil {
		t.Fatalf("response update should not carry request payload")
	}
	if !respUpdates[0].Trace.Response.BodyPartial {
		t.Fatalf("response should be marked partial")
	}
	if respUpdates[0].Trace.ResponseLatency == nil || *respUpdates[0].Trace.ResponseLatency <= 0 {
		t.Fatalf("response latency should be calculated")
	}
}
