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

func TestAssemblerEmitsMultipleMessagesFromSingleChain(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute)
	now := time.Unix(1711717000, 0)

	reqRaw := []byte(
		"GET /api/a HTTP/1.1\r\nHost: example.com\r\n\r\n" +
			"GET /api/b HTTP/1.1\r\nHost: example.com\r\n\r\n",
	)
	reqUpdates, err := asm.Process(Event{
		Timestamp: now,
		ChainID:   2001,
		PID:       77,
		FD:        9,
		SrcIP:     "192.168.4.1",
		DstIP:     "192.168.4.161",
		SrcPort:   51060,
		DstPort:   12581,
		FragIdx:   0,
		Direction: DirectionRequest,
		Payload:   reqRaw,
	})
	if err != nil {
		t.Fatalf("process requests: %v", err)
	}
	if len(reqUpdates) != 2 {
		t.Fatalf("expected 2 request updates, got %d", len(reqUpdates))
	}
	if reqUpdates[0].Trace.ChainID == reqUpdates[1].Trace.ChainID {
		t.Fatalf("logical chain ids should differ for multiple requests on one base chain")
	}
	if got, want := reqUpdates[0].Trace.Request.URL, "/api/a"; got != want {
		t.Fatalf("first request url mismatch: got %q want %q", got, want)
	}
	if got, want := reqUpdates[1].Trace.Request.URL, "/api/b"; got != want {
		t.Fatalf("second request url mismatch: got %q want %q", got, want)
	}

	respRaw := []byte(
		"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na" +
			"HTTP/1.1 201 Created\r\nContent-Length: 1\r\n\r\nb",
	)
	respUpdates, err := asm.Process(Event{
		Timestamp: now.Add(10 * time.Millisecond),
		ChainID:   2001,
		PID:       77,
		FD:        9,
		SrcIP:     "192.168.4.161",
		DstIP:     "192.168.4.1",
		SrcPort:   12581,
		DstPort:   51060,
		FragIdx:   0,
		Direction: DirectionResponse,
		Payload:   respRaw,
	})
	if err != nil {
		t.Fatalf("process responses: %v", err)
	}
	if len(respUpdates) != 2 {
		t.Fatalf("expected 2 response updates, got %d", len(respUpdates))
	}
	if respUpdates[0].Trace.ChainID != reqUpdates[0].Trace.ChainID {
		t.Fatalf("first response should match first request chain id")
	}
	if respUpdates[1].Trace.ChainID != reqUpdates[1].Trace.ChainID {
		t.Fatalf("second response should match second request chain id")
	}
	if got, want := respUpdates[1].Trace.Response.StatusCode, 201; got != want {
		t.Fatalf("second response status mismatch: got %d want %d", got, want)
	}
}

func TestAssemblerResyncsRequestAfterLeadingJunk(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute)
	now := time.Unix(1711717000, 0)

	updates, err := asm.Process(Event{
		Timestamp: now,
		ChainID:   3001,
		PID:       88,
		FD:        11,
		SrcIP:     "192.168.4.1",
		DstIP:     "192.168.4.161",
		SrcPort:   52000,
		DstPort:   12581,
		FragIdx:   0,
		Direction: DirectionRequest,
		Payload:   []byte("xxGET /api/resync HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	})
	if err != nil {
		t.Fatalf("process request: %v", err)
	}
	if len(updates) != 1 {
		t.Fatalf("expected one resynced request update, got %d", len(updates))
	}
	if got, want := updates[0].Trace.Request.URL, "/api/resync"; got != want {
		t.Fatalf("resynced url mismatch: got %q want %q", got, want)
	}
}
