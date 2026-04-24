package httptrace

import (
	"testing"
	"time"
)

// 测试请求完整后立即返回 update，响应完整后再返回完整链路 update
func TestAssemblerEmitsPartialResponseOnClose(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 500*time.Millisecond)
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

// 测试同一个 chain_id 上多个请求/响应片段的聚合
func TestAssemblerEmitsMultipleMessagesFromSingleChain(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 500*time.Millisecond)
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
	asm := NewAssembler(1<<20, time.Minute, 500*time.Millisecond)
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

func TestAssemblerFlushesPartialResponseWhenNextRequestArrives(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 500*time.Millisecond)
	now := time.Unix(1711717000, 0)

	req1, err := asm.Process(Event{
		Timestamp: now,
		ChainID:   4001,
		PID:       99,
		FD:        12,
		SrcIP:     "192.168.4.1",
		DstIP:     "192.168.4.161",
		SrcPort:   53000,
		DstPort:   12581,
		FragIdx:   0,
		Direction: DirectionRequest,
		Payload:   []byte("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	})
	if err != nil || len(req1) != 1 {
		t.Fatalf("first request emit failed: updates=%d err=%v", len(req1), err)
	}

	if updates, err := asm.Process(Event{
		Timestamp: now.Add(10 * time.Millisecond),
		ChainID:   4001,
		PID:       99,
		FD:        12,
		Direction: DirectionResponse,
		FragIdx:   0,
		Payload:   []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"),
	}); err != nil || len(updates) != 0 {
		t.Fatalf("partial first response should wait: updates=%d err=%v", len(updates), err)
	}

	updates, err := asm.Process(Event{
		Timestamp: now.Add(20 * time.Millisecond),
		ChainID:   4001,
		PID:       99,
		FD:        12,
		SrcIP:     "192.168.4.1",
		DstIP:     "192.168.4.161",
		SrcPort:   53000,
		DstPort:   12581,
		FragIdx:   1,
		Direction: DirectionRequest,
		Payload:   []byte("GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	})
	if err != nil {
		t.Fatalf("second request process failed: %v", err)
	}
	if len(updates) != 2 {
		t.Fatalf("expected flushed response + second request, got %d updates", len(updates))
	}
	if updates[0].Kind != "request" && updates[1].Kind != "response" && updates[0].Kind != "response" {
		t.Fatalf("unexpected update kinds: %#v", updates)
	}

	var sawResponse bool
	var sawRequest bool
	for _, update := range updates {
		if update.Kind == "response" {
			sawResponse = true
			if !update.Trace.ResponseTruncated {
				t.Fatalf("partial response should be marked truncated")
			}
		}
		if update.Kind == "request" && update.Trace.Request != nil && update.Trace.Request.URL == "/b" {
			sawRequest = true
		}
	}
	if !sawResponse || !sawRequest {
		t.Fatalf("expected both partial response and second request, got %#v", updates)
	}
}

func TestAssemblerFlushesStalledPartialResponse(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 100*time.Millisecond)
	now := time.Unix(1711717000, 0)

	reqUpdates, err := asm.Process(Event{
		Timestamp: now,
		ChainID:   5001,
		PID:       100,
		FD:        13,
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   54000,
		DstPort:   80,
		FragIdx:   0,
		Direction: DirectionRequest,
		Payload:   []byte("GET /nginx HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	})
	if err != nil || len(reqUpdates) != 1 {
		t.Fatalf("request emit failed: updates=%d err=%v", len(reqUpdates), err)
	}

	respUpdates, err := asm.Process(Event{
		Timestamp: now.Add(10 * time.Millisecond),
		ChainID:   5001,
		PID:       100,
		FD:        13,
		SrcIP:     "10.0.0.2",
		DstIP:     "10.0.0.1",
		SrcPort:   80,
		DstPort:   54000,
		FragIdx:   0,
		Direction: DirectionResponse,
		Payload:   []byte("HTTP/1.1 200 OK\r\nContent-Length: 20\r\nContent-Type: text/plain\r\n\r\nhello"),
	})
	if err != nil {
		t.Fatalf("response process failed: %v", err)
	}
	if len(respUpdates) != 0 {
		t.Fatalf("partial response should wait before stall flush, got %#v", respUpdates)
	}

	flushed := asm.FlushStalled(time.Now().Add(200 * time.Millisecond))
	if len(flushed) != 1 {
		t.Fatalf("expected one stalled response flush, got %d", len(flushed))
	}
	if flushed[0].Kind != "response" || flushed[0].Trace.Response == nil {
		t.Fatalf("expected one response update, got %#v", flushed)
	}
	if !flushed[0].Trace.ResponseTruncated || !flushed[0].Trace.Response.BodyPartial {
		t.Fatalf("stalled flush should mark response partial/truncated")
	}
}

func TestAssemblerEvictExpiredFlushesPartialResponse(t *testing.T) {
	asm := NewAssembler(1<<20, 100*time.Millisecond, 500*time.Millisecond)
	now := time.Now()

	reqUpdates, err := asm.Process(Event{
		Timestamp: now,
		ChainID:   6001,
		PID:       101,
		FD:        14,
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   54001,
		DstPort:   80,
		FragIdx:   0,
		Direction: DirectionRequest,
		Payload:   []byte("GET /expire HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	})
	if err != nil || len(reqUpdates) != 1 {
		t.Fatalf("request emit failed: updates=%d err=%v", len(reqUpdates), err)
	}

	respUpdates, err := asm.Process(Event{
		Timestamp: now.Add(10 * time.Millisecond),
		ChainID:   6001,
		PID:       101,
		FD:        14,
		SrcIP:     "10.0.0.2",
		DstIP:     "10.0.0.1",
		SrcPort:   80,
		DstPort:   54001,
		FragIdx:   0,
		Direction: DirectionResponse,
		Payload:   []byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 20\r\n\r\nbad"),
	})
	if err != nil {
		t.Fatalf("response process failed: %v", err)
	}
	if len(respUpdates) != 1 {
		t.Fatalf("error response should be eagerly flushed, got %#v", respUpdates)
	}
	if respUpdates[0].Kind != "response" || respUpdates[0].Trace.Response == nil {
		t.Fatalf("expected response update, got %#v", respUpdates)
	}
	if !respUpdates[0].Trace.ResponseTruncated || !respUpdates[0].Trace.Response.BodyPartial {
		t.Fatalf("eager error flush should mark response partial/truncated")
	}

	evictedUpdates, evicted := asm.EvictExpired(now.Add(200 * time.Millisecond))
	if evicted != 0 {
		t.Fatalf("state should already be closed after eager error flush, got evicted=%d", evicted)
	}
	if len(evictedUpdates) != 0 {
		t.Fatalf("did not expect extra eviction updates, got %#v", evictedUpdates)
	}
}

func TestAssemblerDefersResponseUntilRequestArrives(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 500*time.Millisecond)
	now := time.Unix(1711717000, 0)

	respUpdates, err := asm.Process(Event{
		Timestamp: now.Add(10 * time.Millisecond),
		ChainID:   7001,
		PID:       102,
		FD:        15,
		SrcIP:     "10.0.0.2",
		DstIP:     "10.0.0.1",
		SrcPort:   80,
		DstPort:   54002,
		FragIdx:   0,
		Direction: DirectionResponse,
		Payload:   []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
	})
	if err != nil {
		t.Fatalf("response-first process failed: %v", err)
	}
	if len(respUpdates) != 0 {
		t.Fatalf("response should wait for matching request, got %#v", respUpdates)
	}

	snap := asm.Snapshot()
	if snap.DeferredResponses == 0 {
		t.Fatalf("expected deferred response counter to increase")
	}
	if snap.OrphanResponses != 0 {
		t.Fatalf("response should not be marked orphan before request arrives")
	}

	updates, err := asm.Process(Event{
		Timestamp: now,
		ChainID:   7001,
		PID:       102,
		FD:        15,
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   54002,
		DstPort:   80,
		FragIdx:   0,
		Direction: DirectionRequest,
		Payload:   []byte("GET /late HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	})
	if err != nil {
		t.Fatalf("request-after-response process failed: %v", err)
	}
	if len(updates) != 2 {
		t.Fatalf("expected request + matched response, got %d updates", len(updates))
	}
	if updates[0].Kind != "request" || updates[1].Kind != "response" {
		t.Fatalf("unexpected update order: %#v", updates)
	}
	if updates[1].Trace.Response == nil || updates[1].Trace.Response.StatusCode != 200 {
		t.Fatalf("expected parsed response, got %#v", updates[1].Trace.Response)
	}

	snap = asm.Snapshot()
	if snap.PendingRequests != 0 || snap.PendingNoRespBytes != 0 {
		t.Fatalf("all pending requests should be matched after late request arrives: %#v", snap)
	}
	if snap.OrphanResponses != 0 {
		t.Fatalf("should not accumulate orphan responses after successful rematch")
	}
}

func TestAssemblerResyncsResponseAfterLeadingJunk(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 500*time.Millisecond)
	now := time.Unix(1711718000, 0)

	reqUpdates, err := asm.Process(Event{
		Timestamp: now,
		ChainID:   8001,
		PID:       103,
		FD:        16,
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   54003,
		DstPort:   80,
		FragIdx:   0,
		Direction: DirectionRequest,
		Payload:   []byte("GET /broken HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	})
	if err != nil || len(reqUpdates) != 1 {
		t.Fatalf("request emit failed: updates=%d err=%v", len(reqUpdates), err)
	}

	respUpdates, err := asm.Process(Event{
		Timestamp: now.Add(10 * time.Millisecond),
		ChainID:   8001,
		PID:       103,
		FD:        16,
		SrcIP:     "10.0.0.2",
		DstIP:     "10.0.0.1",
		SrcPort:   80,
		DstPort:   54003,
		FragIdx:   0,
		Direction: DirectionResponse,
		Payload:   []byte("junkHTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nbad"),
	})
	if err != nil {
		t.Fatalf("response process failed: %v", err)
	}
	if len(respUpdates) != 1 {
		t.Fatalf("expected one resynced response update, got %d", len(respUpdates))
	}
	if respUpdates[0].Trace.Response == nil {
		t.Fatalf("expected parsed response")
	}
	if got, want := respUpdates[0].Trace.Response.StatusCode, 404; got != want {
		t.Fatalf("status code = %d, want %d", got, want)
	}
	if got, want := respUpdates[0].Trace.Response.Body, "bad"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}
func TestAssemblerEagerFlushesErrorResponse(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 500*time.Millisecond)
	now := time.Unix(1711719000, 0)

	reqUpdates, err := asm.Process(Event{
		Timestamp: now,
		ChainID:   9001,
		PID:       104,
		FD:        17,
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   54004,
		DstPort:   80,
		FragIdx:   0,
		Direction: DirectionRequest,
		Payload:   []byte("GET /missing HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	})
	if err != nil || len(reqUpdates) != 1 {
		t.Fatalf("request emit failed: updates=%d err=%v", len(reqUpdates), err)
	}

	respUpdates, err := asm.Process(Event{
		Timestamp: now.Add(10 * time.Millisecond),
		ChainID:   9001,
		PID:       104,
		FD:        17,
		SrcIP:     "10.0.0.2",
		DstIP:     "10.0.0.1",
		SrcPort:   80,
		DstPort:   54004,
		FragIdx:   0,
		Direction: DirectionResponse,
		Payload:   []byte("HTTP/1.1 404 Not Found\r\nContent-Length: 100\r\nContent-Type: text/html\r\n\r\n<html>bad"),
	})
	if err != nil {
		t.Fatalf("response process failed: %v", err)
	}
	if len(respUpdates) != 1 {
		t.Fatalf("expected eager response flush, got %d", len(respUpdates))
	}
	if respUpdates[0].Trace.Response == nil {
		t.Fatalf("expected response payload")
	}
	if got, want := respUpdates[0].Trace.Response.StatusCode, 404; got != want {
		t.Fatalf("status code = %d, want %d", got, want)
	}
	if !respUpdates[0].Trace.ResponseTruncated || !respUpdates[0].Trace.Response.BodyPartial {
		t.Fatalf("error response should be marked partial/truncated")
	}
}
