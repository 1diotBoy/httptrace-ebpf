package httptrace

import (
	"fmt"
	"strings"
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

// 测试下一个请求到达时，flush 部分响应, 并重新组装请求和响应, 确保响应和请求的完整性
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
			// 部分响应应该被标记为截断
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

func TestAssemblerWaitsLongerForChunkedResponse(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 500*time.Millisecond)
	now := time.Unix(1711717050, 0)

	reqUpdates, err := asm.Process(Event{
		Timestamp: now,
		ChainID:   5002,
		PID:       100,
		FD:        13,
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   54000,
		DstPort:   80,
		FragIdx:   0,
		Direction: DirectionRequest,
		Payload:   []byte("GET /chunked HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	})
	if err != nil || len(reqUpdates) != 1 {
		t.Fatalf("request emit failed: updates=%d err=%v", len(reqUpdates), err)
	}

	respUpdates, err := asm.Process(Event{
		Timestamp: now.Add(10 * time.Millisecond),
		ChainID:   5002,
		PID:       100,
		FD:        13,
		SrcIP:     "10.0.0.2",
		DstIP:     "10.0.0.1",
		SrcPort:   80,
		DstPort:   54000,
		FragIdx:   0,
		Direction: DirectionResponse,
		Payload:   []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n"),
	})
	if err != nil {
		t.Fatalf("response process failed: %v", err)
	}
	if len(respUpdates) != 0 {
		t.Fatalf("partial chunked response should wait for more body, got %#v", respUpdates)
	}

	flushed := asm.FlushStalled(time.Now().Add(700 * time.Millisecond))
	if len(flushed) != 0 {
		t.Fatalf("chunked response should not be stalled-flushed too early, got %#v", flushed)
	}

	respUpdates, err = asm.Process(Event{
		Timestamp: now.Add(800 * time.Millisecond),
		ChainID:   5002,
		PID:       100,
		FD:        13,
		SrcIP:     "10.0.0.2",
		DstIP:     "10.0.0.1",
		SrcPort:   80,
		DstPort:   54000,
		FragIdx:   1,
		Direction: DirectionResponse,
		Payload:   []byte("5\r\npedia\r\n0\r\n\r\n"),
	})
	if err != nil {
		t.Fatalf("response completion failed: %v", err)
	}
	if len(respUpdates) != 1 || respUpdates[0].Kind != "response" {
		t.Fatalf("expected one completed response update, got %#v", respUpdates)
	}
	if respUpdates[0].Trace.Response == nil {
		t.Fatalf("expected parsed response")
	}
	if respUpdates[0].Trace.ResponseTruncated || respUpdates[0].Trace.Response.BodyPartial {
		t.Fatalf("completed chunked response should not be marked partial/truncated")
	}
	if got, want := respUpdates[0].Trace.Response.Body, "Wikipedia"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestAssemblerTreatsChunkedResponseMissingFinalTrailerCRLFAsCompleteEnough(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 500*time.Millisecond)
	now := time.Unix(1711717055, 0)

	reqUpdates, err := asm.Process(Event{
		Timestamp: now,
		ChainID:   5003,
		PID:       100,
		FD:        13,
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   54000,
		DstPort:   80,
		FragIdx:   0,
		Direction: DirectionRequest,
		Payload:   []byte("GET /chunked HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	})
	if err != nil || len(reqUpdates) != 1 {
		t.Fatalf("request emit failed: updates=%d err=%v", len(reqUpdates), err)
	}

	body := `{"errCode":"-100","errMsg":"forbidden"}`
	raw := []byte(fmt.Sprintf(
		"HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n",
		len(body), body,
	))
	respUpdates, err := asm.Process(Event{
		Timestamp: now.Add(10 * time.Millisecond),
		ChainID:   5003,
		PID:       100,
		FD:        13,
		SrcIP:     "10.0.0.2",
		DstIP:     "10.0.0.1",
		SrcPort:   80,
		DstPort:   54000,
		FragIdx:   0,
		Direction: DirectionResponse,
		Payload:   raw,
	})
	if err != nil {
		t.Fatalf("response process failed: %v", err)
	}
	if len(respUpdates) != 1 || respUpdates[0].Kind != "response" {
		t.Fatalf("expected one completed response update, got %#v", respUpdates)
	}
	if respUpdates[0].Trace.Response == nil {
		t.Fatalf("expected parsed response")
	}
	if respUpdates[0].Trace.ResponseTruncated || respUpdates[0].Trace.Response.BodyPartial {
		t.Fatalf("response should not be marked partial/truncated when only final trailer CRLF is missing")
	}
	if got, want := respUpdates[0].Trace.Response.Body, body; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestAssemblerSyntheticChunkedFallbackDoesNotForceTruncatedWhenBodyIsComplete(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 50*time.Millisecond)
	now := time.Now()

	reqUpdates, err := asm.Process(Event{
		Timestamp: now,
		ChainID:   5004,
		PID:       100,
		FD:        13,
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   54000,
		DstPort:   80,
		FragIdx:   0,
		Direction: DirectionRequest,
		Payload:   []byte("GET /forbidden HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	})
	if err != nil || len(reqUpdates) != 1 {
		t.Fatalf("request emit failed: updates=%d err=%v", len(reqUpdates), err)
	}

	body := `{"errCode":"-100","errMsg":"forbidden"}`
	raw := []byte(fmt.Sprintf("HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(body), body))
	respUpdates, err := asm.Process(Event{
		Timestamp: now.Add(10 * time.Millisecond),
		ChainID:   5004,
		PID:       100,
		FD:        13,
		SrcIP:     "10.0.0.2",
		DstIP:     "10.0.0.1",
		SrcPort:   80,
		DstPort:   54000,
		FragIdx:   0,
		Direction: DirectionResponse,
		Payload:   raw,
	})
	if err != nil {
		t.Fatalf("response process failed: %v", err)
	}
	if len(respUpdates) != 0 {
		t.Fatalf("expected stalled path to flush later, got %#v", respUpdates)
	}

	flushed := asm.FlushStalled(now.Add(6 * time.Second))
	if len(flushed) != 1 || flushed[0].Kind != "response" {
		t.Fatalf("expected one flushed response update, got %#v", flushed)
	}
	if flushed[0].Trace.Response == nil {
		t.Fatalf("expected parsed response")
	}
	if flushed[0].Trace.ResponseTruncated || flushed[0].Trace.Response.BodyPartial {
		t.Fatalf("synthetic chunked fallback should not force partial/truncated when body is complete")
	}
	if got, want := flushed[0].Trace.Response.Body, body; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestAssemblerWaitsLongerForConnectionCloseErrorResponse(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 500*time.Millisecond)
	now := time.Now()

	reqUpdates, err := asm.Process(Event{
		Timestamp: now,
		ChainID:   5005,
		PID:       100,
		FD:        13,
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   54000,
		DstPort:   80,
		FragIdx:   0,
		Direction: DirectionRequest,
		Payload:   []byte("GET /bad-gateway HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	})
	if err != nil || len(reqUpdates) != 1 {
		t.Fatalf("request emit failed: updates=%d err=%v", len(reqUpdates), err)
	}

	respUpdates, err := asm.Process(Event{
		Timestamp: now.Add(10 * time.Millisecond),
		ChainID:   5005,
		PID:       100,
		FD:        13,
		SrcIP:     "10.0.0.2",
		DstIP:     "10.0.0.1",
		SrcPort:   80,
		DstPort:   54000,
		FragIdx:   0,
		Direction: DirectionResponse,
		Payload:   []byte("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\nbad"),
	})
	if err != nil {
		t.Fatalf("response process failed: %v", err)
	}
	if len(respUpdates) != 1 || respUpdates[0].Kind != "response" {
		t.Fatalf("connection-close error response should complete immediately, got %#v", respUpdates)
	}
	if respUpdates[0].Trace.Response == nil {
		t.Fatalf("expected parsed response")
	}
	if respUpdates[0].Trace.ResponseTruncated || respUpdates[0].Trace.Response.BodyPartial {
		t.Fatalf("connection-close error response should not be marked partial/truncated")
	}
}

// 如果 observed message bytes 比 payload 长，则认为 response 是完整的
func TestAssemblerStalledChunkedResponseMissingOnlyTrailerFramingIsNotMarkedTruncated(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 500*time.Millisecond)
	now := time.Now()

	reqUpdates, err := asm.Process(Event{
		Timestamp: now,
		ChainID:   5007,
		PID:       100,
		FD:        13,
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   54000,
		DstPort:   80,
		FragIdx:   0,
		Direction: DirectionRequest,
		Payload:   []byte("GET /forbidden HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	})
	if err != nil || len(reqUpdates) != 1 {
		t.Fatalf("request emit failed: updates=%d err=%v", len(reqUpdates), err)
	}

	body := `{"errCode":"-100","errMsg":"forbidden"}`
	payload := []byte(fmt.Sprintf(
		"HTTP/1.1 200 \r\nServer: POWERLBS\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n%x\r\n%s",
		len(body), body,
	))
	respUpdates, err := asm.Process(Event{
		Timestamp:            now.Add(10 * time.Millisecond),
		ChainID:              5007,
		PID:                  100,
		FD:                   13,
		SrcIP:                "10.0.0.2",
		DstIP:                "10.0.0.1",
		SrcPort:              80,
		DstPort:              54000,
		FragIdx:              0,
		Direction:            DirectionResponse,
		ObservedMessageBytes: uint64(len(payload) + 7),
		Payload:              payload,
	})
	if err != nil {
		t.Fatalf("response process failed: %v", err)
	}
	if len(respUpdates) != 0 {
		t.Fatalf("response should wait for stalled flush, got %#v", respUpdates)
	}

	flushed := asm.FlushStalled(now.Add(6 * time.Second))
	if len(flushed) != 1 || flushed[0].Kind != "response" {
		t.Fatalf("expected one stalled response update, got %#v", flushed)
	}
	if flushed[0].Trace.Response == nil {
		t.Fatalf("expected parsed response")
	}
	if flushed[0].Trace.ResponseTruncated || flushed[0].Trace.Response.BodyPartial {
		t.Fatalf("response should not be marked partial/truncated when only trailer framing is missing")
	}
	if got, want := flushed[0].Trace.Response.Body, body; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

// 如果 observed message bytes 比 payload 长，则认为 response 是完整的
func TestAssemblerStalledChunkedResponseWithObservedTailGapIsNotMarkedTruncated(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 500*time.Millisecond)
	now := time.Now()

	reqUpdates, err := asm.Process(Event{
		Timestamp: now,
		ChainID:   5008,
		PID:       100,
		FD:        13,
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   54000,
		DstPort:   80,
		FragIdx:   0,
		Direction: DirectionRequest,
		Payload:   []byte("GET /captcha HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	})
	if err != nil || len(reqUpdates) != 1 {
		t.Fatalf("request emit failed: updates=%d err=%v", len(reqUpdates), err)
	}

	body := `{"errCode":"-100","errMsg":"forbidden"}`
	payload := []byte(fmt.Sprintf(
		"HTTP/1.1 200 \r\nServer: POWERLBS\r\nDate: Fri, 05 Jun 2026 15:33:16 GMT\r\nContent-Type: application/json;charset=utf-8\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n%x\r\n%s0\r\n\r\n",
		len(body), body,
	))
	if len(payload) < 3 {
		t.Fatalf("payload too short: %d", len(payload))
	}
	respUpdates, err := asm.Process(Event{
		Timestamp:            now.Add(10 * time.Millisecond),
		ChainID:              5008,
		PID:                  100,
		FD:                   13,
		SrcIP:                "10.0.0.2",
		DstIP:                "10.0.0.1",
		SrcPort:              80,
		DstPort:              54000,
		FragIdx:              0,
		Direction:            DirectionResponse,
		ObservedMessageBytes: uint64(len(payload)),
		Payload:              payload[:len(payload)-2],
	})
	if err != nil {
		t.Fatalf("response process failed: %v", err)
	}
	var update Update
	switch len(respUpdates) {
	case 1:
		update = respUpdates[0]
	case 0:
		flushed := asm.FlushStalled(now.Add(6 * time.Second))
		if len(flushed) != 1 || flushed[0].Kind != "response" {
			t.Fatalf("expected one response update, got %#v / %#v", respUpdates, flushed)
		}
		update = flushed[0]
	default:
		t.Fatalf("unexpected immediate response updates: %#v", respUpdates)
	}
	if update.Trace.Response == nil {
		t.Fatalf("expected parsed response")
	}
	if update.Trace.ResponseTruncated || update.Trace.Response.BodyPartial {
		t.Fatalf("response should not be marked partial/truncated when only tail framing bytes are missing")
	}
	if got, want := update.Trace.Response.Body, body; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestAssemblerEmitsTruncatedResponseOnFinalSizeOnlyEvent(t *testing.T) {
	asm := NewAssembler(32*1024, time.Minute, 500*time.Millisecond)
	now := time.Unix(1711717060, 0)

	reqUpdates, err := asm.Process(Event{
		Timestamp: now,
		ChainID:   5100,
		PID:       100,
		FD:        13,
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   54000,
		DstPort:   80,
		FragIdx:   0,
		Direction: DirectionRequest,
		Payload:   []byte("GET /large HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	})
	if err != nil || len(reqUpdates) != 1 {
		t.Fatalf("request emit failed: updates=%d err=%v", len(reqUpdates), err)
	}

	respUpdates, err := asm.Process(Event{
		Timestamp:            now.Add(10 * time.Millisecond),
		ChainID:              5100,
		PID:                  100,
		FD:                   13,
		SrcIP:                "10.0.0.2",
		DstIP:                "10.0.0.1",
		SrcPort:              80,
		DstPort:              54000,
		FragIdx:              0,
		Direction:            DirectionResponse,
		Flags:                eventFlagCaptureTrunc,
		ObservedMessageBytes: 32 * 1024,
		Payload:              []byte("HTTP/1.1 200 OK\r\nContent-Length: 100000\r\nContent-Type: text/plain\r\n\r\nhello"),
	})
	if err != nil {
		t.Fatalf("response process failed: %v", err)
	}
	if len(respUpdates) != 0 {
		t.Fatalf("truncated response should wait for final size event, got %#v", respUpdates)
	}

	respUpdates, err = asm.Process(Event{
		Timestamp:            now.Add(20 * time.Millisecond),
		ChainID:              5100,
		PID:                  100,
		FD:                   13,
		SrcIP:                "10.0.0.2",
		DstIP:                "10.0.0.1",
		SrcPort:              80,
		DstPort:              54000,
		Direction:            DirectionResponse,
		Flags:                eventFlagSizeOnly | eventFlagEnd,
		ObservedMessageBytes: 128 * 1024,
	})
	if err != nil {
		t.Fatalf("final size-only process failed: %v", err)
	}
	if len(respUpdates) != 1 || respUpdates[0].Kind != "response" {
		t.Fatalf("expected one response update, got %#v", respUpdates)
	}
	if respUpdates[0].Trace.Response == nil {
		t.Fatalf("expected response payload")
	}
	if !respUpdates[0].Trace.ResponseTruncated || !respUpdates[0].Trace.Response.BodyPartial {
		t.Fatalf("response should be marked partial/truncated")
	}
	if got, want := respUpdates[0].Trace.Response.ObservedMessageBytes, uint64(128*1024); got != want {
		t.Fatalf("observed bytes = %d, want %d", got, want)
	}
	if got, want := respUpdates[0].Trace.Response.Body, "hello"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
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
	if len(respUpdates) != 0 {
		t.Fatalf("body-carrying error response should wait for later flush, got %#v", respUpdates)
	}
	evictedUpdates, evicted := asm.EvictExpired(now.Add(200 * time.Millisecond))
	if evicted != 1 {
		t.Fatalf("state should be evicted once idle expires, got evicted=%d", evicted)
	}
	if len(evictedUpdates) != 1 || evictedUpdates[0].Kind != "response" {
		t.Fatalf("expected one eviction flush update, got %#v", evictedUpdates)
	}
	if evictedUpdates[0].Trace.Response == nil {
		t.Fatalf("expected response payload")
	}
	if evictedUpdates[0].Trace.ResponseTruncated {
		t.Fatalf("502 response should not be marked truncated")
	}
	if !evictedUpdates[0].Trace.Response.BodyPartial {
		t.Fatalf("expected partial body marker to remain for incomplete 502 response")
	}
}

func TestAssemblerReleasesIncompleteFragmentsOnEviction(t *testing.T) {
	asm := NewAssembler(1<<20, time.Millisecond, 500*time.Millisecond)
	asm.SetMaxRetainedBytes(1024)
	payload := []byte("POST /hold HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4096\r\n\r\n" + strings.Repeat("x", 128))

	if _, err := asm.Process(Event{
		Timestamp: time.Now(),
		ChainID:   8801,
		Direction: DirectionRequest,
		Payload:   payload,
	}); err != nil {
		t.Fatalf("process incomplete request: %v", err)
	}
	if got := asm.Snapshot().RetainedBytes; got != uint64(len(payload)) {
		t.Fatalf("retained bytes after incomplete request: got %d want %d", got, len(payload))
	}

	if _, evicted := asm.EvictExpired(time.Now().Add(time.Second)); evicted != 1 {
		t.Fatalf("evicted states: got %d want 1", evicted)
	}
	if got := asm.Snapshot().RetainedBytes; got != 0 {
		t.Fatalf("retained bytes after eviction: got %d want 0", got)
	}
}

func TestAssemblerRejectsFragmentsAboveGlobalRetentionBudget(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 500*time.Millisecond)
	asm.SetMaxRetainedBytes(64)

	if _, err := asm.Process(Event{
		Timestamp: time.Now(),
		ChainID:   8802,
		Direction: DirectionRequest,
		Payload:   []byte(strings.Repeat("x", 128)),
	}); err != nil {
		t.Fatalf("process over-budget fragment: %v", err)
	}
	snap := asm.Snapshot()
	if snap.RetainedBytes != 0 {
		t.Fatalf("over-budget fragment retained %d bytes", snap.RetainedBytes)
	}
	if snap.BufferDrops != 1 {
		t.Fatalf("over-budget fragment drops: got %d want 1", snap.BufferDrops)
	}
}

func TestAssemblerFlushStalledTruncatedResponseWithoutFinalSizeEvent(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 100*time.Millisecond)
	now := time.Now()

	reqUpdates, err := asm.Process(Event{
		Timestamp: now,
		ChainID:   6101,
		PID:       101,
		FD:        14,
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   54001,
		DstPort:   80,
		FragIdx:   0,
		Direction: DirectionRequest,
		Payload:   []byte("GET /stall HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	})
	if err != nil || len(reqUpdates) != 1 {
		t.Fatalf("request emit failed: updates=%d err=%v", len(reqUpdates), err)
	}

	respUpdates, err := asm.Process(Event{
		Timestamp:            now.Add(10 * time.Millisecond),
		ChainID:              6101,
		PID:                  101,
		FD:                   14,
		SrcIP:                "10.0.0.2",
		DstIP:                "10.0.0.1",
		SrcPort:              80,
		DstPort:              54001,
		FragIdx:              0,
		Direction:            DirectionResponse,
		Flags:                eventFlagCaptureTrunc,
		ObservedMessageBytes: 32 * 1024,
		Payload:              []byte("HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\nhello"),
	})
	if err != nil {
		t.Fatalf("response process failed: %v", err)
	}
	if len(respUpdates) != 0 {
		t.Fatalf("truncated response should still wait for stall/final signal, got %#v", respUpdates)
	}

	respUpdates, err = asm.Process(Event{
		Timestamp:            now.Add(20 * time.Millisecond),
		ChainID:              6101,
		PID:                  101,
		FD:                   14,
		SrcIP:                "10.0.0.2",
		DstIP:                "10.0.0.1",
		SrcPort:              80,
		DstPort:              54001,
		Direction:            DirectionResponse,
		Flags:                eventFlagSizeOnly,
		ObservedMessageBytes: 128 * 1024,
	})
	if err != nil {
		t.Fatalf("size-only process failed: %v", err)
	}
	if len(respUpdates) != 0 {
		t.Fatalf("size-only progress should not emit immediately, got %#v", respUpdates)
	}

	flushed := asm.FlushStalled(now.Add(250 * time.Millisecond))
	if len(flushed) != 1 {
		t.Fatalf("expected one stalled truncated response flush, got %d", len(flushed))
	}
	if flushed[0].Kind != "response" || flushed[0].Trace.Response == nil {
		t.Fatalf("expected response update, got %#v", flushed)
	}
	if !flushed[0].Trace.ResponseTruncated || !flushed[0].Trace.Response.BodyPartial {
		t.Fatalf("stalled truncated response should mark partial/truncated")
	}
	if got, want := flushed[0].Trace.Response.ObservedMessageBytes, uint64(128*1024); got != want {
		t.Fatalf("observed bytes = %d, want %d", got, want)
	}
	if got, want := flushed[0].Trace.Response.Body, "hello"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
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
func TestAssemblerDoesNotEagerFlushBodyCarryingErrorResponse(t *testing.T) {
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
	if len(respUpdates) != 0 {
		t.Fatalf("expected no eager response flush, got %d", len(respUpdates))
	}
}

func TestAssemblerEmitsTruncatedTLSRequestHeadAndIgnoresFollowOnBody(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 500*time.Millisecond)
	now := time.Unix(1711720000, 0)

	reqPayload := []byte("POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 32\r\n\r\n{\"partial\":")
	updates, err := asm.Process(Event{
		Timestamp:            now,
		ChainID:              9101,
		PID:                  105,
		FD:                   18,
		SrcIP:                "10.0.0.1",
		DstIP:                "10.0.0.2",
		SrcPort:              54005,
		DstPort:              443,
		FragIdx:              0,
		Direction:            DirectionRequest,
		Flags:                eventFlagCaptureTrunc,
		ObservedMessageBytes: 512,
		Source:               "tls_ssl_read",
		Payload:              reqPayload,
	})
	if err != nil {
		t.Fatalf("truncated tls request process failed: %v", err)
	}
	if len(updates) != 0 {
		t.Fatalf("tls request should wait for response before emit, got %#v", updates)
	}

	updates, err = asm.Process(Event{
		Timestamp: now.Add(5 * time.Millisecond),
		ChainID:   9101,
		PID:       105,
		FD:        18,
		FragIdx:   1,
		Direction: DirectionRequest,
		Source:    "tls_ssl_read",
		Payload:   []byte("\"still\":\"body\"}"),
	})
	if err != nil {
		t.Fatalf("follow-on tls body process failed: %v", err)
	}
	if len(updates) != 0 {
		t.Fatalf("follow-on tls body should be ignored after request head emit, got %#v", updates)
	}

	respUpdates, err := asm.Process(Event{
		Timestamp: now.Add(10 * time.Millisecond),
		ChainID:   9101,
		PID:       105,
		FD:        18,
		SrcIP:     "10.0.0.2",
		DstIP:     "10.0.0.1",
		SrcPort:   443,
		DstPort:   54005,
		FragIdx:   0,
		Direction: DirectionResponse,
		Source:    "tls_ssl_write",
		Payload:   []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
	})
	if err != nil {
		t.Fatalf("tls response process failed: %v", err)
	}
	if len(respUpdates) != 2 || respUpdates[0].Kind != "request" || respUpdates[1].Kind != "response" {
		t.Fatalf("expected delayed request + response updates, got %#v", respUpdates)
	}
	if respUpdates[0].Trace.Request == nil || respUpdates[0].Trace.Request.Method != "POST" {
		t.Fatalf("expected delayed parsed request, got %#v", respUpdates[0].Trace.Request)
	}
	if !respUpdates[0].Trace.RequestTruncated || !respUpdates[0].Trace.Request.BodyPartial {
		t.Fatalf("truncated tls request should be marked partial/truncated")
	}
	if respUpdates[1].Trace.Response == nil || respUpdates[1].Trace.Response.StatusCode != 200 {
		t.Fatalf("expected parsed 200 response, got %#v", respUpdates[1].Trace.Response)
	}
	if respUpdates[1].Trace.Request != nil || respUpdates[1].Trace.RequestTS != nil || respUpdates[1].Trace.RequestTruncated {
		t.Fatalf("tls response should not embed request payload, got %#v", respUpdates[1].Trace)
	}

	snap := asm.Snapshot()
	if snap.PendingRequests != 0 {
		t.Fatalf("request should be matched by response, got %#v", snap)
	}
}

func TestAssemblerEmitsPartialTLSRequestWithoutHeaderTerminator(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 100*time.Millisecond)
	now := time.Now()

	reqPayload := []byte("GET /big-cookie HTTP/1.1\r\nHost: example.com\r\nCookie: session=" + strings.Repeat("a", 180))
	updates, err := asm.Process(Event{
		Timestamp:            now,
		ChainID:              9102,
		PID:                  106,
		FD:                   19,
		SrcIP:                "10.0.0.1",
		DstIP:                "10.0.0.2",
		SrcPort:              54006,
		DstPort:              443,
		FragIdx:              0,
		Direction:            DirectionRequest,
		Flags:                eventFlagCaptureTrunc,
		ObservedMessageBytes: 768,
		Source:               "tls_ssl_read",
		Payload:              reqPayload,
	})
	if err != nil {
		t.Fatalf("partial tls request process failed: %v", err)
	}
	if len(updates) != 0 {
		t.Fatalf("tls request should wait for response before emit, got %#v", updates)
	}

	respUpdates, err := asm.Process(Event{
		Timestamp:            now.Add(10 * time.Millisecond),
		ChainID:              9102,
		PID:                  106,
		FD:                   19,
		SrcIP:                "10.0.0.2",
		DstIP:                "10.0.0.1",
		SrcPort:              443,
		DstPort:              54006,
		FragIdx:              0,
		Direction:            DirectionResponse,
		Flags:                eventFlagCaptureTrunc,
		ObservedMessageBytes: 32768,
		Source:               "tls_ssl_write",
		Payload:              []byte("HTTP/1.1 200 OK\r\nContent-Length: 50000\r\n\r\nhello"),
	})
	if err != nil {
		t.Fatalf("partial tls response process failed: %v", err)
	}
	if len(respUpdates) != 0 {
		t.Fatalf("truncated response should wait for stall/size signal, got %#v", respUpdates)
	}

	respUpdates, err = asm.Process(Event{
		Timestamp:            now.Add(20 * time.Millisecond),
		ChainID:              9102,
		PID:                  106,
		FD:                   19,
		SrcIP:                "10.0.0.2",
		DstIP:                "10.0.0.1",
		SrcPort:              443,
		DstPort:              54006,
		Direction:            DirectionResponse,
		Flags:                eventFlagSizeOnly,
		ObservedMessageBytes: 50000,
		Source:               "tls_ssl_write",
	})
	if err != nil {
		t.Fatalf("tls response size-only process failed: %v", err)
	}
	if len(respUpdates) != 0 {
		t.Fatalf("size-only progress should not emit immediately, got %#v", respUpdates)
	}

	flushed := asm.FlushStalled(now.Add(200 * time.Millisecond))
	if len(flushed) != 2 || flushed[0].Kind != "request" || flushed[1].Kind != "response" {
		t.Fatalf("expected delayed request + stalled response updates, got %#v", flushed)
	}
	if flushed[0].Trace.Request == nil || flushed[0].Trace.Request.Method != "GET" || flushed[0].Trace.Request.URL != "/big-cookie" {
		t.Fatalf("expected delayed parsed request, got %#v", flushed[0].Trace.Request)
	}
	if !flushed[0].Trace.RequestTruncated {
		t.Fatalf("expected truncated request flag")
	}
	if flushed[1].Trace.Response == nil || flushed[1].Trace.Response.StatusCode != 200 {
		t.Fatalf("expected parsed response, got %#v", flushed[1].Trace.Response)
	}
}

func TestAssemblerKeepsCollectingPayloadAfterTruncationFlag(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 500*time.Millisecond)
	now := time.Now()

	reqUpdates, err := asm.Process(Event{
		Timestamp: now,
		ChainID:   9201,
		PID:       107,
		FD:        20,
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   54007,
		DstPort:   443,
		FragIdx:   0,
		Direction: DirectionRequest,
		Payload:   []byte("GET /chunked HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	})
	if err != nil || len(reqUpdates) != 1 {
		t.Fatalf("request emit failed: updates=%d err=%v", len(reqUpdates), err)
	}

	respUpdates, err := asm.Process(Event{
		Timestamp:            now.Add(10 * time.Millisecond),
		ChainID:              9201,
		PID:                  107,
		FD:                   20,
		SrcIP:                "10.0.0.2",
		DstIP:                "10.0.0.1",
		SrcPort:              443,
		DstPort:              54007,
		FragIdx:              0,
		Direction:            DirectionResponse,
		Flags:                eventFlagCaptureTrunc,
		ObservedMessageBytes: 2000,
		Source:               "tls_ssl_write",
		Payload:              []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npe"),
	})
	if err != nil {
		t.Fatalf("first response fragment failed: %v", err)
	}
	if len(respUpdates) != 0 {
		t.Fatalf("expected no response yet, got %#v", respUpdates)
	}

	respUpdates, err = asm.Process(Event{
		Timestamp:            now.Add(20 * time.Millisecond),
		ChainID:              9201,
		PID:                  107,
		FD:                   20,
		SrcIP:                "10.0.0.2",
		DstIP:                "10.0.0.1",
		SrcPort:              443,
		DstPort:              54007,
		FragIdx:              1,
		Direction:            DirectionResponse,
		ObservedMessageBytes: 2500,
		Source:               "tls_ssl_write",
		Payload:              []byte("dia\r\n0\r\n\r\n"),
	})
	if err != nil {
		t.Fatalf("second response fragment failed: %v", err)
	}
	if len(respUpdates) != 1 || respUpdates[0].Kind != "response" {
		t.Fatalf("expected one completed response, got %#v", respUpdates)
	}
	if respUpdates[0].Trace.Response == nil {
		t.Fatalf("expected parsed response")
	}
	if got, want := respUpdates[0].Trace.Response.Body, "Wikipedia"; got != want {
		t.Fatalf("body mismatch: got %q want %q", got, want)
	}
}

func TestAssemblerTLSIgnoresSecondRequestOnSameChain(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 500*time.Millisecond)
	now := time.Now()

	req1Updates, err := asm.Process(Event{
		Timestamp: now,
		ChainID:   9301,
		PID:       108,
		FD:        21,
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   54008,
		DstPort:   443,
		FragIdx:   0,
		Direction: DirectionRequest,
		Source:    "tls_ssl_read",
		Payload:   []byte("GET /query HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	})
	if err != nil || len(req1Updates) != 0 {
		t.Fatalf("first tls request should queue until response: updates=%d err=%v", len(req1Updates), err)
	}

	req2Updates, err := asm.Process(Event{
		Timestamp: now.Add(5 * time.Millisecond),
		ChainID:   9301,
		PID:       108,
		FD:        21,
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   54008,
		DstPort:   443,
		FragIdx:   1,
		Direction: DirectionRequest,
		Source:    "tls_ssl_read",
		Payload:   []byte("DELETE /delete HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	})
	if err != nil {
		t.Fatalf("second tls request process failed: err=%v", err)
	}
	if len(req2Updates) != 0 {
		t.Fatalf("same tls chain must not emit a second logical request, got %#v", req2Updates)
	}
	resp1Updates, err := asm.Process(Event{
		Timestamp: now.Add(10 * time.Millisecond),
		ChainID:   9301,
		PID:       108,
		FD:        21,
		SrcIP:     "10.0.0.2",
		DstIP:     "10.0.0.1",
		SrcPort:   443,
		DstPort:   54008,
		FragIdx:   0,
		Direction: DirectionResponse,
		Source:    "tls_ssl_write",
		Payload:   []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst"),
	})
	if err != nil || len(resp1Updates) != 2 {
		t.Fatalf("first tls response emit failed: updates=%d err=%v", len(resp1Updates), err)
	}
	if resp1Updates[0].Kind != "request" || resp1Updates[0].Trace.Request == nil {
		t.Fatalf("expected delayed request update first, got %#v", resp1Updates)
	}
	if got, want := resp1Updates[0].Trace.Request.URL, "/query"; got != want {
		t.Fatalf("first request url = %q, want %q", got, want)
	}
	if resp1Updates[1].Kind != "response" {
		t.Fatalf("expected response update second, got %#v", resp1Updates)
	}
	if got, want := resp1Updates[1].Trace.ChainID, resp1Updates[0].Trace.ChainID; got != want {
		t.Fatalf("first response chain = %d, want %d", got, want)
	}
	if resp1Updates[1].Trace.Request != nil || resp1Updates[1].Trace.RequestTS != nil || resp1Updates[1].Trace.RequestTruncated {
		t.Fatalf("tls response should not carry request object, got %#v", resp1Updates[1].Trace)
	}

	snap := asm.Snapshot()
	if snap.PendingRequests != 0 {
		t.Fatalf("pending requests should be drained, got %#v", snap)
	}
}

func TestAssemblerTLSEmitsOnlyFirstRequestFromSingleChainBuffer(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 500*time.Millisecond)
	now := time.Now()

	updates, err := asm.Process(Event{
		Timestamp: now,
		ChainID:   9302,
		PID:       109,
		FD:        22,
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   54009,
		DstPort:   443,
		FragIdx:   0,
		Direction: DirectionRequest,
		Source:    "tls_ssl_read",
		Payload: []byte(
			"GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n" +
				"DELETE /second HTTP/1.1\r\nHost: example.com\r\n\r\n",
		),
	})
	if err != nil {
		t.Fatalf("tls request process failed: %v", err)
	}
	if len(updates) != 0 {
		t.Fatalf("tls request should wait for response before emit, got %#v", updates)
	}

	respUpdates, err := asm.Process(Event{
		Timestamp: now.Add(10 * time.Millisecond),
		ChainID:   9302,
		PID:       109,
		FD:        22,
		SrcIP:     "10.0.0.2",
		DstIP:     "10.0.0.1",
		SrcPort:   443,
		DstPort:   54009,
		FragIdx:   0,
		Direction: DirectionResponse,
		Source:    "tls_ssl_write",
		Payload:   []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
	})
	if err != nil {
		t.Fatalf("tls response process failed: %v", err)
	}
	if len(respUpdates) != 2 || respUpdates[0].Kind != "request" || respUpdates[1].Kind != "response" {
		t.Fatalf("expected delayed request + one tls response update, got %#v", respUpdates)
	}
	if got, want := respUpdates[0].Trace.Request.URL, "/first"; got != want {
		t.Fatalf("request url = %q, want %q", got, want)
	}
	if got, want := respUpdates[1].Trace.ChainID, respUpdates[0].Trace.ChainID; got != want {
		t.Fatalf("response chain = %d, want %d", got, want)
	}

	snap := asm.Snapshot()
	if snap.PendingRequests != 1 || snap.PendingNoRespBytes != 1 {
		t.Fatalf("expected one later tls request to remain pending, got %#v", snap)
	}
}

func TestAssemblerTLSSessionDedupsSuspiciousDuplicateRequest(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 500*time.Millisecond)
	sockID := uint64(42)

	asm.enqueueTLSPending(sockID, pendingRequest{
		chainID: 1,
		request: &ParsedMessage{
			Method:               "POST",
			URL:                  "/delete?id=1",
			StartLine:            "POST /delete?id=1 HTTP/1.1",
			ContentLength:        -1,
			ObservedMessageBytes: 32768,
			Headers:              map[string]string{"Host": "example.com"},
		},
		requestTruncated: true,
	})
	asm.enqueueTLSPending(sockID, pendingRequest{
		chainID: 2,
		request: &ParsedMessage{
			Method:        "POST",
			URL:           "/search",
			StartLine:     "POST /search HTTP/1.1",
			ContentLength: 128,
			Headers:       map[string]string{"Host": "example.com", "Content-Length": "128"},
		},
	})
	asm.enqueueTLSPending(sockID, pendingRequest{
		chainID: 3,
		request: &ParsedMessage{
			Method:        "POST",
			URL:           "/update",
			StartLine:     "POST /update HTTP/1.1",
			ContentLength: 256,
			Headers:       map[string]string{"Host": "example.com", "Content-Length": "256"},
		},
	})
	asm.enqueueTLSPending(sockID, pendingRequest{
		chainID: 4,
		request: &ParsedMessage{
			Method:        "POST",
			URL:           "/delete?id=1",
			StartLine:     "POST /delete?id=1 HTTP/1.1",
			ContentLength: 35,
			Headers: map[string]string{
				"Host":           "example.com",
				"Content-Length": "35",
				"Connection":     "keep-alive",
			},
		},
	})

	if got := asm.tlsPendingCount(sockID); got != 3 {
		t.Fatalf("pending count = %d, want 3", got)
	}

	first, ok := asm.popTLSPending(sockID)
	if !ok || first.chainID != 2 {
		t.Fatalf("first pending = %#v ok=%v, want chain 2", first, ok)
	}
	second, ok := asm.popTLSPending(sockID)
	if !ok || second.chainID != 3 {
		t.Fatalf("second pending = %#v ok=%v, want chain 3", second, ok)
	}
	third, ok := asm.popTLSPending(sockID)
	if !ok || third.chainID != 4 {
		t.Fatalf("third pending = %#v ok=%v, want chain 4", third, ok)
	}
}

// 测试低信心签名请求直到更好的重复请求到达
func TestAssemblerTLSKeepsLowConfidenceSignedRequestUntilBetterDuplicateArrives(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 500*time.Millisecond)
	sockID := uint64(99)

	asm.enqueueTLSPending(sockID, pendingRequest{
		chainID: 11,
		request: &ParsedMessage{
			Method:               "POST",
			URL:                  "/delete?id=1",
			StartLine:            "POST /delete?id=1 HTTP/1.1",
			ContentLength:        -1,
			ObservedMessageBytes: 32768,
			Headers:              map[string]string{"Host": "example.com"},
			Body:                 "",
			BodyPartial:          false,
		},
		requestTruncated: true,
	})
	if got := asm.tlsPendingCount(sockID); got != 1 {
		t.Fatalf("pending count after low-confidence signed request = %d, want 1", got)
	}

	asm.enqueueTLSPending(sockID, pendingRequest{
		chainID: 12,
		request: &ParsedMessage{
			Method:               "POST",
			URL:                  "/delete?id=1",
			StartLine:            "POST /delete?id=1 HTTP/1.1",
			ContentLength:        35,
			ObservedMessageBytes: 1096,
			Headers: map[string]string{
				"Host":           "example.com",
				"Content-Length": "35",
			},
		},
		requestTruncated: false,
	})
	if got := asm.tlsPendingCount(sockID); got != 1 {
		t.Fatalf("pending count after better duplicate = %d, want 1", got)
	}
	got, ok := asm.popTLSPending(sockID)
	if !ok || got.chainID != 12 {
		t.Fatalf("pending = %#v ok=%v, want chain 12", got, ok)
	}
}

func TestAssemblerTLSKeepsRepeatedSignedRequestsOnSameSock(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 500*time.Millisecond)
	sockID := uint64(199)

	first := pendingRequest{
		chainID: 31,
		request: &ParsedMessage{
			Method:               "POST",
			URL:                  "/power-asm/v2/serviceinfo/update",
			StartLine:            "POST /power-asm/v2/serviceinfo/update HTTP/1.1",
			ContentLength:        833,
			ObservedMessageBytes: 1858,
			Headers: map[string]string{
				"Host":           "example.com",
				"Content-Length": "833",
			},
			BodyPartial: true,
		},
		requestTruncated: true,
	}
	second := pendingRequest{
		chainID: 32,
		request: &ParsedMessage{
			Method:               "POST",
			URL:                  "/power-asm/v2/serviceinfo/update",
			StartLine:            "POST /power-asm/v2/serviceinfo/update HTTP/1.1",
			ContentLength:        833,
			ObservedMessageBytes: 1858,
			Headers: map[string]string{
				"Host":           "example.com",
				"Content-Length": "833",
			},
			BodyPartial: true,
		},
		requestTruncated: true,
	}

	asm.enqueueTLSPending(sockID, first)
	asm.enqueueTLSPending(sockID, second)

	if got := asm.tlsPendingCount(sockID); got != 2 {
		t.Fatalf("pending count after repeated signed requests = %d, want 2", got)
	}
	gotFirst, ok := asm.popTLSPending(sockID)
	if !ok || gotFirst.chainID != 31 {
		t.Fatalf("first pending = %#v ok=%v, want chain 31", gotFirst, ok)
	}
	gotSecond, ok := asm.popTLSPending(sockID)
	if !ok || gotSecond.chainID != 32 {
		t.Fatalf("second pending = %#v ok=%v, want chain 32", gotSecond, ok)
	}
}

// 测试低信心签名请求直到更好的重复请求到达
func TestAssemblerTLSSuppressesLowConfidenceUnsignedRequest(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 500*time.Millisecond)
	sockID := uint64(100)

	asm.enqueueTLSPending(sockID, pendingRequest{
		chainID: 21,
		request: &ParsedMessage{
			StartLine:            "",
			ContentLength:        -1,
			ObservedMessageBytes: 32768,
			Headers:              map[string]string{"Host": "example.com"},
			Body:                 "",
			BodyPartial:          false,
		},
		requestTruncated: true,
	})
	if got := asm.tlsPendingCount(sockID); got != 0 {
		t.Fatalf("pending count after unsigned low-confidence request = %d, want 0", got)
	}
}

func TestAssemblerTLSAssignsPendingAtFirstResponseFragment(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 10*time.Millisecond)
	now := time.Now()

	for _, tc := range []struct {
		chainID uint64
		url     string
	}{
		{chainID: 1001, url: "/query"},
		{chainID: 1002, url: "/update"},
	} {
		updates, err := asm.Process(Event{
			Timestamp: now,
			ChainID:   tc.chainID,
			SockID:    777,
			PID:       1,
			FD:        4,
			FragIdx:   0,
			Direction: DirectionRequest,
			Source:    "tls_ssl_read",
			Payload:   []byte("POST " + tc.url + " HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		})
		if err != nil || len(updates) != 0 {
			t.Fatalf("queue tls request %s failed: updates=%d err=%v", tc.url, len(updates), err)
		}
	}

	updates, err := asm.Process(Event{
		Timestamp: now.Add(10 * time.Millisecond),
		ChainID:   2001,
		SockID:    777,
		PID:       1,
		FD:        4,
		FragIdx:   0,
		Direction: DirectionResponse,
		Source:    "tls_ssl_write",
		Payload:   []byte("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\npartial"),
	})
	if err != nil {
		t.Fatalf("first partial tls response failed: updates=%d err=%v", len(updates), err)
	}
	if len(updates) != 0 {
		t.Fatalf("first partial tls response should stay buffered until stall flush, got %#v", updates)
	}

	flushed := asm.FlushStalled(now.Add(30 * time.Millisecond))
	if len(flushed) != 3 {
		t.Fatalf("stalled flush should emit first delayed request+response plus second stalled request, got %#v", flushed)
	}
	if got, want := flushed[0].Trace.Request.URL, "/query"; got != want {
		t.Fatalf("first response paired request = %q, want %q", got, want)
	}
	if got, want := flushed[1].Trace.ChainID, flushed[0].Trace.ChainID; got != want {
		t.Fatalf("first response chain = %d, want %d", got, want)
	}
	if got, want := flushed[2].Trace.Request.URL, "/update"; got != want {
		t.Fatalf("second stalled request url = %q, want %q", got, want)
	}

	updates, err = asm.Process(Event{
		Timestamp: now.Add(20 * time.Millisecond),
		ChainID:   2002,
		SockID:    777,
		PID:       1,
		FD:        4,
		FragIdx:   0,
		Direction: DirectionResponse,
		Source:    "tls_ssl_write",
		Payload:   []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
	})
	if err != nil {
		t.Fatalf("second tls response failed: %v", err)
	}
	if len(updates) != 1 {
		t.Fatalf("second tls response should emit only response after stalled request flush, got %#v", updates)
	}
	if updates[0].Kind != "response" {
		t.Fatalf("second tls response should be response-only, got %#v", updates)
	}

	flushed = asm.FlushStalled(now.Add(50 * time.Millisecond))
	if len(flushed) != 0 {
		t.Fatalf("stalled flush should have nothing left, got %#v", flushed)
	}
}

func TestAssemblerTLSDropsNonHTTPRequestRawChainAndIgnoresFollowupResponse(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 10*time.Millisecond)
	now := time.Now()

	updates, err := asm.Process(Event{
		Timestamp: now,
		ChainID:   3001,
		SockID:    999,
		PID:       1,
		FD:        4,
		FragIdx:   0,
		Direction: DirectionRequest,
		Source:    "tls_ssl_read",
		Payload:   []byte(".bottom)&&(e.offsets.popper.top=n(i.bottom)),e},"),
	})
	if err != nil {
		t.Fatalf("process bogus tls request: %v", err)
	}
	if len(updates) != 0 {
		t.Fatalf("unexpected updates for bogus tls request: %d", len(updates))
	}
	if asm.HasState(3001) {
		t.Fatalf("bogus tls request chain should not create active state")
	}

	updates, err = asm.Process(Event{
		Timestamp: now.Add(5 * time.Millisecond),
		ChainID:   3001,
		SockID:    999,
		PID:       1,
		FD:        4,
		FragIdx:   0,
		Direction: DirectionResponse,
		Source:    "tls_ssl_write",
		Payload:   []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
	})
	if err != nil {
		t.Fatalf("process followup tls response: %v", err)
	}
	if len(updates) != 0 {
		t.Fatalf("unexpected updates for suppressed tls chain response: %d", len(updates))
	}
	if asm.HasState(3001) {
		t.Fatalf("suppressed tls chain response should remain ignored")
	}
}

func TestAssemblerIgnoresLateHTTPFragmentsAfterClosedChain(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 10*time.Millisecond)
	now := time.Unix(1711717000, 0)

	updates, err := asm.Process(Event{
		Timestamp: now,
		ChainID:   9101,
		PID:       42,
		FD:        7,
		FragIdx:   0,
		Direction: DirectionRequest,
		Payload:   []byte("GET /large HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	})
	if err != nil || len(updates) != 1 || updates[0].Kind != "request" {
		t.Fatalf("request emit failed: updates=%#v err=%v", updates, err)
	}

	updates, err = asm.Process(Event{
		Timestamp: now.Add(10 * time.Millisecond),
		ChainID:   9101,
		FragIdx:   0,
		Direction: DirectionResponse,
		Payload:   []byte("HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\nhello"),
	})
	if err != nil || len(updates) != 0 {
		t.Fatalf("partial response should wait before close: updates=%#v err=%v", updates, err)
	}

	updates, err = asm.Process(Event{
		Timestamp: now.Add(15 * time.Millisecond),
		ChainID:   9101,
		Flags:     eventFlagControl | eventFlagClose,
	})
	if err != nil || len(updates) != 1 || updates[0].Kind != "response" {
		t.Fatalf("response finalize failed: updates=%#v err=%v", updates, err)
	}
	if asm.HasState(9101) {
		t.Fatalf("closed http chain should not keep active state")
	}

	updates, err = asm.Process(Event{
		Timestamp:            now.Add(20 * time.Millisecond),
		ChainID:              9101,
		FragIdx:              1,
		Direction:            DirectionResponse,
		ObservedMessageBytes: 50000,
		Payload:              []byte("late body fragment that should be ignored"),
	})
	if err != nil {
		t.Fatalf("late response fragment failed: %v", err)
	}
	if len(updates) != 0 {
		t.Fatalf("late http fragment should be ignored, got %#v", updates)
	}
	if asm.HasState(9101) {
		t.Fatalf("late http fragment should not recreate state")
	}
}

// 测试在延迟响应到达时，不会重复发送请求
func TestAssemblerTLSFlushesStalledPendingRequestWithoutDuplicatingOnLaterResponse(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 10*time.Millisecond)
	now := time.Now()

	reqUpdates, err := asm.Process(Event{
		Timestamp: now,
		ChainID:   20001,
		SockID:    900,
		PID:       1,
		FD:        4,
		FragIdx:   0,
		Direction: DirectionRequest,
		Source:    "tls_ssl_read",
		Payload:   []byte("POST /query HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"),
	})
	if err != nil {
		t.Fatalf("tls request process failed: %v", err)
	}
	if len(reqUpdates) != 0 {
		t.Fatalf("tls request should stay delayed before stall, got %#v", reqUpdates)
	}

	stalled := asm.FlushStalled(now.Add(20 * time.Millisecond))
	if len(stalled) != 1 || stalled[0].Kind != "request" {
		t.Fatalf("stalled tls pending request should emit one request update, got %#v", stalled)
	}
	if got, want := stalled[0].Trace.Request.URL, "/query"; got != want {
		t.Fatalf("stalled request url = %q, want %q", got, want)
	}

	respUpdates, err := asm.Process(Event{
		Timestamp: now.Add(30 * time.Millisecond),
		ChainID:   30001,
		SockID:    900,
		PID:       1,
		FD:        4,
		FragIdx:   0,
		Direction: DirectionResponse,
		Source:    "tls_ssl_write",
		Payload:   []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
	})
	if err != nil {
		t.Fatalf("tls response process failed: %v", err)
	}
	if len(respUpdates) != 1 || respUpdates[0].Kind != "response" {
		t.Fatalf("later tls response should emit only one response update, got %#v", respUpdates)
	}
	if got, want := respUpdates[0].Trace.ChainID, stalled[0].Trace.ChainID; got != want {
		t.Fatalf("response chain = %d, want %d", got, want)
	}
}

func TestAssemblerTLSIgnoresLateFragmentsAfterClosedChain(t *testing.T) {
	asm := NewAssembler(1<<20, time.Minute, 10*time.Millisecond)
	now := time.Now()

	updates, err := asm.Process(Event{
		Timestamp: now,
		ChainID:   30001,
		SockID:    901,
		PID:       1,
		FD:        4,
		FragIdx:   0,
		Direction: DirectionRequest,
		Source:    "tls_ssl_read",
		Payload:   []byte("POST /query HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"),
	})
	if err != nil || len(updates) != 0 {
		t.Fatalf("tls request process failed: updates=%d err=%v", len(updates), err)
	}

	respUpdates, err := asm.Process(Event{
		Timestamp: now.Add(20 * time.Millisecond),
		ChainID:   40001,
		SockID:    901,
		PID:       1,
		FD:        4,
		FragIdx:   0,
		Direction: DirectionResponse,
		Source:    "tls_ssl_write",
		Payload:   []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
	})
	if err != nil {
		t.Fatalf("tls response process failed: %v", err)
	}
	if len(respUpdates) != 2 {
		t.Fatalf("tls response should emit delayed request+response, got %#v", respUpdates)
	}

	late, err := asm.Process(Event{
		Timestamp: now.Add(30 * time.Millisecond),
		ChainID:   30001,
		SockID:    901,
		PID:       1,
		FD:        4,
		FragIdx:   1,
		Direction: DirectionRequest,
		Source:    "tls_ssl_read",
		Payload:   []byte("{\"body\":\"late-fragment\"}"),
	})
	if err != nil {
		t.Fatalf("late tls fragment process failed: %v", err)
	}
	if len(late) != 0 {
		t.Fatalf("late tls fragment should be ignored, got %#v", late)
	}

	snap := asm.Snapshot()
	if snap.RequestBufferStates != 0 || snap.PendingRequests != 0 || snap.PendingNoRespBytes != 0 {
		t.Fatalf("late tls fragment should not recreate request state, got %#v", snap)
	}
}
