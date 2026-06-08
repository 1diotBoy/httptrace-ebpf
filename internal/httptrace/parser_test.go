package httptrace

import (
	"fmt"
	"strings"
	"testing"
)

func TestTryParseRequest(t *testing.T) {
	raw := []byte("POST /api/v1/items HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11\r\n\r\nhello world")

	msg, complete, err := TryParseMessage(DirectionRequest, raw, ParseOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !complete {
		t.Fatalf("request should be complete")
	}
	if got, want := msg.Method, "POST"; got != want {
		t.Fatalf("method mismatch: got %q want %q", got, want)
	}
	if got, want := msg.URL, "/api/v1/items"; got != want {
		t.Fatalf("url mismatch: got %q want %q", got, want)
	}
	if got, want := msg.Body, "hello world"; got != want {
		t.Fatalf("body mismatch: got %q want %q", got, want)
	}
}

func TestTryParseChunkedResponse(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n")

	msg, complete, err := TryParseMessage(DirectionResponse, raw, ParseOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !complete {
		t.Fatalf("response should be complete")
	}
	if got, want := msg.StatusCode, 200; got != want {
		t.Fatalf("status mismatch: got %d want %d", got, want)
	}
	if got, want := msg.Body, "Wikipedia"; got != want {
		t.Fatalf("body mismatch: got %q want %q", got, want)
	}
}

func TestTryParseChunkedResponseWithoutFinalTrailerCRLFTreatsBodyAsCompleteEnough(t *testing.T) {
	body := `{"errCode":"-100","errMsg":"forbidden"}`
	raw := []byte(fmt.Sprintf(
		"HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n",
		len(body), body,
	))

	msg, complete, err := TryParseMessage(DirectionResponse, raw, ParseOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !complete {
		t.Fatalf("response should be treated as complete-enough")
	}
	if got, want := msg.StatusCode, 403; got != want {
		t.Fatalf("status mismatch: got %d want %d", got, want)
	}
	if msg.BodyPartial {
		t.Fatalf("body should not be marked partial when only final trailer CRLF is missing")
	}
	if got, want := msg.Body, body; got != want {
		t.Fatalf("body mismatch: got %q want %q", got, want)
	}
}

func TestTryParseChunkedResponseWithOnlyTerminalZeroTreatsBodyAsCompleteEnough(t *testing.T) {
	body := `{"errCode":"-100","errMsg":"forbidden"}`
	raw := []byte(fmt.Sprintf(
		"HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0",
		len(body), body,
	))

	msg, complete, err := TryParseMessage(DirectionResponse, raw, ParseOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !complete {
		t.Fatalf("response should be treated as complete-enough")
	}
	if msg.BodyPartial {
		t.Fatalf("body should not be marked partial when terminal zero chunk is cut at EOF")
	}
	if got, want := msg.Body, body; got != want {
		t.Fatalf("body mismatch: got %q want %q", got, want)
	}
}

func TestTryParseChunkedResponseMissingCRLFBeforeTerminalZeroTreatsBodyAsCompleteEnough(t *testing.T) {
	body := `{"errCode":"-100","errMsg":"forbidden"}`
	raw := []byte(fmt.Sprintf(
		"HTTP/1.1 200 \r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s0\r\n\r\n",
		len(body), body,
	))

	msg, complete, err := TryParseMessage(DirectionResponse, raw, ParseOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !complete {
		t.Fatalf("response should be treated as complete-enough")
	}
	if msg.BodyPartial {
		t.Fatalf("body should not be marked partial when only CRLF before terminal zero is missing")
	}
	if got, want := msg.Body, body; got != want {
		t.Fatalf("body mismatch: got %q want %q", got, want)
	}
}

func TestTryParseResponseHeadWithPartialBody(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\nContent-Type: application/json\r\n\r\nabc")

	msg, ok, err := TryParseMessageHead(DirectionResponse, raw, ParseOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("response head should be parseable")
	}
	if got, want := msg.StatusCode, 200; got != want {
		t.Fatalf("status mismatch: got %d want %d", got, want)
	}
	if !msg.BodyPartial {
		t.Fatalf("partial response body should be marked")
	}
	if got, want := msg.Body, "abc"; got != want {
		t.Fatalf("partial body mismatch: got %q want %q", got, want)
	}
}

func TestTryParsePartialResponseHead(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nServer: Tengine\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nCache-Control: no-cache")

	msg, ok, err := TryParsePartialHead(DirectionResponse, raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("partial response head should be parseable")
	}
	if got, want := msg.StatusCode, 200; got != want {
		t.Fatalf("status mismatch: got %d want %d", got, want)
	}
	if got, want := msg.Headers["Server"], "Tengine"; got != want {
		t.Fatalf("server header mismatch: got %q want %q", got, want)
	}
	if !msg.Chunked {
		t.Fatalf("expected chunked response")
	}
	if !msg.BodyPartial {
		t.Fatalf("expected partial body marker for truncated response head")
	}
}

func TestTryParsePartialHeadChunkedBodyCompleteEnoughDoesNotStayPartial(t *testing.T) {
	body := `{"errCode":"-100","errMsg":"forbidden"}`
	raw := []byte(fmt.Sprintf(
		"HTTP/1.1 200 \r\nServer: POWERLBS\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n%x\r\n%s0\r\n\r\n",
		len(body), body,
	))

	msg, ok, err := TryParsePartialHead(DirectionResponse, raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("partial head should be parseable")
	}
	if msg.BodyPartial {
		t.Fatalf("body should not remain partial when chunked body is complete-enough in partial-head path")
	}
	if got, want := msg.Body, body; got != want {
		t.Fatalf("body mismatch: got %q want %q", got, want)
	}
}

func TestTryParseChunkedResponseHeadStripsChunkPrefixFromPartialBody(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npe")

	msg, ok, err := TryParseMessageHead(DirectionResponse, raw, ParseOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("chunked response head should be parseable")
	}
	if !msg.Chunked {
		t.Fatalf("expected chunked response")
	}
	if !msg.BodyPartial {
		t.Fatalf("expected partial body marker")
	}
	if got, want := msg.Body, "Wikipe"; got != want {
		t.Fatalf("body mismatch: got %q want %q", got, want)
	}
}

func TestFindMessageStartRequest(t *testing.T) {
	raw := []byte("xxPOST /api HTTP/1.1\r\nHost: example.com\r\n\r\n")
	got := FindMessageStart(DirectionRequest, raw)
	if got != 2 {
		t.Fatalf("request start mismatch: got %d want %d", got, 2)
	}
}

func TestFindMessageStartResponse(t *testing.T) {
	raw := []byte("junkHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	got := FindMessageStart(DirectionResponse, raw)
	if got != 4 {
		t.Fatalf("response start mismatch: got %d want %d", got, 4)
	}
}

func TestBuildSyntheticResponseFromJSONBody(t *testing.T) {
	raw := []byte("{\"timestamp\":\"2026-04-19 21:56:31\",\"status\":518,\"error\":\"Http Status 518\",\"path\":\"/power-asm/v2/serviceinfo/update\"}")
	msg, ok := BuildSyntheticResponse(raw)
	if !ok {
		t.Fatalf("expected synthetic response")
	}
	if got, want := msg.StatusCode, 518; got != want {
		t.Fatalf("status mismatch: got %d want %d", got, want)
	}
	if got, want := msg.Body, string(raw); got != want {
		t.Fatalf("body mismatch: got %q want %q", got, want)
	}
	if !msg.BodyPartial {
		t.Fatalf("synthetic response should be marked partial")
	}
}

func TestBuildSyntheticResponseFromHTMLBody(t *testing.T) {
	raw := []byte("<!doctype html><html lang=\"en\"><head><title>HTTP Status 404 – Not Found</title></head><body><h1>HTTP Status 404 – Not Found</h1></body></html>")
	msg, ok := BuildSyntheticResponse(raw)
	if !ok {
		t.Fatalf("expected synthetic response")
	}
	if got, want := msg.StatusCode, 404; got != want {
		t.Fatalf("status mismatch: got %d want %d", got, want)
	}
	if got, want := msg.Reason, "Not Found"; got != want {
		t.Fatalf("reason mismatch: got %q want %q", got, want)
	}
}

func TestBuildSyntheticResponseStripsHTTPHeadersFromBody(t *testing.T) {
	raw := []byte("HTTP/1.1 200 \r\nServer: POWERLBS\r\nTransfer-Encoding: chunked\r\n\r\nc4e\r\n{\"errCode\":\"0\"")
	msg, ok := BuildSyntheticResponse(raw)
	if !ok {
		t.Fatalf("expected synthetic response")
	}
	if got, want := msg.StartLine, "HTTP/1.1 200 "; got != want {
		t.Fatalf("start line mismatch: got %q want %q", got, want)
	}
	if strings.HasPrefix(msg.Body, "HTTP/1.1") {
		t.Fatalf("body should not include response head: %q", msg.Body)
	}
	if got, want := msg.Body, "{\"errCode\":\"0\""; got != want {
		t.Fatalf("body mismatch: got %q want %q", got, want)
	}
	if !msg.BodyPartial {
		t.Fatalf("synthetic response should still be marked partial")
	}
}

func TestBuildSyntheticResponseDecodesCompleteChunkedBodyFromFallbackHead(t *testing.T) {
	body := `{"errCode":"-100","errMsg":"无权限访问，无法获取用户信息！"}`
	raw := []byte(fmt.Sprintf("HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(body), body))
	msg, ok := BuildSyntheticResponse(raw)
	if !ok {
		t.Fatalf("expected synthetic response")
	}
	if got, want := msg.StartLine, "HTTP/1.1"; got != want {
		t.Fatalf("start line mismatch: got %q want %q", got, want)
	}
	if got, want := msg.Body, body; got != want {
		t.Fatalf("body mismatch: got %q want %q", got, want)
	}
	if msg.BodyPartial {
		t.Fatalf("body should not be marked partial after complete chunk decode")
	}
}
