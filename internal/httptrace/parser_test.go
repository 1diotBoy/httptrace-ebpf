package httptrace

import "testing"

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
