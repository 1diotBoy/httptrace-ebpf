package storage

import (
	"testing"

	"power-ebpf/internal/httptrace"
)

func TestPrepareParsedMessageForRedisKeepsBodyUntouched(t *testing.T) {
	body := "hello world"

	got := prepareParsedMessageForRedis(&httptrace.ParsedMessage{Body: body})
	if got == nil {
		t.Fatalf("expected parsed message")
	}
	if got.Body != body {
		t.Fatalf("body should stay unchanged: got %q want %q", got.Body, body)
	}
	if got.BodySizeBytes != len(body) {
		t.Fatalf("body size mismatch: got %d want %d", got.BodySizeBytes, len(body))
	}
}

func TestPrepareTraceForRedisKeepsRequestAndResponseUntouched(t *testing.T) {
	trace := httptrace.TraceDocument{
		Request:  &httptrace.ParsedMessage{Body: "request-body"},
		Response: &httptrace.ParsedMessage{Body: "response-body"},
	}

	got := prepareTraceForRedis(trace)
	if got.Request == nil || got.Response == nil {
		t.Fatalf("request and response should both exist")
	}
	if got.Request.Body != trace.Request.Body {
		t.Fatalf("request body should stay unchanged")
	}
	if got.Response.Body != trace.Response.Body {
		t.Fatalf("response body should stay unchanged")
	}
	if got.Request.BodySizeBytes != len(trace.Request.Body) {
		t.Fatalf("request body size mismatch: got %d", got.Request.BodySizeBytes)
	}
	if got.Response.BodySizeBytes != len(trace.Response.Body) {
		t.Fatalf("response body size mismatch: got %d", got.Response.BodySizeBytes)
	}
}

func TestParseBodyLimitBytesAcceptsKBAndBytes(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want int64
	}{
		{name: "kb value", raw: "32", want: 32 * 1024},
		{name: "bytes value", raw: "32768", want: 32 * 1024},
		{name: "clamp over 32kb", raw: "64", want: 32 * 1024},
		{name: "lower byte value", raw: "16384", want: 16 * 1024},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseBodyLimitBytes(tc.raw)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("limit mismatch: got %d want %d", got, tc.want)
			}
		})
	}
}
