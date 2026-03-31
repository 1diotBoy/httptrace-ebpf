package app

import "testing"

func TestParseIPv4HexLE(t *testing.T) {
	got, ok := parseIPv4HexLE("B82812AC")
	if !ok {
		t.Fatalf("parseIPv4HexLE returned !ok")
	}
	want := "172.18.40.184"
	if got != want {
		t.Fatalf("parseIPv4HexLE mismatch: got %q want %q", got, want)
	}
}

func TestParseProcAddr(t *testing.T) {
	ip, port, ok := parseProcAddr("B82812AC:3F62")
	if !ok {
		t.Fatalf("parseProcAddr returned !ok")
	}
	if ip != "172.18.40.184" {
		t.Fatalf("ip mismatch: got %q want %q", ip, "172.18.40.184")
	}
	if port != 16226 {
		t.Fatalf("port mismatch: got %d want %d", port, 16226)
	}
}

func TestParseIPv6ProcHexIPv4Mapped(t *testing.T) {
	got, ok := parseIPv6ProcHex("0000000000000000FFFF0000B82812AC")
	if !ok {
		t.Fatalf("parseIPv6ProcHex returned !ok")
	}
	if got != "172.18.40.184" {
		t.Fatalf("parseIPv6ProcHex mismatch: got %q want %q", got, "172.18.40.184")
	}
}
