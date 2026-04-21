package app

import (
	"fmt"
	"power-ebpf/internal/httptrace"
	"testing"
)

func TestMatchPortPairSingleSideMatchesEitherEndpoint(t *testing.T) {
	if !matchPortPair(0, 12581, 53422, 12581) {
		t.Fatalf("dst-port should match local service endpoint")
	}
	if !matchPortPair(12581, 0, 53422, 12581) {
		t.Fatalf("src-port should also match either endpoint when used alone")
	}
}

func TestMatchPortPairSymmetricPair(t *testing.T) {
	if !matchPortPair(12581, 443, 12581, 443) {
		t.Fatalf("direct pair should match")
	}
	if !matchPortPair(12581, 443, 443, 12581) {
		t.Fatalf("reversed pair should also match")
	}
	if matchPortPair(12581, 443, 12581, 8080) {
		t.Fatalf("unexpected pair match")
	}
}

func TestMatchIPPairSingleSideMatchesEitherEndpoint(t *testing.T) {
	if !matchIPPair("", "192.168.4.161", "10.0.0.8", "192.168.4.161") {
		t.Fatalf("single-side ip filter should match either endpoint")
	}
	if !matchIPPair("192.168.4.161", "", "10.0.0.8", "192.168.4.161") {
		t.Fatalf("single-side src ip filter should match either endpoint")
	}
}

func TestMatchDetailReason(t *testing.T) {
	filter := ResolvedFilter{
		SrcPort: 0,
		DstPort: 80,
	}
	ok, reason := filter.MatchDetail(httptrace.Event{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 40000,
		DstPort: 8080,
	})
	if ok {
		t.Fatalf("expected port mismatch")
	}
	if reason != FilterReasonPort {
		t.Fatalf("unexpected reason: got %q want %q", reason, FilterReasonPort)
	}
}

func TestRedisPasswordSM4Decrypt(t *testing.T) {
	password := "Powersi@redis202312"
	// 加密
	encryptStr, _ := SM4Encrypt(password)
	fmt.Println(encryptStr)
	// 解密
	decryptStr, _ := SM4Decrypt(encryptStr)
	fmt.Println(decryptStr)
}
