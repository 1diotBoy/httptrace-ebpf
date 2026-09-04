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
	fmt.Println("加密结果：", encryptStr)
	// 解密
	decryptStr, _ := SM4Decrypt(encryptStr)
	fmt.Println("解密结果：", decryptStr)
}

func TestNormalizeRuntimeConfigClampsAggressiveDefaults(t *testing.T) {
	cfg := Config{
		CaptureBytes:    32 * 1024,
		PerfPages:       1024,
		BatchSize:       100,
		WorkerCount:     64,
		WorkerQueueSize: 6400,
		RedisWorkers:    32,
		RedisQueueSize:  32768,
		RetryQueueSize:  32768,
	}

	got, plan := normalizeRuntimeConfig(cfg, 64, 512<<20, true)

	if got.PerfPages != 32 {
		t.Fatalf("perf pages not clamped: got %d want %d", got.PerfPages, 32)
	}
	if got.WorkerCount != 2 {
		t.Fatalf("worker count not clamped: got %d want %d", got.WorkerCount, 2)
	}
	if got.WorkerQueueSize != 256 {
		t.Fatalf("worker queue size not clamped: got %d want %d", got.WorkerQueueSize, 256)
	}
	if got.RedisWorkers != 1 {
		t.Fatalf("redis workers not clamped: got %d want %d", got.RedisWorkers, 1)
	}
	if got.RedisQueueSize != 2048 {
		t.Fatalf("redis queue size not clamped: got %d want %d", got.RedisQueueSize, 2048)
	}
	if got.RetryQueueSize != 1024 {
		t.Fatalf("retry queue size not clamped: got %d want %d", got.RetryQueueSize, 1024)
	}
	if plan.PerfTotalBytes == 0 || plan.WorkerQueueBytes == 0 {
		t.Fatalf("resource plan should include memory estimates: %#v", plan)
	}
}

func TestNormalizeRuntimeConfigFillsAutoSizes(t *testing.T) {
	cfg := Config{
		CaptureBytes:    32 * 1024,
		BatchSize:       64,
		WorkerCount:     0,
		WorkerQueueSize: 0,
		RedisWorkers:    0,
		RedisQueueSize:  0,
		RetryQueueSize:  0,
	}

	got, _ := normalizeRuntimeConfig(cfg, 16, 3<<30, true)

	if got.WorkerCount != 8 {
		t.Fatalf("auto worker count mismatch: got %d want %d", got.WorkerCount, 8)
	}
	if got.WorkerQueueSize != 512 {
		t.Fatalf("auto worker queue mismatch: got %d want %d", got.WorkerQueueSize, 512)
	}
	if got.RedisWorkers != 4 {
		t.Fatalf("auto redis worker mismatch: got %d want %d", got.RedisWorkers, 4)
	}
	if got.RedisQueueSize != 4096 {
		t.Fatalf("auto redis queue mismatch: got %d want %d", got.RedisQueueSize, 4096)
	}
	if got.RetryQueueSize != 2048 {
		t.Fatalf("auto retry queue mismatch: got %d want %d", got.RetryQueueSize, 2048)
	}
}

func TestNormalizeRuntimeConfigUsesPossibleCPUsForPerfBudget(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PerfPages = 512

	got, plan := normalizeRuntimeConfigForCPUs(cfg, 16, 1024, 3<<30, true)
	if got.PerfPages != 16 {
		t.Fatalf("perf pages must be limited by possible CPUs: got %d want 16", got.PerfPages)
	}
	if plan.RuntimeCPUCount != 16 || plan.CPUCount != 1024 {
		t.Fatalf("unexpected cpu plan: %#v", plan)
	}
	if got, want := plan.PerfTotalBytes, uint64(64<<20); got != want {
		t.Fatalf("perf buffer budget: got %d want %d", got, want)
	}
}
