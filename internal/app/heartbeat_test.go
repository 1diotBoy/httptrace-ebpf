package app

import (
	"testing"
	"time"
)

func TestNormalizeHeartbeatEndpoint(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{
			raw:  "http://172.16.36.212:8080/power-asm/",
			want: "http://172.16.36.212:8080/power-asm/v2/dataCollectClient/heartbeat.shtml",
		},
		{
			raw:  "127.0.0.1:8080",
			want: "http://127.0.0.1:8080/v2/dataCollectClient/heartbeat.shtml",
		},
		{
			raw:  "https://collector.example.com",
			want: "https://collector.example.com/v2/dataCollectClient/heartbeat.shtml",
		},
		{
			raw:  "https://collector.example.com/v2/dataCollectClient/heartbeat.shtml",
			want: "https://collector.example.com/v2/dataCollectClient/heartbeat.shtml",
		},
	}

	for _, tc := range cases {
		got, err := normalizeHeartbeatEndpoint(tc.raw)
		if err != nil {
			t.Fatalf("normalizeHeartbeatEndpoint(%q) returned error: %v", tc.raw, err)
		}
		if got != tc.want {
			t.Fatalf("normalizeHeartbeatEndpoint(%q) = %q want %q", tc.raw, got, tc.want)
		}
	}
}

// 首次上报
func TestHeartbeatBuildRequestFirstReport(t *testing.T) {
	now := time.Date(2026, 5, 21, 10, 0, 0, 0, time.Local)
	h := &heartbeatRuntime{
		clientID: "machine-id",
		nodeInfo: heartbeatNodeInfo{
			Hostname:      "gateway-prod-01",
			ClientIP:      "192.168.1.10",
			OSType:        "Linux",
			OSVersion:     "CentOS 7.9",
			SystemModel:   "PowerEdge",
			CPUCores:      "4",
			CPUModel:      "Intel Xeon",
			MemorySize:    "8GB",
			DiskSize:      "100GB",
			KernelVersion: "5.15.0",
			StartupTime:   "2026-05-21 09:55:00",
		},
		sendFullReport:   true,
		fullReportReason: heartbeatFullReportRestart,
	}
	payload, fullReport := h.buildRequest(now, true, heartbeatTrafficStat{
		InputCount:  12,
		OutputCount: 8,
		InputBytes:  1024,
		OutputBytes: 2048,
	})

	if !fullReport {
		t.Fatalf("expected first heartbeat to be a full report")
	}
	if payload.ClientID != "machine-id" {
		t.Fatalf("unexpected client id: %q", payload.ClientID)
	}
	if payload.Hostname != "gateway-prod-01" || payload.OSType != "Linux" || payload.CPUModel != "Intel Xeon" {
		t.Fatalf("full report fields missing: %#v", payload)
	}
	if payload.LastHeartbeatTime != "" {
		t.Fatalf("first heartbeat should not include lastHeartbeatTime, got %q", payload.LastHeartbeatTime)
	}
	if !payload.IsRestart {
		t.Fatalf("first heartbeat should set isRestart=true")
	}
	if payload.TrafficStat == nil || payload.TrafficStat.InputCount != 12 || payload.TrafficStat.OutputBytes != 2048 {
		t.Fatalf("unexpected traffic stat: %#v", payload.TrafficStat)
	}
}

func TestHeartbeatBuildRequestDisabledAndPreviousDay(t *testing.T) {
	last := time.Date(2026, 5, 21, 23, 59, 30, 0, time.Local)
	resetAt := time.Date(2026, 5, 22, 0, 0, 0, 0, time.Local)
	h := &heartbeatRuntime{
		clientID: "machine-id",
		nodeInfo: heartbeatNodeInfo{
			Hostname:    "gateway-prod-01",
			ClientIP:    "192.168.1.10",
			StartupTime: "2026-05-21 09:55:00",
		},
		sendFullReport:    false,
		fullReportReason:  heartbeatFullReportNone,
		lastHeartbeatTime: last,
	}
	h.setPreviousDayTraffic(heartbeatTrafficStat{
		InputCount:  99800,
		OutputCount: 99800,
		InputBytes:  4567890000,
		OutputBytes: 9876540000,
	}, resetAt)

	payload, fullReport := h.buildRequest(resetAt.Add(2*time.Minute), false, heartbeatTrafficStat{
		InputCount:  12,
		OutputCount: 12,
		InputBytes:  1024000,
		OutputBytes: 2048000,
	})

	if fullReport {
		t.Fatalf("expected normal heartbeat to omit full machine info")
	}
	if payload.Hostname != "" || payload.OSVersion != "" || payload.CPUModel != "" {
		t.Fatalf("normal heartbeat should omit machine info, got %#v", payload)
	}
	if payload.TrafficStat != nil {
		t.Fatalf("disabled collection should send trafficStat=null")
	}
	if payload.PreviousDayTrafficStat == nil || payload.PreviousDayTrafficStat.InputCount != 99800 {
		t.Fatalf("expected previous day traffic stat in rollover window, got %#v", payload.PreviousDayTrafficStat)
	}
	if payload.LastHeartbeatTime != "2026-05-21 23:59:30" {
		t.Fatalf("unexpected last heartbeat time: %q", payload.LastHeartbeatTime)
	}
	if payload.IsRestart {
		t.Fatalf("subsequent heartbeat should set isRestart=false")
	}
}

// 手动刷新
func TestHeartbeatBuildRequestManualRefreshFullReportIsNotRestart(t *testing.T) {
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.Local)
	h := &heartbeatRuntime{
		clientID: "machine-id",
		nodeInfo: heartbeatNodeInfo{
			Hostname:      "gateway-prod-01",
			ClientIP:      "192.168.1.10",
			OSType:        "Linux",
			OSVersion:     "CentOS 7.9",
			SystemModel:   "PowerEdge",
			CPUCores:      "4",
			CPUModel:      "Intel Xeon",
			MemorySize:    "8GB",
			DiskSize:      "100GB",
			KernelVersion: "5.15.0",
			StartupTime:   "2026-05-21 09:55:00",
		},
		sendFullReport:    true,
		fullReportReason:  heartbeatFullReportManualRefresh,
		lastHeartbeatTime: time.Date(2026, 5, 22, 11, 59, 30, 0, time.Local),
	}

	payload, fullReport := h.buildRequest(now, true, heartbeatTrafficStat{
		InputCount:  3,
		OutputCount: 2,
		InputBytes:  300,
		OutputBytes: 200,
	})

	if !fullReport {
		t.Fatalf("manual refresh should trigger a full report")
	}
	if payload.TrafficStat == nil || payload.TrafficStat.InputCount != 3 || payload.TrafficStat.OutputCount != 2 {
		t.Fatalf("manual refresh should keep current traffic stat, got %#v", payload.TrafficStat)
	}
	if payload.Hostname == "" || payload.CPUModel == "" {
		t.Fatalf("manual refresh full report should include hardware info: %#v", payload)
	}
	if payload.IsRestart {
		t.Fatalf("manual refresh full report should set isRestart=false")
	}
}

func TestStatsResetDailyCounters(t *testing.T) {
	s := &stats{
		rawBySource: map[string]sourceDirectionCounts{
			"tcp_sendmsg": {Request: 1},
		},
		updatesBySource: map[string]sourceUpdateCounts{
			"tcp_sendmsg": {Response: 2},
		},
	}
	s.requests.Store(9)
	s.responses.Store(8)
	s.inputBytes.Store(1024)
	s.outputBytes.Store(2048)
	s.tupleMiss.Store(3)

	s.resetDailyCounters()

	if got := s.requests.Load(); got != 0 {
		t.Fatalf("requests not reset: %d", got)
	}
	if got := s.responses.Load(); got != 0 {
		t.Fatalf("responses not reset: %d", got)
	}
	if got := s.inputBytes.Load(); got != 0 {
		t.Fatalf("inputBytes not reset: %d", got)
	}
	if got := s.outputBytes.Load(); got != 0 {
		t.Fatalf("outputBytes not reset: %d", got)
	}
	if got := s.tupleMiss.Load(); got != 0 {
		t.Fatalf("tupleMiss not reset: %d", got)
	}
	if s.rawBySource != nil || s.updatesBySource != nil {
		t.Fatalf("source maps should be cleared, got raw=%v updates=%v", s.rawBySource, s.updatesBySource)
	}
}
