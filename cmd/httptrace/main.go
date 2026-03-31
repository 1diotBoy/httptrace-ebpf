package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"power-ebpf/internal/app"
)

func main() {
	ensureStableBPFLoad()

	cfg := app.DefaultConfig()

	flag.StringVar(&cfg.IfName, "ifname", cfg.IfName, "filter by interface name")
	flag.StringVar(&cfg.SrcIP, "src-ip", cfg.SrcIP, "filter by IPv4 endpoint; if dst-ip is empty, matches either endpoint")
	flag.StringVar(&cfg.DstIP, "dst-ip", cfg.DstIP, "filter by IPv4 endpoint; if src-ip is empty, matches either endpoint")
	flag.UintVar(&cfg.SrcPort, "src-port", cfg.SrcPort, "filter by port endpoint; if dst-port is empty, matches either endpoint")
	flag.UintVar(&cfg.DstPort, "dst-port", cfg.DstPort, "filter by port endpoint; if src-port is empty, matches either endpoint")
	flag.IntVar(&cfg.CaptureBytes, "capture-bytes", cfg.CaptureBytes, "maximum payload bytes captured per request/response, values above 10KB are truncated")
	flag.IntVar(&cfg.PerfPages, "perf-pages", cfg.PerfPages, "perf buffer pages per CPU")
	flag.IntVar(&cfg.BatchSize, "batch-size", cfg.BatchSize, "events parsed per worker batch")
	flag.IntVar(&cfg.WorkerCount, "workers", cfg.WorkerCount, "number of parser workers")
	flag.IntVar(&cfg.RedisWorkers, "redis-workers", cfg.RedisWorkers, "number of async redis writer workers")
	flag.IntVar(&cfg.RedisQueueSize, "redis-queue-size", cfg.RedisQueueSize, "buffered redis write queue size")
	flag.DurationVar(&cfg.FlushInterval, "flush-interval", cfg.FlushInterval, "batch flush interval")
	flag.DurationVar(&cfg.LogInterval, "log-interval", cfg.LogInterval, "stats log interval")
	flag.BoolVar(&cfg.PrintHTTP, "print-http", cfg.PrintHTTP, "print parsed HTTP request/response to console")
	flag.BoolVar(&cfg.PrintSummary, "print-summary", cfg.PrintSummary, "print one-line request/response summary to console")
	flag.BoolVar(&cfg.DebugKernel, "debug-kernel", cfg.DebugKernel, "print extended kernel hook/branch diagnostics")
	flag.DurationVar(&cfg.TransactionTTL, "txn-ttl", cfg.TransactionTTL, "idle transaction eviction TTL")
	flag.IntVar(&cfg.MaxMessageBytes, "max-message-bytes", cfg.MaxMessageBytes, "maximum reassembled bytes kept per request/response before truncation")
	flag.StringVar(&cfg.RedisAddr, "redis-addr", cfg.RedisAddr, "redis address, empty disables redis write")
	flag.StringVar(&cfg.RedisPassword, "redis-password", cfg.RedisPassword, "redis password")
	flag.IntVar(&cfg.RedisDB, "redis-db", cfg.RedisDB, "redis DB index")
	flag.StringVar(&cfg.RedisKeyPrefix, "redis-prefix", cfg.RedisKeyPrefix, "redis key prefix")
	flag.DurationVar(&cfg.RedisTTL, "redis-ttl", cfg.RedisTTL, "redis key ttl")
	flag.Parse()
	log.Printf("starting httptrace pid=%d", os.Getpid())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	svc, err := app.NewService(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer svc.Close()

	runErrCh := make(chan error, 1)
	// 启动goroutine执行svc.Run
	go func() {
		runErrCh <- svc.Run(ctx)
	}()

	select {
	case err := <-runErrCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Fatal(err)
		}
	case <-ctx.Done():
		// 启动阶段如果卡在 BPF 加载里，主 goroutine 不能再同步阻塞等待；
		// 否则用户按 Ctrl+C 时会感觉“程序完全退不掉”。
		log.Printf("received interrupt, stopping httptrace...")
		select {
		case err := <-runErrCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				log.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			log.Printf("startup/shutdown is still busy, force exiting")
		}
	}
}

// ensureStableBPFLoad 通过自重启把 asyncpreemptoff=1 带进新的 Go runtime。
// 否则在某些内核上，长时间的 BPF_PROG_LOAD 会被 Go 的 SIGURG 异步抢占反复打断，
// 表现成“程序没输出、Ctrl+C 也很难停掉”。
func ensureStableBPFLoad() {
	const knob = "asyncpreemptoff=1"

	if strings.Contains(os.Getenv("GODEBUG"), knob) {
		return
	}

	exe, err := os.Executable()
	if err != nil {
		return
	}

	env := os.Environ()
	updated := false
	for i, item := range env {
		if !strings.HasPrefix(item, "GODEBUG=") {
			continue
		}
		value := strings.TrimPrefix(item, "GODEBUG=")
		if value == "" {
			env[i] = "GODEBUG=" + knob
		} else {
			env[i] = "GODEBUG=" + value + "," + knob
		}
		updated = true
		break
	}
	if !updated {
		env = append(env, "GODEBUG="+knob)
	}

	_ = syscall.Exec(exe, os.Args, env)
}
