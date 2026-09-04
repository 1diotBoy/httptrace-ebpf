package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
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
	// 加密
	sm4encryptStr := flag.String("sm4encryptStr", "", "传入密码，使用SM4加密后输出（不启动服务）")

	// 过滤规则配置
	flag.StringVar(&cfg.IfName, "ifname", cfg.IfName, "按网络接口名称过滤")
	flag.StringVar(&cfg.SrcIP, "src-ip", cfg.SrcIP, "按 IPv4 端点过滤；dst-ip 为空时匹配任一端点")
	flag.StringVar(&cfg.DstIP, "dst-ip", cfg.DstIP, "按 IPv4 端点过滤；src-ip 为空时匹配任一端点")
	flag.UintVar(&cfg.SrcPort, "src-port", cfg.SrcPort, "按端口端点过滤；dst-port 为空时匹配任一端点")
	flag.UintVar(&cfg.DstPort, "dst-port", cfg.DstPort, "按端口端点过滤；src-port 为空时匹配任一端点")
	flag.StringVar(&cfg.HeartbeatServer, "heartbeat-server", cfg.HeartbeatServer, "心跳服务器基础地址；设置后向 /v2/dataCollectClient/heartbeat 发送 POST 请求")
	flag.BoolVar(&cfg.EnableTLS, "enable-tls", cfg.EnableTLS, "通过 OpenSSL uprobe 开启 HTTPS 明文采集；默认关闭")
	flag.StringVar(&cfg.TLSLibPath, "tls-lib-path", cfg.TLSLibPath, "以逗号分隔的 libssl 路径覆盖项；为空时自动发现 nginx 映射的 libssl")
	flag.StringVar(&cfg.TLSComm, "tls-comm", cfg.TLSComm, "TLS uprobe 使用的进程 comm 名称，默认 nginx")
	flag.BoolVar(&cfg.SuppressSocketForTLS, "tls-suppress-socket", cfg.SuppressSocketForTLS, "启用 TLS 采集时，抑制同一 comm 的旧 socket HTTP 事件；默认关闭，以便同时采集 HTTP 和 HTTPS")
	flag.BoolVar(&cfg.DisableKernelFilter, "disable-kernel-filter", cfg.DisableKernelFilter, "关闭内核侧 IP/端口过滤以便隔离排查；perf 输出前跳过全部过滤")
	flag.BoolVar(&cfg.DisableUserTuple, "disable-user-tuple", cfg.DisableUserTuple, "关闭 /proc 五元组解析和用户态五元组过滤；可用时仍在输出中保留内核五元组")

	// 采集规则配置
	flag.IntVar(&cfg.CaptureBytes, "capture-bytes", cfg.CaptureBytes, "内核中每个请求/响应最多采集的负载字节数")
	flag.IntVar(&cfg.PerfPages, "perf-pages", cfg.PerfPages, "每个 CPU 的 perf 缓冲区页数")
	flag.IntVar(&cfg.BatchSize, "batch-size", cfg.BatchSize, "每个 worker 批量解析的事件数")
	flag.IntVar(&cfg.WorkerCount, "workers", cfg.WorkerCount, "解析 worker 数量")
	flag.IntVar(&cfg.WorkerQueueSize, "worker-queue-size", cfg.WorkerQueueSize, "每个 worker 缓存的解析事件数；0 表示按可用内存自动调整")
	flag.DurationVar(&cfg.TransactionTTL, "txn-ttl", cfg.TransactionTTL, "空闲事务淘汰 TTL")
	flag.IntVar(&cfg.MaxMessageBytes, "max-message-bytes", cfg.MaxMessageBytes, "每个请求/响应最多保留的重组字节数；应与内核采集上限保持一致")
	flag.IntVar(&cfg.AssemblerBufferBytes, "assembler-buffer-bytes", cfg.AssemblerBufferBytes, "进程范围内为不完整请求/响应片段保留的字节数")

	// 用户态日志配置
	flag.DurationVar(&cfg.FlushInterval, "flush-interval", cfg.FlushInterval, "批量刷新间隔")
	flag.DurationVar(&cfg.LogInterval, "log-interval", cfg.LogInterval, "统计日志间隔")
	flag.BoolVar(&cfg.PrintHTTP, "print-http", cfg.PrintHTTP, "将解析后的 HTTP 请求/响应打印到控制台")
	flag.BoolVar(&cfg.PrintSummary, "print-summary", cfg.PrintSummary, "将请求/响应单行摘要打印到控制台")
	flag.BoolVar(&cfg.DebugKernel, "debug-kernel", cfg.DebugKernel, "打印扩展的内核 hook/分支诊断信息")

	// nginx 响应等待
	flag.DurationVar(&cfg.ResponseStallTimeout, "response-stall-timeout", cfg.ResponseStallTimeout, "超过此空闲时间后刷新不完整响应，适用于 nginx/sendfile 类型响应路径")

	// redis 相关配置
	flag.IntVar(&cfg.RedisWorkers, "redis-workers", cfg.RedisWorkers, "异步 Redis 写入 worker 数量")
	flag.IntVar(&cfg.RedisQueueSize, "redis-queue-size", cfg.RedisQueueSize, "缓存的 Redis 写入队列记录数")
	flag.IntVar(&cfg.RedisQueueBytes, "redis-queue-bytes", cfg.RedisQueueBytes, "排队或执行中的 Redis 写入最多保留的字节数")
	flag.IntVar(&cfg.RetryQueueSize, "retry-queue-size", cfg.RetryQueueSize, "缓存的五元组重试队列大小；0 表示按可用内存自动调整")
	flag.StringVar(&cfg.RedisAddr, "redis-addr", cfg.RedisAddr, "Redis 地址；为空时关闭 Redis 写入")
	flag.StringVar(&cfg.RedisPassword, "redis-password", cfg.RedisPassword, "Redis 密码")
	flag.IntVar(&cfg.RedisDB, "redis-db", cfg.RedisDB, "Redis 数据库索引")
	flag.StringVar(&cfg.RedisKeyPrefix, "redis-prefix", cfg.RedisKeyPrefix, "Redis 键前缀")
	flag.DurationVar(&cfg.RedisTTL, "redis-ttl", cfg.RedisTTL, "Redis 键 TTL")

	flag.Usage = func() {
		fmt.Println("power-httptrace 用法：")
		// fmt.Println("=====================================")
		// fmt.Println("固定 SM4 密钥 (key):", app.SM4Key)
		// fmt.Println("固定 SM4 偏移量 (iv):", app.SM4IV)
		// fmt.Println("=====================================")
		// fmt.Println("其他命令行参数:")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *sm4encryptStr != "" {
		encryptStr, err := app.SM4Encrypt(*sm4encryptStr)
		if err != nil {
			fmt.Println("加密失败：", err)
			os.Exit(1)
		}
		fmt.Println("加密结果：", encryptStr)
		os.Exit(0)
	}

	log.Printf("正在启动 httptrace，pid=%d", os.Getpid())

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
		log.Printf("收到中断信号，正在停止 httptrace...")
		select {
		case err := <-runErrCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				log.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			log.Printf("启动或停止仍在处理中，强制退出")
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
