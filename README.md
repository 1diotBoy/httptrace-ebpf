# power-ebpf

基于 `cilium/ebpf` 的 HTTP 全链路采集示例，目标是兼容 4.19 能力边界：

- 内核态用 `kprobe(sock_sendmsg)` 抓请求明文。
- 内核态用 `kprobe(sock_recvmsg) + kretprobe(sock_recvmsg)` 抓响应明文。
- 过滤规则通过 `bpf_map_update_elem` 写入 `filter_map`，内核按网卡 / IP / 端口过滤。
- 事件通过 `perf event array` 上送用户态，适配 4.19 不支持 `ringbuf` 的限制。
- 用户态按 `chain_id` 聚合请求/响应，解析 HTTP 头和 Body，计算响应延迟，并将 JSON 文档写入 Redis。

## 构建

```bash
make build
```

产物是静态 Go 二进制：

```bash
bin/httptrace
```

## 运行

```bash
sudo ./bin/httptrace \
  --ifname eth0 \
  --dst-port 80 \
  --redis-addr 127.0.0.1:6379
```

常用参数：

- `--ifname` / `--src-ip` / `--dst-ip` / `--src-port` / `--dst-port`
- `--capture-bytes` 控制单条 request/response 最多上送多少明文，默认和上限都是 `10KB`
- `--batch-size` / `--workers` / `--flush-interval` 控制用户态批量解析
- `--redis-addr` / `--redis-prefix` / `--redis-ttl` 控制 Redis 存储

## 设计说明

- `sock_recvmsg` 必须配合 `kretprobe`，因为返回前用户缓冲区里才有响应明文。
- 4.19 环境里不依赖 `ringbuf` 和 CO-RE/BTF。
- `chain_id` 用 `sock_id` 加应用层发送/接收游标进行稳定关联，并保留 `flow_map` 追踪分片状态。
- 对 chunked body 做了解析；对无 `Content-Length` 且依赖连接关闭结束的响应，会在 `tcp_close` 控制事件到来时尝试收尾。

## 目录结构

```text
.
├── bpf/
│   ├── http_trace.bpf.c        # eBPF 主程序，负责挂载、过滤、采集、上报
│   └── include/compat.h        # 4.19 风格兼容结构定义
├── cmd/httptrace/main.go       # CLI 入口
├── internal/app/               # loader、挂载、worker、统计、过滤补偿
├── internal/httptrace/         # HTTP 重组、解析、请求响应关联
├── internal/storage/redis.go   # Redis JSON 存储
├── internal/bpfgen/            # bpf2go 生成入口和嵌入后的字节码
└── scripts/strip-bpf.sh        # 生成后移除 BTF section，适配老内核
```

## 采集解析流程

1. `main.go` 解析参数，构造过滤规则并启动 `Service`。
2. `Service` 用 `cilium/ebpf` 加载 `bpf/http_trace.bpf.c` 并挂到 `sock_sendmsg` / `sock_recvmsg` / `kretprobe(sock_recvmsg)`。
3. 内核态先按 map 里的规则做第一层过滤，再把 HTTP 元数据和明文 fragment 通过 perf buffer 上送。
4. 用户态 `readLoop` 解码 perf 事件，并补一层 ifname/IP/端口对称过滤。
5. `workerLoop` 按批次把 fragment 交给 `Assembler`。
6. `Assembler` 按 `chain_id + frag_idx` 重组请求和响应；请求和响应分开打印、分开写 Redis，用同一个 `chain_id` 关联。超过 `10KB` 的请求体/响应体会标记截断，并直接丢弃后续片段。
7. `parser.go` 解析请求行/状态行、头、`Content-Length` / `chunked` body。
8. `storage/redis.go` 把结果 JSON 化并写入 Redis。
