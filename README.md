# power-ebpf

基于 `cilium/ebpf` 的 HTTP 全链路采集示例，当前按内核系列自动选择采集 variant：

- `4.19.x / 4.x`：请求主路径 `kprobe(sock_recvmsg) + kretprobe(sock_recvmsg)`，响应主路径 `kprobe(sock_sendmsg)`，并保留 `tcp_sendmsg` 作为补充路径(nginx请求)。
- `5.15.x`：请求主路径 `kprobe(tcp_recvmsg) + kretprobe(tcp_recvmsg)`，响应主路径 `kprobe(tcp_sendmsg)`。
- `6.x`：仍走 `tcp_recvmsg/tcp_sendmsg`，但单独使用 6.x 专用 `iov_iter` 兼容布局，避免 `msg_iter` 解析错位导致“命中 hook 但没有 request/response 事件”。
- 过滤规则通过 `bpf_map_update_elem` 写入 `filter_map`，内核做第一层粗过滤，用户态再做一层精确补偿过滤。（暂时关闭过滤功能）
- 事件通过 `perf event array` 上送用户态，适配 4.19 不支持 `ringbuf` 的限制。
- 用户态按 `chain_id + frag_idx` 聚合请求/响应，解析 HTTP 头和 Body，计算响应延迟，并将 JSON 文档写入 Redis。

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
- `--capture-bytes` 控制单条 request/response 最多上送多少明文，默认和上限都是 `32KB`
- `--batch-size` / `--workers` / `--flush-interval` 控制用户态批量解析
- `--redis-addr` / `--redis-prefix` / `--redis-ttl` 控制 Redis 存储

高级调试参数：

- `POWER_EBPF_OBJECT_VARIANT=legacy|tcp|tcp-6.x|modern` 可强制选择某一套内核态 variant，默认自动按内核版本选择。
- `POWER_EBPF_VERIFIER_LOG=1` 打开 verifier 指令日志，便于定位不同内核上的加载失败原因。

## 设计说明

- `sock_recvmsg` 必须配合 `kretprobe`，因为返回前用户缓冲区里还没有收到完整明文。
- 请求和响应都可能跨多次 `recv/send syscall`，内核只负责切片上报，用户态按 `chain_id + frag_idx` 重组，不做 TCP 报文重组。
- `chain_id` 由 `conn_id + req_seq + rx_cursor` 组合生成，同一条 keep-alive 连接上的多次请求/响应会得到不同 `chain_id`。（处理jmeter环境下keep-alive）
- 对 chunked body 做了解析；对无 `Content-Length` 且依赖连接关闭结束的响应，会在 `tcp_close` 控制事件到来时尝试收尾。
- 对 Nginx 这类“头和体不一定都走 `sock_sendmsg`”的场景，`tcp_sendmsg` 只作为补充源，事件里会带 `capture_source` 标识来源。

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
2. `Service` 用 `cilium/ebpf` 加载 `bpf/http_trace.bpf.c`，并按内核版本自动选择：
   - `4.x`：`sock_recvmsg + kretprobe(sock_recvmsg)` 抓请求，`sock_sendmsg` 抓响应，`tcp_sendmsg` 做补充
   - `5.15.x`：`tcp_recvmsg + kretprobe(tcp_recvmsg)` 抓请求，`tcp_sendmsg` 抓响应
   - `6.x`：同样走 `tcp_recvmsg + kretprobe(tcp_recvmsg)` / `tcp_sendmsg`，但使用 6.x 专用 `iov_iter` 对象版本
   - 共同挂载 `tcp_close`：给依赖连接关闭结束的响应补收尾信号
3. 内核态每次上送 `http_event`，里面包含：
   - `chain_id`、`sock_id`、`seq_hint`
   - `pid/tid/fd/comm`
   - `src_ip/dst_ip/src_port/dst_port/ifindex`
   - `direction`、`flags`、`capture_source`
   - `frag_idx`、`payload_len`、`payload`
4. 用户态 `readLoop` 解码 perf 事件，先尝试基于 `pid+fd+/proc` 补全五元组。
5. 如果第一次 tuple 反查失败，但事件方向明确且是有效数据，会进入短暂重试队列，避免请求/响应起始片段过早被端口过滤掉。
6. 通过过滤后的事件按 worker 批量送入 `Assembler`，按 `chain_id + frag_idx` 重组请求流和响应流。
7. `parser.go` 解析请求行/状态行、头、`Content-Length` / `chunked` body；请求和响应分开输出、分开入 Redis，用同一个 `chain_id` 关联。
8. 如果响应长期没有新片段，`Assembler` 会按空闲超时或 `tcp_close` 信号把部分响应先收尾输出，避免 Nginx keep-alive 场景下一直挂住。
