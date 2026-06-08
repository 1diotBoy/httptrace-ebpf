# Power-HTTPTrace eBPF 全链路 HTTP 采集系统 — 技术介绍文档

---

## 一、eBPF 简介与技术选型

### 1.1 什么是 eBPF

eBPF（extended Berkeley Packet Filter）是 Linux 内核中的一项革命性技术，允许在**不修改内核源码、不加载内核模块**的前提下，将用户编写的沙箱化程序安全地注入内核态运行。eBPF 程序经过严格的 **verifier（验证器）** 静态分析，确保不会导致内核崩溃或死循环，然后通过 JIT 编译为本地指令执行，性能极高。

eBPF 的核心能力：
- **kprobe/kretprobe**：动态挂载到任意内核函数的入口和返回点
- **tracepoint**：挂载到内核预定义的静态追踪点
- **uprobe/uretprobe**：挂载到用户态进程的任意函数入口和返回点
- **perf_event / ringbuf**：高效地将内核采集的数据推送到用户态
- **BPF maps**：内核态与用户态之间共享数据的哈希表/数组结构

### 1.2 为什么选择 eBPF 做 HTTP 旁路采集

| 对比维度 | eBPF 旁路采集 | 传统 Agent/插件方式 | 网络抓包（tcpdump/Wireshark） | Service Mesh Sidecar |
|---------|-------------|------------------|---------------------------|---------------------|
| **侵入性** | **零侵入**，无需修改应用代码或配置 | 需嵌入 SDK 或修改启动参数 | 零侵入 | 需注入 Sidecar 容器 |
| **性能开销** | 极低（内核态 JIT 执行，按需采样） | 应用内采集，消耗业务线程 CPU | 旁路抓包，但全量拷贝到用户态 | 代理转发，增加网络跳数和延迟 |
| **HTTPS 支持** | 通过 uprobe 挂载 SSL_read/SSL_write 解密后的明文 | 需应用配合导出 | 需要私钥才能解密 | 需配合 mTLS |
| **内核版本适配** | 需针对不同内核做兼容适配 | 不涉及内核 | 不涉及内核 | 不涉及内核 |
| **部署复杂度** | 部署一个二进制 + systemd 服务 | 每个应用单独集成 | 安装抓包工具 | 需容器编排配合 |

**选择 eBPF 的核心原因：**

1. **零侵入**：不需要修改 Nginx/Java 应用的任何代码、配置或启动参数，也不需要在 Pod 里注入 Sidecar。
2. **旁路采集**：不在业务请求的主链路上，即使采集器宕机也不影响业务流量。
3. **性能优秀**：内核态做第一层过滤和截断（默认 32KB），只有有效 HTTP 流量才上送用户态，perf buffer 压力可控。
4. **能拿到完整明文**：在内核 `recvmsg` 返回之后、`sendmsg` 发送之前读取用户态缓冲区，此时 TLS 已经由应用层解密完成（若配合 OpenSSL uprobe 则直接在加密前/解密后截获明文）。

### 1.3 工作机制概述

```
                        ┌─────────────────────────────────┐
                        │         应用进程 (Nginx/Java)      │
                        │   SSL_read() / SSL_write()       │
                        │   recv() / send()                │
                        └──────────┬──────────────────────┘
                                   │ 系统调用
                        ┌──────────▼──────────────────────┐
                        │     Linux 内核网络栈              │
                        │                                  │
                        │  kprobe(tcp_recvmsg)             │
                        │  kretprobe(tcp_recvmsg)  ◄── 采集请求明文
                        │  kprobe(tcp_sendmsg)     ◄── 采集响应明文
                        │  tracepoint(sys_enter_*) ◄── 获取 fd
                        │  tracepoint(inet_sock_set_state) ◄── 维护五元组
                        │                                  │
                        │  ┌──────────────────────┐        │
                        │  │ eBPF 程序 (内核态)    │        │
                        │  │ - HTTP 方向识别      │        │
                        │  │ - IP/端口过滤        │        │
                        │  │ - fragment 切片上传  │        │
                        │  │ - perf_event 输出    │        │
                        │  └──────────────────────┘        │
                        └──────────┬──────────────────────┘
                                   │ perf event array
                        ┌──────────▼──────────────────────┐
                        │     用户态 Go 程序 (httptrace)    │
                        │                                  │
                        │  - 解码 perf 事件                │
                        │  - /proc 五元组补全              │
                        │  - 按 chain_id + frag_idx 重组  │
                        │  - HTTP 协议解析                 │
                        │  - JSON 写入 Redis               │
                        └─────────────────────────────────┘
```

### 1.4 Java 端如何对接旁路模块（Redis 消费）

旁路采集器将解析后的 HTTP 请求/响应以 JSON 形式写入 Redis List，Java 端通过消费 Redis 获取全链路数据：

```
Java 消费端伪代码:
┌────────────────────────────────────────────┐
│  String key = "POWER-HTTP-TRACE";          │
│  while (true) {                            │
│      // 阻塞式从 Redis List 右侧弹出       │
│      String json = redis.brpop(key);       │
│      HttpTrace trace = parseJson(json);     │
│                                              │
│      if ("request".equals(trace.kind)) {     │
│          // 处理请求数据                     │
│          // chain_id 用于关联后续响应        │
│          saveRequest(trace);                │
│      } else if ("response".equals(trace.kind)) { │
│          // 处理响应数据                     │
│          // 通过 chain_id 关联请求           │
│          // response_latency_ms 为响应延迟   │
│          saveResponse(trace);               │
│      }                                      │
│  }                                          │
└────────────────────────────────────────────┘

Redis Key 说明:
  POWER-HTTP-TRACE       → List 结构, 存储全部 HTTP Trace JSON
  AAA-diaoge-trace       → List 结构, 测试调试用备份
```

每条 JSON 的关键字段：

| 字段 | 说明 |
|------|------|
| `kind` | `"request"` 或 `"response"` |
| `chain_id` | 唯一链路 ID，请求和响应通过此字段关联 |
| `src_ip` / `dst_ip` | 源 IP / 目的 IP |
| `src_port` / `dst_port` | 源端口 / 目的端口 |
| `capture_source` | 采集来源（`sock_sendmsg` / `tcp_sendmsg` 等） |
| `request` | 解析后的请求对象（方法、URL、Header、Body） |
| `response` | 解析后的响应对象（状态码、Header、Body） |
| `response_latency_ms` | 响应延迟（请求开始到响应开始，单位毫秒） |
| `request_truncated` | 请求是否被截断 |
| `response_truncated` | 响应是否被截断 |

---

## 二、部署与运行环境

### 2.1 运行环境要求

| 项目 | 要求 |
|------|------|
| **操作系统** | Linux（Kylin v10、UOS、CentOS、Ubuntu 等） |
| **内核版本** | **4.19.x / 5.15.x / 6.x** 均支持 |
| **架构** | **amd64** (x86_64) / **arm64** (aarch64) |
| **权限** | **root** 运行（eBPF 需要 CAP_BPF / CAP_SYS_ADMIN） |
| **Redis** | 可选，用于存储采集结果（不配置则仅控制台输出） |
| **依赖** | 静态编译的 Go 二进制，无运行时依赖 |

**内核版本兼容矩阵：**

| 内核系列 | Hook 策略 | 说明 |
|---------|----------|------|
| 4.19.x (4.x) | `sock_sendmsg` + `sock_recvmsg`/`kretprobe(sock_recvmsg)` + `tcp_sendmsg` 补充 | 兼容 4.19 verifier 限制，使用 tuple-cache 做五元组过滤 |
| 5.15.x | `tcp_sendmsg` + `tcp_recvmsg`/`kretprobe(tcp_recvmsg)` | 标准 TCP 层采集 |
| 6.x | 同上，但使用 6.x 专用 `iov_iter` 布局 | ITER_UBUF 兼容，避免 `msg_iter` 解析错位 |

### 2.2 打包方式

#### RPM 包（Kylin / CentOS）

```bash
# 构建
make build-amd64    # 或 make build-arm64

# 打包 RPM
rpmbuild -bb packaging/power-httptrace.spec

# 产物
power-httptrace-1.0.0-1.ky10.x86_64.rpm
```

#### DEB 包（Ubuntu / Debian / UOS）

```bash
# 使用打包脚本
bash scripts/deb-pkg.sh

# 产物
power-httptrace_1.0.0-1_amd64.deb
```

#### 手动部署

```bash
# 直接复制二进制
cp bin/httptrace-linux-amd64 /app/soft/power-httptrace/bin/httptrace
chmod +x /app/soft/power-httptrace/bin/httptrace
```

### 2.3 安装后的目录结构

```
/app/soft/power-httptrace/           ← 安装根目录
├── bin/
│   └── httptrace                    ← 主程序（静态 Go 二进制）
/app/log/power-httptrace/            ← 日志目录
├── console.log                      ← 运行日志（systemd 重定向输出）
/etc/sysconfig/power-httptrace       ← 配置文件（环境变量 + 启动参数）
/etc/logrotate.d/power-httptrace     ← 日志轮转配置
/usr/lib/systemd/system/power-httptrace.service  ← systemd 服务文件
```

### 2.4 主要配置参数详解

配置文件路径：`/etc/sysconfig/power-httptrace`

```
HTTPTRACE_ARGS="参数列表"
```

**过滤类参数（控制采集哪些流量）：**

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--ifname` | 空 | 按网卡名过滤（如 `eth0`，通过接口 IPv4 做用户态补偿过滤） |
| `--src-ip` | 空 | 按源 IP 过滤；若 dst-ip 为空则匹配任意一端 |
| `--dst-ip` | 空 | 按目的 IP 过滤；若 src-ip 为空则匹配任意一端 |
| `--src-port` | 0 | 按源端口过滤 |
| `--dst-port` | 0 | 按目的端口过滤 |
| `--disable-kernel-filter` | false | 禁用内核态 IP/端口过滤（调试用，全量上报） |
| `--disable-user-tuple` | true | 禁用 /proc 五元组反查和用户态过滤 |

**采集控制参数：**

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--capture-bytes` | 32768 | 单条请求/响应最多采集字节数，上限 32KB |
| `--max-message-bytes` | 32768 | 用户态重组后保留的最大字节数 |
| `--perf-pages` | 64 | 每个 CPU 的 perf buffer 页数（自动按内存调优） |
| `--enable-tls` | false | 启用 HTTPS 明文采集（通过 OpenSSL uprobe） |
| `--tls-lib-path` | 空 | 手动指定 libssl.so 路径，空则自动发现 |
| `--tls-comm` | nginx | TLS uprobe 目标进程名 |

**性能调优参数：**

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--workers` | min(CPU核数, 8) | 用户态解析工作线程数 |
| `--batch-size` | 100 | 每批处理的事件数 |
| `--worker-queue-size` | 自动 | 每个 Worker 的事件缓冲队列深度 |
| `--flush-interval` | 200ms | 批量刷新间隔 |
| `--txn-ttl` | 10m | 空闲事务超时淘汰时间 |
| `--response-stall-timeout` | 500ms | 响应片段无新数据时的超时刷新 |
| `--redis-workers` | min(CPU/2, 4) | 异步 Redis 写入线程数 |
| `--redis-queue-size` | 4096 | Redis 写入队列大小 |

**Redis 存储参数：**

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--redis-addr` | 空 | Redis 地址（`host:port`），空则不写入 Redis |
| `--redis-password` | 内置 SM4 加密值 | Redis 密码（用 SM4 加密后的 Base64） |
| `--redis-db` | 0 | Redis 数据库编号 |
| `--redis-prefix` | http-trace | Redis Key 前缀 |
| `--redis-ttl` | 24h | Redis Key 过期时间 |

**调试参数：**

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--print-http` | true | 控制台打印完整 HTTP 请求/响应 JSON |
| `--print-summary` | true | 控制台打印单行摘要 |
| `--debug-kernel` | false | 打印内核态 hook/分支诊断信息 |
| `--log-interval` | 5s | 统计日志打印间隔 |

**环境变量（高级调试）：**

| 变量 | 说明 |
|------|------|
| `POWER_EBPF_OBJECT_VARIANT` | 强制选择 eBPF 对象变体：`legacy` / `tcp-5.15+` / `tcp-6.x` / `modern` |
| `POWER_EBPF_VERIFIER_LOG` | 设为 `1` 打开 verifier 指令日志（排查加载失败） |

---

## 三、工程代码架构

### 3.1 项目目录结构

```
httptrace-ebpf/
├── bpf/                              ← 内核态 eBPF C 程序
│   ├── http_trace.bpf.c              ← 核心：kprobe/tracepoint 挂载、HTTP 识别、切片上传
│   ├── tls_trace.bpf.c               ← TLS uprobe：挂载 SSL_read/SSL_write 截获明文
│   └── include/compat.h              ← 跨内核版本兼容结构定义
├── cmd/httptrace/main.go             ← CLI 入口，参数解析，服务启动
├── internal/
│   ├── app/
│   │   ├── config.go                 ← 配置结构、过滤规则、资源规划、SM4 加密
│   │   ├── service.go                ← 核心服务：BPF 加载、probe 挂载、readLoop、worker、日志
│   │   └── socket_resolver.go        ← 五元组反查：通过 /proc/pid/fd 和 /proc/net/tcp 补全
│   ├── httptrace/
│   │   ├── assembler.go              ← 用户态重组引擎：按 chain_id + frag_idx 聚合 fragment
│   │   └── parser.go                 ← HTTP 协议解析：请求行/状态行/Header/body/chunked
│   ├── bpfgen/                       ← bpf2go 生成的 Go 绑定代码（多架构多版本）
│   │   ├── gen.go                    ← go:generate 指令（编译 .bpf.c → .bpfel.o → .bpfel.go）
│   │   ├── load.go                   ← 内核版本检测、变体选择、对象加载
│   │   ├── types.go                  ← 内核态/用户态共享的数据结构定义
│   │   └── tlsgen.go / tlsload.go    ← TLS uprobe 对象的生成和加载
│   ├── tlstrace/
│   │   ├── attach.go                 ← TLS uprobe 挂载（SSL_read/SSL_write/SSL_free 等）
│   │   └── discovery.go              ← libssl.so 路径自动发现（扫描 /proc/pid/maps）
│   └── storage/
│       └── redis.go                  ← Redis JSON 存储（LPush 写入 List）
├── Makefile                          ← 构建：generate → build → build-amd64/build-arm64
├── packaging/                        ← RPM 打包相关
│   ├── power-httptrace.spec          ← RPM spec 文件
│   ├── SOURCES/                      ← systemd service、sysconfig、logrotate
│   └── Install/                      ← 部署说明文档
├── scripts/
│   ├── strip-bpf.sh                  ← 生成后移除 BTF section（适配老内核）
│   └── deb-pkg.sh                    ← DEB 打包脚本
└── ubuntu-deb/                       ← DEB 打包文件
```

### 3.2 核心模块职责

```
┌──────────────────────────────────────────────────────────────────┐
│                      cmd/httptrace/main.go                       │
│  入口：解析参数 → 构建 Config → NewService → svc.Run(ctx)       │
└──────────────────────────────┬───────────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────────┐
│                   internal/app/service.go                        │
│  Service.Run():                                                  │
│  1. LoadObjects() → 按内核版本选择 eBPF 变体                    │
│  2. installFilter() → 写入内核 filter_map                        │
│  3. attachAll() → 挂载 kprobe/kretprobe/tracepoint               │
│  4. startRedisWriters() → 启动 Redis 异步写入 goroutine          │
│  5. startWorkers() → 启动解析 worker goroutine                   │
│  6. readLoop() → 从 perf buffer 读取事件，解码/补全/分发         │
│  7. logLoop() → 周期性打印统计、stalled flush、过期淘汰          │
└──────────────────────────────┬───────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
┌──────────────┐  ┌──────────────────┐  ┌──────────────────┐
│ socket_      │  │ httptrace/       │  │ storage/         │
│ resolver.go  │  │ assembler.go     │  │ redis.go         │
│              │  │ parser.go        │  │                  │
│ 五元组补全   │  │ 事件重组+解析    │  │ JSON Redis 写入  │
│ /proc 反查   │  │ chain_id 关联    │  │ LPush            │
└──────────────┘  └──────────────────┘  └──────────────────┘
```

### 3.3 启动流程

```
main()
  │
  ├─ ensureStableBPFLoad()       ← 自重启设置 GODEBUG=asyncpreemptoff=1
  │                                 (避免 BPF 加载被 SIGURG 抢占卡死)
  ├─ DefaultConfig()             ← 构建默认配置
  ├─ flag.Parse()                ← 解析命令行参数
  ├─ signal.NotifyContext()      ← 注册 SIGINT/SIGTERM 处理
  └─ NewService(cfg)
       │
       ├─ cfg.normalizedForHost() ← 按主机内存自动调优队列/worker
       ├─ cfg.ResolveFilter()     ← 解析过滤规则（IP/端口/网卡）
       └─ NewRedisStore()         ← 连接 Redis
            │
            └─ svc.Run(ctx)
                 │
                 ├─ rlimit.RemoveMemlock()     ← 解除内存锁限制
                 ├─ LoadObjects()              ← 加载 eBPF 对象（自动选择变体）
                 ├─ installFilter()            ← 写入内核过滤规则
                 ├─ attachAll()                ← 挂载 kprobe/tracepoint
                 │    ├── 必需：kprobe + kretprobe (sendmsg/recvmsg)
                 │    ├── 可选：tcp_sendmsg/tcp_recvmsg (补充路径)
                 │    ├── 辅助：tcp_close (关闭信号)
                 │    ├── 五元组：tcp_v4/v6_connect, inet_csk_accept
                 │    └── tracepoint：sys_enter_* (fd 获取), inet_sock_set_state
                 ├─ startRedisWriters()        ← 启动 Redis 写入 goroutine
                 ├─ startWorkers()             ← 启动解析 worker goroutine
                 ├─ readLoop()                 ← 主循环：读取 perf buffer → 解码 → 分发
                 └─ logLoop()                  ← 统计日志 + stalled flush + 过期淘汰
```

### 3.4 eBPF 对象变体策略

由于不同内核版本的 verifier 能力和 `iov_iter` 内存布局差异很大，项目编译了 **7 套 eBPF 对象变体**，运行时自动选择：

```
编译宏                         变体名               内核目标
────────────────────────────────────────────────────────────────
(默认, -O2)                    tcp-5.15+           5.15.x（默认）
-O1, -DCOMPACT_VERIFIER=1     tcp-5.15-compact    5.15.x（兼容模式）
-O2, -DIOV_ITER_LAYOUT_V6=1   tcp-6.x             6.x
-O1, -DIOV_ITER_LAYOUT_V6=1   tcp-6.x-compact     6.x（兼容模式）
  -DCOMPACT_VERIFIER=1
-O2, -DIOV_ITER_LAYOUT_V66=1  tcp-6.6             6.6
-O1, -DIOV_ITER_LAYOUT_V66=1  tcp-6.6-compact     6.6（兼容模式）
  -DCOMPACT_VERIFIER=1
-O1, -DLEGACY_VERIFIER=1      legacy-4.x          4.19.x
```

选择策略（`load.go:chooseVariantPlans()`）：
1. 若设置了 `POWER_EBPF_OBJECT_VARIANT` 环境变量 → 强制使用指定变体
2. 否则检测 `/proc/version` 内核版本 → 按内核大版本号选择
3. 特殊内核 profile（已知的厂商内核如 Kylin v10）使用特定变体列表
4. 加载失败时自动尝试下一个变体（verifier 拒绝 → 回退到 legacy/compact）

---

## 四、数据采集流程详解

### 4.1 整体流程图（内核态 ↔ 用户态交互）

```
                        应用层 (Nginx / Java)
                              │
          ┌───────────────────┼───────────────────┐
          │ recv()/read()     │                   │ send()/write()
          ▼                   │                   ▼
 ┌────────────────────┐       │          ┌────────────────────┐
 │ sys_enter_recvfrom │       │          │ sys_enter_sendto   │  ← tracepoint (获取 fd)
 │ sys_enter_recvmsg  │       │          │ sys_enter_sendmsg  │
 │ sys_enter_read     │       │          │ sys_enter_write    │
 │ sys_enter_readv    │       │          │ sys_enter_writev   │
 └────────┬───────────┘       │          └────────┬───────────┘
          │ stash fd          │                   │ stash fd
          ▼                   │                   ▼
 ┌────────────────────┐       │          ┌────────────────────┐
 │ kprobe(sock_recvmsg│       │          │ kprobe(sock_sendmsg │  ← 入口 kprobe
 │      /tcp_recvmsg) │       │          │      /tcp_sendmsg) │
 └────────┬───────────┘       │          └────────┬───────────┘
          │                    │                   │
          │ store_recv_args()  │                   │ prepare_send_scratch()
          │ → 保存 msg_iter    │                   │ → 保存 iov_iter
          │ → 提取五元组        │                   │ → 提取五元组
          │ → 过滤检查          │                   │ → 过滤检查
          │                    │                   │ → select_response_chain()
          ▼                    │                   ▼
 ┌────────────────────┐       │          ┌────────────────────┐
 │ kretprobe(recvmsg) │       │          │ handle_send_entry()│  ← 发送就在入口处理
 └────────┬───────────┘       │          └────────┬───────────┘
          │                    │                   │
          │ handle_recv_return │                   │ capture_response_message()
          │ → 读 iov 前缀      │                   │ → 切片上传 payload
          │ → 识别 HTTP 方向   │                   │ → flag=START/END/CAPTURE_TRUNC
          │ → 分配 chain_id    │                   │
          │ → capture_message  │                   │
          │   切片上传 payload  │                   │
          ▼                    │                   ▼
 ┌─────────────────────────────────────────────────────────────┐
│                    perf_event_array (per-CPU)                 │
│                    ┌──────────────────────┐                   │
│                    │ struct http_event {  │                   │
│                    │  chain_id, frag_idx, │                   │
│                    │  direction, flags,   │                   │
│                    │  src_ip/dst_ip,      │                   │
│                    │  pid, tid, fd, comm  │                   │
│                    │  payload[4096]       │  ← 每片最多 4KB  │
│                    │ }                    │                   │
│                    └──────────────────────┘                   │
└───────────────────────────┬─────────────────────────────────┘
                            │ bpf_perf_event_output()
════════════════════════════╪══════════════════════════════════
                            │ 用户态 perf.Reader
                            ▼
 ┌─────────────────────────────────────────────────────────────┐
│                   readLoop() — 事件读取循环                    │
│                                                              │
│  record ← reader.Read()                                      │
│       │                                                      │
│       ▼                                                      │
│  decodeRawEvent(record.RawSample) → HttpTraceHttpEvent       │
│       │                                                      │
│       ▼                                                      │
│  normalizeEvent() → Event (用户态友好格式)                     │
│       │                                                      │
│       ▼                                                      │
│  resolveEvent() — /proc 五元组补全                            │
│       │                                                      │
│       ├─ cache 命中 → 直接使用                                │
│       ├─ /proc/pid/fd/ + /proc/net/tcp → 解析                │
│       └─ 失败 → 进入重试队列 (10/30/100ms 三次重试)           │
│            │                                                 │
│            ▼                                                 │
│  dispatchEvent() — 用户态过滤 + 分发到 worker                  │
│       │                                                      │
│       ├─ filter.MatchDetail() → IP/端口/网卡 精确过滤         │
│       ├─ passThrough 机制：五元组暂缺时先放行                  │
│       └─ worker[CPU%N] ← event                               │
└──────────────────────────────┬──────────────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │   workerLoop()      │  ← 批量处理
                    │                     │
                    │ batch[] ← events    │
                    │ flush 触发:         │
                    │  - batch 满 100 条  │
                    │  - flushInterval    │
                    │       │            │
                    │       ▼            │
                    │ assembler.Process()│
                    └──────────┬─────────┘
                               │
                    ┌──────────▼──────────────────────────────┐
                    │        Assembler (重组引擎)               │
                    │                                          │
                    │  stateMap[chain_id] → traceState {       │
                    │    requestStream:  fragmentStream        │
                    │    responseStream: fragmentStream        │
                    │  }                                       │
                    │                                          │
                    │  Process():                              │
                    │  1. shard = shards[chain_id % 64]  ← 分片 │
                    │  2. received[frag_idx] = payload         │
                    │  3. drain() → 按 nextFrag 顺序组装到 buffer│
                    │  4. tryEmitUpdates():                    │
                    │     ├─ emitRequests() ← parser 解析       │
                    │     │   - TryParseMessage()              │
                    │     │   - 识别 Content-Length/chunked    │
                    │     │   - 完整则 emit request Update      │
                    │     │   - 不完整则等待更多 fragment       │
                    │     └─ emitResponses()                   │
                    │         - 关联 pending request           │
                    │         - 计算 ResponseLatency           │
                    │         - emit response Update           │
                    └──────────┬──────────────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │   handleUpdate()    │
                    │                     │
                    │  - PrintSummary     │
                    │  - PrintHTTP (JSON) │
                    │  - writeCh ← Update │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  RedisWriter (异步) │
                    │                     │
                    │  LPush "POWER-      │
                    │  HTTP-TRACE" body   │
                    │  (JSON TraceDoc)    │
                    └────────────────────┘
```

### 4.2 关键数据结构流动

```
内核态 struct http_event (C)          用户态 Event (Go)           用户态 TraceDocument (JSON)
══════════════════════════════        ═══════════════════         ═══════════════════════
chain_id          (u64)       →       ChainID   (uint64)   →     chain_id
sock_id           (u64)       →       SockID    (uint64)   →     sock_id
ts_ns             (u64)       →       Timestamp (time.Time)→     request_ts / response_ts
pid/tid           (u32/u32)   →       PID/TID               →     pid / tid
fd                (s32)       →       FD      (int32)       →     fd
src_ip/dst_ip     (u32/u32)   →       SrcIP/DstIP (string)  →     src_ip / dst_ip
src_port/dst_port (u16/u16)   →       SrcPort/DstPort       →     src_port / dst_port
direction         (u8)        →       Direction             →     (kind: "request"/"response")
flags             (u8)        →       Flags                 →     (truncated)
frag_idx          (u16)       →       FragIdx               →     (组装用，不出现在最终文档)
payload_len       (u16)       →       Payload ([]byte)      →     (参与 HTTP 解析)
payload[4096]     (u8[4096])  →       Payload ([]byte)      →     (参与 HTTP 解析)
source            (u8)        →       Source  (string)      →     capture_source
comm[16]          (char[16])  →       Comm    (string)      →     comm
observed_message_bytes (u64)  →       ObservedMessageBytes  →     observed_message_bytes
                                    ↓ HTTP Parser 解析后
                                    ParsedMessage {
                                      Method, URL, StatusCode
                                      Headers, Body
                                      ContentLength
                                      Chunked, BodyPartial
                                    }
```

### 4.3 chain_id 生成与 Keep-Alive 处理

`chain_id` 是整个采集系统的核心关联字段，其生成逻辑在 eBPF 内核态完成：

```c
// 位于 bpf/http_trace.bpf.c
conn_id = random_u32 << 32 ^ ktime_get_ns() ^ sock_id;  // 连接级唯一 ID
req_seq++;                                                // 每次新请求递增
chain_id = conn_id ^ (req_seq << 32) ^ rx_cursor;         // 保证同连接的多次请求唯一
```

**Keep-Alive 场景处理**：
- 同一 TCP 连接上的多轮请求/响应，`req_seq` 递增保证 `chain_id` 不同
- `push_pending_request` / `pop_pending_request` 维护请求队列（最多 4 个槽位）
- 响应通过队列 FIFO 出队与请求一一配对
- 无 Content-Length 的响应通过 `tcp_close` 控制事件收尾

### 4.4 HTTP 方向识别

在内核态的 `kretprobe(recvmsg)` 返回点读取用户态缓冲区的前缀字节来判断 HTTP 方向：

```
读取 iov 前缀 (最多16字节)
    │
    ▼
looks_like_http_request() ─── GET / POST / PUT / PATCH / DELETE / HEAD / OPTIONS / TRACE / CONNECT
    │                         (还支持短前缀匹配，如高并发下第一包只读到 "G" / "PO")
    ▼                         → DIR_REQUEST → 分配新 chain_id
looks_like_http_response() ── HTTP/ 开头
    │                          → DIR_RESPONSE → 跳过（响应不走 recv）
    ▼
DIR_UNKNOWN ── 如果当前有活跃请求，则延续上一个 chain_id
    │                          (body/后续片段不会以 HTTP 方法开头)
    └─ 无活跃请求 → 跳过（非 HTTP 流量）
```

### 4.5 三种响应收尾机制

| 机制 | 触发条件 | 说明 |
|------|---------|------|
| **正常解析** | Content-Length 到达 / chunked 结束标记 | 标准 HTTP 响应完整 |
| **Stalled Flush** | 响应 buffer 有数据但超时无新片段（默认 500ms） | Nginx sendfile/chunked 响应持续发送但无完整结束 |
| **tcp_close** | TCP 连接关闭 | 内核态发送 `EVT_FLAG_CLOSE` 控制事件，用户态做最终收尾 |

---

## 五、运行示例

### 5.1 启动命令示例

```bash
# 基础运行：监听 eth0 网卡 80 端口流量，写入 Redis
sudo ./bin/httptrace \
  --ifname eth0 \
  --dst-port 80 \
  --redis-addr 127.0.0.1:6379 \
  --redis-password "your-sm4-encrypted-password"

# 调试模式：打印完整 HTTP 请求/响应到控制台
sudo ./bin/httptrace \
  --ifname eth0 \
  --dst-port 55555 \
  --print-http=true \
  --print-summary=true \
  --debug-kernel=true \
  --workers 4 \
  --log-interval 10s
```

### 5.2 采集输出示例

**控制台摘要输出：**
```
[worker=0] request chain=0x9a3f2c1b8e4d5a01 pid=12345 fd=12 source=sock_recvmsg GET /api/users
[worker=0] response chain=0x9a3f2c1b8e4d5a01 pid=12345 fd=12 source=sock_sendmsg 200 15.32ms
```

**Redis JSON 输出（请求）：**
```json
{
  "kind": "request",
  "chain_id": 1111222233334444,
  "pid": 12345,
  "tid": 12345,
  "fd": 12,
  "comm": "nginx",
  "capture_source": "sock_recvmsg",
  "src_ip": "10.0.0.100",
  "dst_ip": "10.0.0.200",
  "src_port": 52341,
  "dst_port": 80,
  "request": {
    "method": "POST",
    "url": "/api/users",
    "version": "HTTP/1.1",
    "start_line": "POST /api/users HTTP/1.1",
    "headers": {
      "Content-Type": "application/json",
      "Host": "10.0.0.200",
      "Content-Length": "45"
    },
    "body": "{\"name\":\"test\",\"email\":\"test@example.com\"}",
    "body_size_bytes": 45,
    "content_length": 45,
    "observed_message_bytes": 230
  }
}
```

**Redis JSON 输出（响应，通过 `chain_id` 关联同一请求）：**
```json
{
  "kind": "response",
  "chain_id": 1111222233334444,
  "pid": 12345,
  "fd": 12,
  "comm": "nginx",
  "capture_source": "sock_sendmsg",
  "src_ip": "10.0.0.200",
  "dst_ip": "10.0.0.100",
  "src_port": 80,
  "dst_port": 52341,
  "response_ts": "2026-06-02T10:30:00.123456789Z",
  "response_latency_ms": 15.32,
  "response": {
    "status_code": 200,
    "reason": "OK",
    "version": "HTTP/1.1",
    "start_line": "HTTP/1.1 200 OK",
    "headers": {
      "Content-Type": "application/json",
      "Content-Length": "28"
    },
    "body": "{\"status\":\"ok\",\"id\":12345}",
    "body_size_bytes": 28,
    "content_length": 28
  }
}
```

### 5.3 systemd 服务管理

```bash
# 启动
systemctl start power-httptrace

# 停止
systemctl stop power-httptrace

# 查看状态
systemctl status power-httptrace

# 查看实时日志
tail -f /app/log/power-httptrace/console.log
```

### 5.4 统计日志输出示例

```
periodic stats kernel(send_calls=15234 recv_calls=18210 request_fragments=1523 response_fragments=1241 filtered=89 perf_errors=0 truncations=5)
user(perf_received=2764 lost=0 requests=423 responses=398 redis=821 redis_failures=0 parse_failures=0 evicted=0
user_filtered=12 tuple_resolved=398 tuple_miss=0 pending_req=3 pending_resp=0 pending_no_resp=0
req_buf_states=2 resp_buf_states=1 stalled_flush=5 evict_flush=0 orphan_resp=0)
```

---

## 六、关键技术细节

### 6.1 4.19 内核兼容性

4.19 的 eBPF verifier 比现代内核严格得多，项目做了大量适配：

- **禁止循环**：所有循环展开为固定次数（`#pragma unroll` 或手写展开），避免 back-edge
- **栈空间限制**：`noinline` 子函数将大局部变量隔离到子函数栈，避免组合栈超限
- **变长参数**：`bpf_probe_read` 的 size 参数用 `&= const` 硬限制，避免 verifier 报 "unbounded memory access"
- **指针追踪**：避免子函数通过出参传递 map value 指针，调用方直接 `bpf_map_lookup_elem`
- **`bpf_probe_read_user`**：部分厂商内核使用特殊的用户态内存读取函数
- **O1 优化**：legacy 对象用 `-O1` 编译，减少 verifier 需要追踪的程序状态

### 6.2 去重与 guard 机制

当同时挂载 `sock_sendmsg` 和 `tcp_sendmsg` 时，同一条 send 调用可能先后命中两个 hook。

```
claim_send_guard(pid_tgid, msg_ptr):
  已存在相同 msg_ptr?
    ├─ 同 source → duplicate，跳过
    ├─ 不同 source → 判断 payload_primary:
    │    ├─ 新 source 是 primary → upgrade，接管 payload 采集
    │    └─ 新 source 不是 primary → duplicate，跳过
    └─ 不存在 → 创建 guard entry
```

### 6.3 多 CPU perf buffer 乱序处理

内核态 perf event 按 per-CPU 输出，多核场景下同一个 chain 的请求和响应片段可能乱序到达用户态：
- **fragment 按 `frag_idx` 序号重组**：不在内核态保证顺序，由用户态 `fragmentStream.drain()` 按 `nextFrag` 依次合并
- **响应先于请求到达**：暂存到 `deferredResponses`，等请求到达后再配对
- **请求先被提前输出（promote）**：若响应已到但请求还在 buffer 中，先解析请求头再配对

### 6.4 内存自适应调优

启动时根据 `/proc/meminfo` 的 `MemAvailable` 自动分档：

| 可用内存 | Worker 上限 | Redis Worker | Perf Pages | Worker Queue |
|---------|------------|-------------|------------|-------------|
| ≤512MB | 2 | 1 | 16 | 256 |
| ≤1GB | 4 | 2 | 32 | 512 |
| ≤2GB | 6 | 3 | 64 | 768 |
| >2GB | 8 | 4 | 64 | 1024 |

---

## 七、构建与开发

### 7.1 构建环境依赖

```bash
# 编译工具链
go 1.23+        # Go 编译器
clang           # C 编译器（编译 eBPF 程序）
llvm-strip      # 剥离调试符号

# 内核头文件 (编译 eBPF 需要)
# amd64
/usr/include/x86_64-linux-gnu
# arm64
/usr/aarch64-linux-gnu/include

# 构建
make build          # 当前架构
make build-amd64    # x86_64
make build-arm64    # aarch64
```

### 7.2 代码生成流程

```
make generate →
  1. bpf2go 将 .bpf.c 编译为 .bpfel.o (eBPF ELF)
  2. bpf2go 将 .bpfel.o 嵌入为 Go 字节数组 (.bpfel.go)
  3. strip-bpf.sh 剥离 BTF section（适配老内核不支持 BTF）
  4. 对每个架构/变体组合重复以上步骤
```

---

## 八、关键设计约束与注意事项

1. **`sock_recvmsg` 必须配合 `kretprobe`**：进入时用户缓冲区为空，返回后才能读到完整 HTTP 明文。
2. **不做 TCP 报文重组**：内核只负责切片上报 `chain_id + frag_idx`，由用户态按序号拼装。
3. **`ifindex` 不可靠**：socket 层的 `skc_bound_dev_if` 在本机访问或未显式 bind 时经常为 0，因此网卡过滤在用户态按接口 IPv4 做补偿。
4. **全局队列限制**：pending request 最多缓存 4 个，溢出时丢弃最老的（4.19 verifier 不支持动态队列）。
5. **perf buffer 而非 ringbuf**：为兼容 4.19 内核（不支持 BPF ringbuf）。
6. **GODEBUG=asyncpreemptoff=1**：通过自重启带此参数运行，避免长时间 BPF 加载被 Go runtime 的 SIGURG 异步抢占打断。
