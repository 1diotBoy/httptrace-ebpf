#include "include/compat.h"

struct bpf_map_def SEC("maps") events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1024,
};

struct bpf_map_def SEC("maps") filter_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct filter_config),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") flow_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct flow_state),
	.max_entries = 65535,
};

struct bpf_map_def SEC("maps") recv_args_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct recv_args),
	.max_entries = 65535,
};

struct bpf_map_def SEC("maps") send_fd_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(__s32),
	.max_entries = 65535,
};

struct bpf_map_def SEC("maps") send_guard_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct send_guard),
	.max_entries = 65535,
};

struct bpf_map_def SEC("maps") recv_fd_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(__s32),
	.max_entries = 65535,
};

struct bpf_map_def SEC("maps") scratch_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct http_event),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") kernel_stats_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct kernel_stats),
	.max_entries = 1,
};

static __always_inline struct kernel_stats *stats_lookup(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&kernel_stats_map, &key);
}

static __always_inline int read_filter(struct filter_config *cfg)
{
	__u32 key = 0;
	struct filter_config *value = bpf_map_lookup_elem(&filter_map, &key);

	if (!value)
		return -1;

	bpf_probe_read(cfg, sizeof(*cfg), value);
	return 0;
}

static __always_inline int extract_sk(void *sock_ptr, struct sock_compat **sk)
{
	struct socket_compat sock = {};

	if (!sock_ptr)
		return -1;
	if (bpf_probe_read(&sock, sizeof(sock), sock_ptr) < 0)
		return -1;
	if (!sock.sk)
		return -1;

	*sk = (struct sock_compat *)sock.sk;
	return 0;
}

static __always_inline __attribute__((unused)) int has_any_endpoint_filter(void)
{
	struct filter_config cfg = {};

	if (read_filter(&cfg) < 0)
		return 0;
	if (cfg.src_ip || cfg.dst_ip || cfg.src_port || cfg.dst_port)
		return 1;
	return 0;
}

/* 只看 socket 的本端/local endpoint。
 * recv 路径里：
 * - 服务端收到请求时，本端就是服务 IP/PORT。
 * - 客户端收到响应时，本端则是客户端临时 IP/PORT。
 * 因此 4.19 上 request fallback 只能按本端匹配，不能按“任意一端命中”对称匹配。
 */
static __always_inline __attribute__((unused)) int matches_local_endpoint_filter(const struct recv_args *meta)
{
	struct filter_config cfg = {};

	if (!meta)
		return 0;
	if (read_filter(&cfg) < 0)
		return 0;
	if (cfg.src_ip && meta->src_ip == cfg.src_ip)
		return 1;
	if (cfg.dst_ip && meta->src_ip == cfg.dst_ip)
		return 1;
	if (cfg.src_port && meta->src_port == cfg.src_port)
		return 1;
	if (cfg.dst_port && meta->src_port == cfg.dst_port)
		return 1;
	return 0;
}

static __always_inline __attribute__((unused)) int extract_tuple(struct sock_compat *sk, struct recv_args *meta)
{
	struct sock_common_compat common = {};

	if (!sk)
		return -1;
	if (bpf_probe_read(&common, sizeof(common), sk) < 0)
		return -1;
	if (common.skc_family != AF_INET)
		return -1;

	meta->ifindex = common.skc_bound_dev_if;
	meta->src_ip = common.skc_rcv_saddr;
	meta->dst_ip = common.skc_daddr;
	meta->src_port = common.skc_num;
	meta->dst_port = bpf_ntohs(common.skc_dport);
	meta->family = common.skc_family;
	return 0;
}

/* src/dst 同时存在时，按链路对称匹配：
 * - 如果两边配置成同一个值，表示“任意一端命中这个值即可”。
 * - 如果两边是不同值，允许请求/响应方向翻转。
 */
static __always_inline __attribute__((unused)) int match_u32_pair(__u32 cfg_src, __u32 cfg_dst, __u32 meta_src, __u32 meta_dst)
{
	if (cfg_src && cfg_dst) {
		if (cfg_src == cfg_dst)
			return meta_src == cfg_src || meta_dst == cfg_src;
		return (meta_src == cfg_src && meta_dst == cfg_dst) ||
		       (meta_src == cfg_dst && meta_dst == cfg_src);
	}
	if (cfg_src)
		return meta_src == cfg_src || meta_dst == cfg_src;
	if (cfg_dst)
		return meta_src == cfg_dst || meta_dst == cfg_dst;
	return 1;
}

static __always_inline __attribute__((unused)) int match_u16_pair(__u16 cfg_src, __u16 cfg_dst, __u16 meta_src, __u16 meta_dst)
{
	if (cfg_src && cfg_dst) {
		if (cfg_src == cfg_dst)
			return meta_src == cfg_src || meta_dst == cfg_src;
		return (meta_src == cfg_src && meta_dst == cfg_dst) ||
		       (meta_src == cfg_dst && meta_dst == cfg_src);
	}
	if (cfg_src)
		return meta_src == cfg_src || meta_dst == cfg_src;
	if (cfg_dst)
		return meta_src == cfg_dst || meta_dst == cfg_dst;
	return 1;
}

/* matches_filter 是内核态第一层过滤：
 * - 端口/IP 用对称匹配，保证请求方向和响应方向都能进来。
 * - ifindex 只在 meta->ifindex 非 0 时才做强过滤，因为 socket 层拿到的更像 bind_dev_if，
 *   本机打本机或者未显式 bind 设备的连接经常是 0。
 * 真正的 ifname 精确过滤会在用户态按接口 IPv4 再补一层。
 */
static __always_inline __attribute__((unused)) int matches_filter(const struct recv_args *meta)
{
	struct filter_config cfg = {};
	struct kernel_stats *stats = stats_lookup();

	if (read_filter(&cfg) < 0)
		return 1;
	if (cfg.ifindex && meta->ifindex && cfg.ifindex != meta->ifindex)
		goto reject;
	if (!match_u32_pair(cfg.src_ip, cfg.dst_ip, meta->src_ip, meta->dst_ip))
		goto reject;
	if (!match_u16_pair(cfg.src_port, cfg.dst_port, meta->src_port, meta->dst_port))
		goto reject;

	return 1;

reject:
	if (stats)
		stats->filtered += 1;
	return 0;
}

static __always_inline int lookup_or_init_flow(__u64 sock_id, struct flow_state **state)
{
	struct flow_state zero = {};

	*state = bpf_map_lookup_elem(&flow_map, &sock_id);
	if (*state)
		return 0;

	zero.conn_id = ((__u64)bpf_get_prandom_u32() << 32) ^ bpf_ktime_get_ns() ^ sock_id;
	if (bpf_map_update_elem(&flow_map, &sock_id, &zero, BPF_NOEXIST) < 0)
		return -1;

	*state = bpf_map_lookup_elem(&flow_map, &sock_id);
	return *state ? 0 : -1;
}

/* next_chain_id 为每条连接生成稳定但不重复的请求编号：
 * - conn_id 在 flow_state 初次创建时生成，避免短连接复用同一个 sock 地址时 chain_id 重复。
 * - req_seq 在 keep-alive 连接上递增，保证同一连接上的多次请求/响应各自唯一。
 */
static __always_inline __u64 next_chain_id(struct flow_state *state)
{
	__u64 seq_component = 0;

	if (!state)
		return 0;
	// 请求序列号递增,生成唯一chain id,防止短连接复用同一个 sock 地址时 chain_id 重复 qqq
	state->req_seq += 1;
	seq_component = (__u64)state->req_seq << 32;
	return state->conn_id ^ seq_component ^ state->rx_cursor;
}

static __always_inline void start_request_capture(struct flow_state *state, __u64 chain_id)
{
	if (!state)
		return;

	state->last_req_chain_id = chain_id;
	state->req_frag_idx = 0;
	state->req_capture_bytes = 0;
	state->req_capture_stopped = 0;
	state->req_active = 1;
	state->response_pending = 1;

	/* 新请求开始后，旧响应状态已经结束或失效，直接清掉，避免 keep-alive 上串流。 */
	state->resp_active = 0;
	state->resp_frag_idx = 0;
	state->resp_capture_bytes = 0;
	state->resp_capture_stopped = 0;
}

static __always_inline void start_response_capture(struct flow_state *state)
{
	if (!state)
		return;

	state->resp_frag_idx = 0;
	state->resp_capture_bytes = 0;
	state->resp_capture_stopped = 0;
	state->resp_active = 1;
	state->response_pending = 0;
	state->req_active = 0;
}

static __always_inline int read_msg_iter(struct msghdr_compat *msg, struct iov_iter_compat *iter)
{
	if (!msg)
		return -1;
	return bpf_probe_read(iter, sizeof(*iter), &msg->msg_iter);
}

static __always_inline int read_prefix_from_iter(const struct iov_iter_compat *iter, char *buf, __u32 buf_len)
{
	struct iovec_compat iov = {};
	__u64 skip = 0;
	__u64 available = 0;

	if (!iter || !iter->iov || !iter->nr_segs)
		return 0;
	if (bpf_probe_read(&iov, sizeof(iov), &iter->iov[0]) < 0)
		return 0;

	skip = iter->iov_offset;
	if (skip >= iov.iov_len)
		return 0;

	available = iov.iov_len - skip;
	if (available > buf_len)
		available = buf_len;
	if (!available)
		return 0;

	if (bpf_probe_read(buf, available, (const char *)iov.iov_base + skip) < 0)
		return 0;
	return available;
}

static __always_inline int looks_like_http_request(const char *buf, __u32 len)
{
	if (len >= 4 &&
	    buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T' && buf[3] == ' ')
		return 1;
	if (len >= 5 &&
	    buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T' && buf[4] == ' ')
		return 1;
	if (len >= 4 &&
	    buf[0] == 'P' && buf[1] == 'U' && buf[2] == 'T' && buf[3] == ' ')
		return 1;
	if (len >= 5 &&
	    buf[0] == 'P' && buf[1] == 'A' && buf[2] == 'T' && buf[3] == 'C' && buf[4] == 'H')
		return 1;
	if (len >= 6 &&
	    buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'E' && buf[4] == 'T' && buf[5] == 'E')
		return 1;
	if (len >= 4 &&
	    buf[0] == 'H' && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D')
		return 1;
	if (len >= 7 &&
	    buf[0] == 'O' && buf[1] == 'P' && buf[2] == 'T' && buf[3] == 'I' && buf[4] == 'O' && buf[5] == 'N' && buf[6] == 'S')
		return 1;
	if (len >= 5 &&
	    buf[0] == 'T' && buf[1] == 'R' && buf[2] == 'A' && buf[3] == 'C' && buf[4] == 'E')
		return 1;
	if (len >= 7 &&
	    buf[0] == 'C' && buf[1] == 'O' && buf[2] == 'N' && buf[3] == 'N' && buf[4] == 'E' && buf[5] == 'C' && buf[6] == 'T')
		return 1;

	return 0;
}

/* 高并发下第一段 recv 有时只有 "G" / "PO" / "HEA" 这类半截方法名。
 * 旧逻辑只认完整方法，偶发会漏掉这一条 request，最后表现成：
 * - request 比压测样本少 1
 * - response 反而多 1（孤儿响应）
 * 这里补一层“方法名前缀”识别，尽量把第一包很短的请求也纳入同一个 chain。
 */
static __always_inline int looks_like_http_request_prefix(const char *buf, __u32 len)
{
	if (!buf || len == 0)
		return 0;

	if (len <= 3 &&
	    buf[0] == 'G' &&
	    (len < 2 || buf[1] == 'E') &&
	    (len < 3 || buf[2] == 'T'))
		return 1;
	if (len <= 4 &&
	    buf[0] == 'P' && buf[1] == 'O' &&
	    (len < 3 || buf[2] == 'S') &&
	    (len < 4 || buf[3] == 'T'))
		return 1;
	if (len <= 3 &&
	    buf[0] == 'P' && buf[1] == 'U' &&
	    (len < 3 || buf[2] == 'T'))
		return 1;
	if (len <= 5 &&
	    buf[0] == 'P' && buf[1] == 'A' &&
	    (len < 3 || buf[2] == 'T') &&
	    (len < 4 || buf[3] == 'C') &&
	    (len < 5 || buf[4] == 'H'))
		return 1;
	if (len <= 6 &&
	    buf[0] == 'D' && buf[1] == 'E' &&
	    (len < 3 || buf[2] == 'L') &&
	    (len < 4 || buf[3] == 'E') &&
	    (len < 5 || buf[4] == 'T') &&
	    (len < 6 || buf[5] == 'E'))
		return 1;
	if (len <= 4 &&
	    buf[0] == 'H' && buf[1] == 'E' &&
	    (len < 3 || buf[2] == 'A') &&
	    (len < 4 || buf[3] == 'D'))
		return 1;
	if (len <= 7 &&
	    buf[0] == 'O' && buf[1] == 'P' &&
	    (len < 3 || buf[2] == 'T') &&
	    (len < 4 || buf[3] == 'I') &&
	    (len < 5 || buf[4] == 'O') &&
	    (len < 6 || buf[5] == 'N') &&
	    (len < 7 || buf[6] == 'S'))
		return 1;
	if (len <= 5 &&
	    buf[0] == 'T' && buf[1] == 'R' &&
	    (len < 3 || buf[2] == 'A') &&
	    (len < 4 || buf[3] == 'C') &&
	    (len < 5 || buf[4] == 'E'))
		return 1;
	if (len <= 7 &&
	    buf[0] == 'C' && buf[1] == 'O' &&
	    (len < 3 || buf[2] == 'N') &&
	    (len < 4 || buf[3] == 'N') &&
	    (len < 5 || buf[4] == 'E') &&
	    (len < 6 || buf[5] == 'C') &&
	    (len < 7 || buf[6] == 'T'))
		return 1;

	return 0;
}

static __always_inline int looks_like_http_response(const char *buf, __u32 len)
{
	if (len < 5)
		return 0;

	return buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P' && buf[4] == '/';
}

static __always_inline __u8 detect_http_direction(const char *buf, __u32 len)
{
	if (looks_like_http_request(buf, len))
		return DIR_REQUEST;
	if (looks_like_http_response(buf, len))
		return DIR_RESPONSE;
	return DIR_UNKNOWN;
}

static __always_inline __u32 pick_capture_limit(void)
{
	struct filter_config cfg = {};

	if (read_filter(&cfg) < 0 || !cfg.capture_bytes)
		return DEFAULT_MESSAGE_LIMIT;
	if (cfg.capture_bytes > DEFAULT_MESSAGE_LIMIT)
		cfg.capture_bytes = DEFAULT_MESSAGE_LIMIT;
	if (cfg.capture_bytes > MAX_CAPTURE_BYTES_PER_CALL)
		return MAX_CAPTURE_BYTES_PER_CALL;
	return cfg.capture_bytes;
}

/* emit_control_event 上报 close 之类的控制事件，用户态收到后可以把“靠 EOF 结束”的响应收尾。 */
static __attribute__((noinline)) int emit_control_event(void *ctx, const struct recv_args *meta,
							__u64 chain_id, __u64 sock_id, __u8 flags)
{
	struct http_event *event = NULL;
	__u32 key = 0;
	struct kernel_stats *stats = stats_lookup();

	event = bpf_map_lookup_elem(&scratch_heap, &key);
	if (!event)
		return -1;

	event->ts_ns = bpf_ktime_get_ns();
	event->chain_id = chain_id;
	event->sock_id = sock_id;
	event->seq_hint = meta ? meta->seq_hint : 0;
	event->pid = meta ? meta->pid : 0;
	event->tid = meta ? meta->tid : 0;
	event->fd = meta ? meta->fd : -1;
	event->ifindex = meta ? meta->ifindex : 0;
	event->src_ip = meta ? meta->src_ip : 0;
	event->dst_ip = meta ? meta->dst_ip : 0;
	event->src_port = meta ? meta->src_port : 0;
	event->dst_port = meta ? meta->dst_port : 0;
	event->direction = DIR_UNKNOWN;
	event->flags = EVT_FLAG_CONTROL | flags;
	event->source = meta ? meta->source : SRC_UNKNOWN;
	event->family = meta ? meta->family : 0;
	if (meta)
		__builtin_memcpy(event->comm, meta->comm, sizeof(event->comm));

	if (bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event)) < 0) {
		if (stats)
			stats->perf_errors += 1;
		return -1;
	}

	if (stats)
		stats->close_events += 1;
	return 0;
}

/* emit_data_event 把内核态采到的一段 HTTP 明文连同元数据一起推到 perf buffer。
 * 这里必须只按 safe_len 读取真实有效字节。
 * 如果像旧版本那样固定读 MAX_PAYLOAD_SIZE，在 4.19 上很容易因为越过用户缓冲区边界而失败，
 * 最终表现成：send/recv hook 都命中了，但 request/response fragment 始终是 0。
 */
static __attribute__((noinline)) int emit_data_event(void *ctx, const struct emit_call *call)
{
	struct http_event *event = NULL;
	struct kernel_stats *stats = stats_lookup();
	__u32 key = 0;
	__u32 safe_len = call->payload_len & MAX_PAYLOAD_MASK;

	event = bpf_map_lookup_elem(&scratch_heap, &key);
	if (!event)
		return -1;
	/* 4.19 verifier 对 helper 的变长 size 参数非常敏感。
	 * 这里直接用 “var &= const” 把长度硬限制到 0..1023，
	 * 避免 verifier 报 "R2 unbounded memory access"。
	 */

	event->ts_ns = bpf_ktime_get_ns();
	event->chain_id = call->chain_id;
	event->sock_id = call->meta->sock_id;
	event->seq_hint = call->seq_hint;
	event->pid = call->meta->pid;
	event->tid = call->meta->tid;
	event->fd = call->meta->fd;
	event->ifindex = call->meta->ifindex;
	event->src_ip = call->meta->src_ip;
	event->dst_ip = call->meta->dst_ip;
	event->src_port = call->meta->src_port;
	event->dst_port = call->meta->dst_port;
	event->payload_len = safe_len;
	event->total_len = call->total_len;
	event->frag_idx = call->frag_idx;
	event->direction = call->direction;
	event->flags = call->flags;
	event->source = call->source;
	event->family = call->meta->family;
	__builtin_memcpy(event->comm, call->meta->comm, sizeof(event->comm));
	if (safe_len > 0 && bpf_probe_read(event->payload, safe_len, call->src) < 0) {
		if (stats)
			stats->perf_errors += 1;
		return -1;
	}

	if (bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event)) < 0) {
		if (stats)
			stats->perf_errors += 1;
		return -1;
	}

	if (stats) {
		if (call->direction == DIR_REQUEST)
			stats->send_events += 1;
		else if (call->direction == DIR_RESPONSE)
			stats->recv_events += 1;
	}
	return 0;
}

/* capture_message 负责把一个 sendmsg/recvmsg 调用切成多个 fragment 事件。
 * 每个 fragment 都带相同的 chain_id，用户态按 frag_idx 重组即可。
 */
static __attribute__((noinline)) int capture_message_from_iter(void *ctx, struct capture_call *call)
{
	struct kernel_stats *stats = stats_lookup();
	__u32 capture_limit = pick_capture_limit();
	__u32 captured = 0;
	__u32 total_captured = call->message_captured ? *call->message_captured : 0;
	__u16 frag_idx = (__u16)*call->frag_cursor;
	__u16 common_flags = call->base_flags;

	if (!call->iter || !call->iter->iov || !call->iter->nr_segs)
		return 0;
	if (call->capture_stopped && *call->capture_stopped)
		return 0;
	if (total_captured >= capture_limit) {
		if (call->capture_stopped)
			*call->capture_stopped = 1;
		return 0;
	}
	if (total_captured + call->total_len > capture_limit) {
		common_flags |= EVT_FLAG_CAPTURE_TRUNC;
		if (stats && (!call->capture_stopped || !*call->capture_stopped))
			stats->truncations += 1;
	}

#pragma unroll
	for (int i = 0; i < MAX_IOVECS; i++) {
		struct iovec_compat iov = {};
		__u64 seg_len;
		__u64 seg_skip;
		const char *base;

		if ((__u64)i >= call->iter->nr_segs || captured >= call->total_len || total_captured >= capture_limit)
			break;
		if (bpf_probe_read(&iov, sizeof(iov), &call->iter->iov[i]) < 0)
			break;

		seg_skip = i == 0 ? call->iter->iov_offset : 0;
		if (seg_skip >= iov.iov_len)
			continue;

		seg_len = iov.iov_len - seg_skip;
		if (seg_len > call->total_len - captured)
			seg_len = call->total_len - captured;
		if (seg_len > capture_limit - total_captured)
			seg_len = capture_limit - total_captured;
		base = (const char *)iov.iov_base + seg_skip;

#pragma unroll
		for (int j = 0; j < MAX_CHUNKS_PER_IOV; j++) {
			__u32 chunk = 0;
			__u16 flags = common_flags;
			struct emit_call emit = {};

			if (!seg_len || captured >= call->total_len || total_captured >= capture_limit)
				break;
			chunk = seg_len > MAX_PAYLOAD_SIZE ? MAX_PAYLOAD_SIZE : (__u32)seg_len;
			if (frag_idx == *call->frag_cursor)
				flags |= EVT_FLAG_START;
			if (captured + chunk >= call->total_len || total_captured + chunk >= capture_limit)
				flags |= EVT_FLAG_END;
			emit.meta = call->meta;
			emit.chain_id = call->chain_id;
			emit.seq_hint = call->seq_hint;
			emit.frag_idx = frag_idx;
			emit.flags = flags;
			emit.total_len = (__u16)call->total_len;
			emit.direction = call->direction;
			emit.source = call->source;
			emit.src = base;
			emit.payload_len = chunk;
			if (emit_data_event(ctx, &emit) < 0)
				return -1;

			base += chunk;
			seg_len -= chunk;
			captured += chunk;
			total_captured += chunk;
			frag_idx += 1;
		}
	}

	*call->frag_cursor = frag_idx;
	if (call->message_captured)
		*call->message_captured = total_captured;
	if (call->capture_stopped && total_captured >= capture_limit)
		*call->capture_stopped = 1;
	return 0;
}

/* fill_common_meta 统一补齐 PID/TID/FD/comm 等基础元数据。
 * 五元组和接口信息统一留给用户态基于 pid+fd+/proc 反查，避免不同内核版本上的 sock
 * 布局差异把整个采集链路卡死，也顺手把 BPF 主程序体积压下来。
 */
static __always_inline void fill_common_meta(struct recv_args *meta, struct sock_compat *sk,
					     __s32 fd, __u8 source)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	*meta = (struct recv_args){};
	meta->sock_id = (__u64)sk;
	meta->pid = pid_tgid >> 32;
	meta->tid = pid_tgid;
	meta->fd = fd;
	meta->seq_hint = 0;
	meta->source = source;
	bpf_get_current_comm(meta->comm, sizeof(meta->comm));
	meta->family = 0;
}

/* recvmsg 看到的是“对端 -> 本端”的消息方向。
 * sock_common 里的地址默认按“本端/local -> 对端/peer”摆放，
 * 所以在 recv 路径真正上报事件前需要交换一次，保证用户态看到的 src/dst
 * 就是这条 HTTP 消息本身的源/目的。 */
static __always_inline __attribute__((unused)) void swap_meta_endpoints(struct recv_args *meta)
{
	__u32 ip = 0;
	__u16 port = 0;

	if (!meta)
		return;

	ip = meta->src_ip;
	meta->src_ip = meta->dst_ip;
	meta->dst_ip = ip;

	port = meta->src_port;
	meta->src_port = meta->dst_port;
	meta->dst_port = port;
}

static __always_inline int stash_fd(__u64 pid_tgid, __s32 fd, void *map)
{
	return bpf_map_update_elem(map, &pid_tgid, &fd, BPF_ANY);
}

static __always_inline void clear_send_guard(__u64 pid_tgid)
{
	bpf_map_delete_elem(&send_guard_map, &pid_tgid);
}

/* 当同时挂了 sock_sendmsg 和 tcp_sendmsg 时，同一条 send 调用可能先后命中两个 hook。
 * 这里按 pid_tgid + msg 指针做一次轻量去重
 * - msg 指针更接近“这一次具体发送调用”，适合在 sock_sendmsg 与 tcp_sendmsg 之间去重。
 * - 第一个真正进入 response 采集的 hook 获得本次发送的“所有权”。
 * - 后续同一 msg 的第二个 hook 直接跳过，避免重复上报和 tx_cursor/frag_idx 双重推进。
 * 常见路径下通常还是 sock_sendmsg 先命中，因此它天然是主路径，tcp_sendmsg 作为补充兜底。
 */
static __always_inline int claim_send_guard(__u64 pid_tgid, struct msghdr_compat *msg, __u8 source)
{
	struct send_guard guard = {};
	struct send_guard *existing = NULL;
	__u64 msg_ptr = (__u64)msg;

	existing = bpf_map_lookup_elem(&send_guard_map, &pid_tgid);
	if (existing && existing->msg_ptr == msg_ptr)
		return 0;

	guard.msg_ptr = msg_ptr;
	guard.source = source;
	bpf_map_update_elem(&send_guard_map, &pid_tgid, &guard, BPF_ANY);
	return 1;
}

static __always_inline __s32 consume_fd(__u64 pid_tgid, void *map)
{
	__s32 *fd = bpf_map_lookup_elem(map, &pid_tgid);
	__s32 value = -1;

	if (fd)
		value = *fd;
	bpf_map_delete_elem(map, &pid_tgid);
	return value;
}

static __always_inline int store_recv_args(struct sock_compat *sk, struct msghdr_compat *msg, __s32 fd,
					   __u8 source)
{
	struct recv_args meta = {};
	struct iov_iter_compat iter = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct kernel_stats *stats = stats_lookup();
	struct recv_args *existing = NULL;

	existing = bpf_map_lookup_elem(&recv_args_map, &pid_tgid);
	if (existing && fd < 0)
		return 0;

	fill_common_meta(&meta, sk, fd, source);
	if (extract_tuple(sk, &meta) == 0 && !matches_filter(&meta))
		return 0;

	meta.msg_ptr = (__u64)msg;
	if (read_msg_iter(msg, &iter) < 0 || !iter.count) {
		if (stats)
			stats->recv_store_no_iter += 1;
		return 0;
	}
	meta.saved_iter = iter;
	bpf_map_update_elem(&recv_args_map, &pid_tgid, &meta, BPF_ANY);
	if (stats)
		stats->recv_store_ok += 1;
	return 0;
}

/* handle_recv_return 统一处理 sock_recvmsg/tcp_recvmsg 的返回路径：
 * - 新请求命中请求行时，分配新的 chain_id。
 * - 同一请求的后续 recvmsg 调用沿用同一个 chain_id，并继续累计 fragment 索引。
 */
static __attribute__((noinline)) int handle_recv_return(void *ctx, __u64 pid_tgid, __s64 ret)
{
	struct recv_args *meta = NULL;
	struct recv_args emit_meta = {};
	struct flow_state *state = NULL;
	struct kernel_stats *stats = stats_lookup();
	char prefix[16] = {};
	int prefix_len = 0;
	__u8 direction = DIR_UNKNOWN;
	__u64 chain_id = 0;
	__u64 seq_hint = 0;
	__u16 flags = EVT_FLAG_HTTP_HINT;

	meta = bpf_map_lookup_elem(&recv_args_map, &pid_tgid);
	if (!meta) {
		if (stats)
			stats->recv_ret_no_meta += 1;
		return 0;
	}
	if (stats)
		stats->recv_calls += 1;
	if (ret <= 0)
		goto cleanup;
	if (lookup_or_init_flow(meta->sock_id, &state) < 0)
		goto cleanup;

	emit_meta = *meta;

	state->rx_cursor += ret;
	seq_hint = state->rx_cursor;

	prefix_len = read_prefix_from_iter(&meta->saved_iter, prefix, sizeof(prefix));
	direction = detect_http_direction(prefix, prefix_len);
	if (direction == DIR_UNKNOWN && looks_like_http_request_prefix(prefix, prefix_len))
		direction = DIR_REQUEST;
	if (direction == DIR_REQUEST) {
		if (stats)
			stats->recv_dir_request += 1;
		chain_id = next_chain_id(state);
		start_request_capture(state, chain_id);
	} else if (direction == DIR_RESPONSE) {
		if (stats)
			stats->recv_dir_response += 1;
		goto cleanup;
	} else if (state->req_active && state->last_req_chain_id && !state->req_capture_stopped) {
		if (stats)
			stats->recv_dir_unknown += 1;
		chain_id = state->last_req_chain_id;
		flags = 0;
	} else if (state->last_req_chain_id && !state->response_pending) {
		if (stats) {
			stats->recv_dir_unknown += 1;
			stats->recv_fallback_keepalive += 1;
		}
		/* 长连接顺序调用时，下一条请求未必总是从当前 recv 缓冲的第一个字节开始，
		 * 这时仅靠方法行前缀判断会漏掉第二、第三个接口。
		 * 这里在“上一轮已经进入响应阶段”的前提下，允许把新的 recv 直接视作下一条 request。
		 */
		chain_id = next_chain_id(state);
		start_request_capture(state, chain_id);
		flags = 0;
	} else {
		if (stats)
			stats->recv_dir_unknown += 1;
		goto cleanup;
	}

	emit_meta.seq_hint = seq_hint;
	{
		struct capture_call call = {};

		call.iter = &meta->saved_iter;
		call.meta = &emit_meta;
		call.chain_id = chain_id;
		call.seq_hint = seq_hint;
		call.frag_cursor = &state->req_frag_idx;
		call.message_captured = &state->req_capture_bytes;
		call.capture_stopped = &state->req_capture_stopped;
		call.total_len = (__u32)ret;
		call.base_flags = flags;
		call.direction = DIR_REQUEST;
		call.source = emit_meta.source;
		capture_message_from_iter(ctx, &call);
	}

cleanup:
	bpf_map_delete_elem(&recv_args_map, &pid_tgid);
	return 0;
}

static __attribute__((noinline)) int handle_send_entry(void *ctx, struct sock_compat *sk,
						       struct msghdr_compat *msg, __s32 fd,
						       __u8 source)
{
	struct recv_args meta = {};
	struct flow_state *state = NULL;
	struct iov_iter_compat iter = {};
	struct kernel_stats *stats = stats_lookup();
	__u64 sock_id = 0;
	__u64 chain_id = 0;
	__u64 seq_hint = 0;
	__u16 flags = 0;

	if (stats)
		stats->send_calls += 1;
	if (!sk)
		return 0;
	fill_common_meta(&meta, sk, fd, source);
	if (extract_tuple(sk, &meta) == 0 && !matches_filter(&meta))
		return 0;
	if (read_msg_iter(msg, &iter) < 0 || !iter.count) {
		if (stats)
			stats->send_iter_empty += 1;
		return 0;
	}

	sock_id = meta.sock_id;
	if (lookup_or_init_flow(sock_id, &state) < 0)
		return 0;

	state->tx_cursor += iter.count;
	seq_hint = state->tx_cursor;
	meta.seq_hint = seq_hint;

	/* 对 TCP 响应来说，tcp_sendmsg 的第一段不一定都以 "HTTP/" 开头。
	 * 只要同一连接上已经有活跃 request，就直接把 send 路径视作 response。
	 */
	if (!state->last_req_chain_id) {
		if (stats)
			stats->send_no_req_chain += 1;
		return 0;
	}

	if (state->resp_active && !state->resp_capture_stopped) {
		if (stats)
			stats->send_resp_continue += 1;
		chain_id = state->last_req_chain_id;
	} else if (state->response_pending) {
		start_response_capture(state);
		if (stats)
			stats->send_resp_start += 1;
		chain_id = state->last_req_chain_id;
	} else {
		if (stats)
			stats->send_no_req_chain += 1;
		return 0;
	}
	if (!claim_send_guard(bpf_get_current_pid_tgid(), msg, source))
		return 0;

	{
		struct capture_call call = {};

		call.iter = &iter;
		call.meta = &meta;
		call.chain_id = chain_id;
		call.seq_hint = seq_hint;
		call.frag_cursor = &state->resp_frag_idx;
		call.message_captured = &state->resp_capture_bytes;
		call.capture_stopped = &state->resp_capture_stopped;
		call.total_len = (__u32)iter.count;
		call.base_flags = flags;
		call.direction = DIR_RESPONSE;
		call.source = source;
		if (capture_message_from_iter(ctx, &call) < 0)
			return 0;
	}

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int tracepoint_sys_enter_sendto(struct trace_event_raw_sys_enter_compat *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__s32 fd = (__s32)ctx->args[0];

	clear_send_guard(pid_tgid);
	stash_fd(pid_tgid, fd, &send_fd_map);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int tracepoint_sys_enter_sendmsg(struct trace_event_raw_sys_enter_compat *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__s32 fd = (__s32)ctx->args[0];

	clear_send_guard(pid_tgid);
	stash_fd(pid_tgid, fd, &send_fd_map);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint_sys_enter_write(struct trace_event_raw_sys_enter_compat *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__s32 fd = (__s32)ctx->args[0];

	clear_send_guard(pid_tgid);
	stash_fd(pid_tgid, fd, &send_fd_map);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int tracepoint_sys_enter_writev(struct trace_event_raw_sys_enter_compat *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__s32 fd = (__s32)ctx->args[0];

	clear_send_guard(pid_tgid);
	stash_fd(pid_tgid, fd, &send_fd_map);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tracepoint_sys_enter_recvfrom(struct trace_event_raw_sys_enter_compat *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__s32 fd = (__s32)ctx->args[0];

	stash_fd(pid_tgid, fd, &recv_fd_map);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int tracepoint_sys_enter_recvmsg(struct trace_event_raw_sys_enter_compat *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__s32 fd = (__s32)ctx->args[0];

	stash_fd(pid_tgid, fd, &recv_fd_map);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint_sys_enter_read(struct trace_event_raw_sys_enter_compat *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__s32 fd = (__s32)ctx->args[0];

	stash_fd(pid_tgid, fd, &recv_fd_map);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_readv")
int tracepoint_sys_enter_readv(struct trace_event_raw_sys_enter_compat *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__s32 fd = (__s32)ctx->args[0];

	stash_fd(pid_tgid, fd, &recv_fd_map);
	return 0;
}

SEC("kprobe/sock_sendmsg")
int BPF_KPROBE(kprobe_sock_sendmsg, void *sock_ptr, struct msghdr_compat *msg)
{
	struct sock_compat *sk = NULL;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__s32 fd = consume_fd(pid_tgid, &send_fd_map);
	struct kernel_stats *stats = stats_lookup();
	if (stats)
		stats->sock_send_hits += 1;
	if (extract_sk(sock_ptr, &sk) < 0)
		return 0;
	return handle_send_entry(ctx, sk, msg, fd, SRC_SOCK_SENDMSG);
}

SEC("kprobe/tcp_sendmsg")
/* tcp_sendmsg 只作为响应发送的补充路径：
 * - 主路径仍然是 sock_sendmsg，语义更接近应用层明文发送。
 * - 对 Nginx 等场景，如果响应没有完整经过 sock_sendmsg，tcp_sendmsg 可以补到一部分 TCP 发送数据。
 */
int BPF_KPROBE(kprobe_tcp_sendmsg, struct sock_compat *sk, struct msghdr_compat *msg)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__s32 fd = consume_fd(pid_tgid, &send_fd_map);
	struct kernel_stats *stats = stats_lookup();
	if (stats)
		stats->tcp_send_hits += 1;

	return handle_send_entry(ctx, sk, msg, fd, SRC_TCP_SENDMSG);
}

SEC("kprobe/sock_recvmsg")
/* sock_recvmsg 入口只保存上下文；
 * 真正的响应明文要等到 kretprobe 时，用户态缓冲区被内核填好之后才能读到。
 */
int BPF_KPROBE(kprobe_sock_recvmsg, void *sock_ptr, struct msghdr_compat *msg)
{
	struct sock_compat *sk = NULL;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__s32 fd = consume_fd(pid_tgid, &recv_fd_map);
	struct kernel_stats *stats = stats_lookup();
	if (stats)
		stats->sock_recv_hits += 1;

	if (extract_sk(sock_ptr, &sk) < 0)
		return 0;
	return store_recv_args(sk, msg, fd, SRC_SOCK_RECVMSG);
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(kprobe_tcp_recvmsg, struct sock_compat *sk, struct msghdr_compat *msg)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__s32 fd = consume_fd(pid_tgid, &recv_fd_map);
	struct kernel_stats *stats = stats_lookup();
	if (stats)
		stats->tcp_recv_hits += 1;

	if (!sk)
		return 0;
	return store_recv_args(sk, msg, fd, SRC_TCP_RECVMSG);
}

/* kretprobe/sock_recvmsg 负责读取响应明文，并把请求/响应通过同一个 chain_id 关联起来。 */
SEC("kretprobe/sock_recvmsg")
int BPF_KRETPROBE(kretprobe_sock_recvmsg)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__s64 ret = PT_REGS_RC(ctx);

	return handle_recv_return(ctx, pid_tgid, ret);
}

SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(kretprobe_tcp_recvmsg)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__s64 ret = PT_REGS_RC(ctx);

	return handle_recv_return(ctx, pid_tgid, ret);
}

/* tcp_close 上报 close 控制事件，帮助用户态在 keep-alive/connection: close 场景下做最终收尾。 */
SEC("kprobe/tcp_close")
int BPF_KPROBE(kprobe_tcp_close, struct sock_compat *sk)
{
	struct flow_state *state = NULL;
	struct recv_args meta = {};
	struct kernel_stats *stats = stats_lookup();
	__u64 chain_id = 0;
	__u64 sock_id = (__u64)sk;

	if (lookup_or_init_flow(sock_id, &state) < 0)
		return 0;
	fill_common_meta(&meta, sk, -1, SRC_TCP_CLOSE);

	chain_id = state->last_req_chain_id;
	emit_control_event(ctx, &meta, chain_id, sock_id, EVT_FLAG_CLOSE);

	if (stats)
		stats->close_events += 1;
	bpf_map_delete_elem(&flow_map, &sock_id);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
