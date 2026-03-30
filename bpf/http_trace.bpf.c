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

static __always_inline int extract_tuple(struct sock_compat *sk, struct recv_args *meta)
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
static __always_inline int match_u32_pair(__u32 cfg_src, __u32 cfg_dst, __u32 meta_src, __u32 meta_dst)
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

static __always_inline int match_u16_pair(__u16 cfg_src, __u16 cfg_dst, __u16 meta_src, __u16 meta_dst)
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
static __always_inline int matches_filter(const struct recv_args *meta)
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

	if (bpf_map_update_elem(&flow_map, &sock_id, &zero, BPF_NOEXIST) < 0)
		return -1;

	*state = bpf_map_lookup_elem(&flow_map, &sock_id);
	return *state ? 0 : -1;
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

static __always_inline int read_prefix(struct msghdr_compat *msg, char *buf, __u32 buf_len)
{
	struct iov_iter_compat iter = {};

	if (read_msg_iter(msg, &iter) < 0)
		return 0;
	return read_prefix_from_iter(&iter, buf, buf_len);
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
 * 为了兼容更严格的 verifier，这里固定从用户缓冲拷贝一个 MAX_PAYLOAD_SIZE 的窗口，
 * 但真正的有效长度仍然通过 payload_len 告诉用户态。
 */
static __attribute__((noinline)) int emit_data_event(void *ctx, const struct emit_call *call)
{
	struct http_event *event = NULL;
	struct kernel_stats *stats = stats_lookup();
	__u32 key = 0;
	__u32 safe_len = call->payload_len;

	event = bpf_map_lookup_elem(&scratch_heap, &key);
	if (!event)
		return -1;
	if (safe_len > MAX_PAYLOAD_SIZE)
		safe_len = MAX_PAYLOAD_SIZE;

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
	event->family = call->meta->family;
	__builtin_memcpy(event->comm, call->meta->comm, sizeof(event->comm));
	if (safe_len > 0 && bpf_probe_read(event->payload, MAX_PAYLOAD_SIZE, call->src) < 0)
		return -1;

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

static __always_inline int capture_message(void *ctx, struct msghdr_compat *msg,
					   const struct recv_args *meta, __u64 chain_id,
					   __u64 seq_hint, __u8 direction, __u32 *frag_cursor,
					   __u32 *message_captured, __u8 *capture_stopped,
					   __u32 total_len, __u16 base_flags)
{
	struct iov_iter_compat iter = {};
	struct capture_call call = {};

	if (read_msg_iter(msg, &iter) < 0)
		return -1;
	call.iter = &iter;
	call.meta = meta;
	call.chain_id = chain_id;
	call.seq_hint = seq_hint;
	call.frag_cursor = frag_cursor;
	call.message_captured = message_captured;
	call.capture_stopped = capture_stopped;
	call.total_len = total_len;
	call.base_flags = base_flags;
	call.direction = direction;
	return capture_message_from_iter(ctx, &call);
}

/* fill_common_meta 统一补齐 PID/TID/FD/五元组/comm 等基础元数据。 */
static __always_inline int fill_common_meta(struct recv_args *meta, struct sock_compat *sk,
					    __s32 fd)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	*meta = (struct recv_args){};
	meta->sock_id = (__u64)sk;
	meta->pid = pid_tgid >> 32;
	meta->tid = pid_tgid;
	meta->fd = fd;
	meta->seq_hint = 0;
	bpf_get_current_comm(meta->comm, sizeof(meta->comm));
	return extract_tuple(sk, meta);
}

/* recvmsg 看到的是“对端 -> 本端”的消息方向。
 * sock_common 里的地址默认按“本端/local -> 对端/peer”摆放，
 * 所以在 recv 路径真正上报事件前需要交换一次，保证用户态看到的 src/dst
 * 就是这条 HTTP 消息本身的源/目的。 */
static __always_inline void swap_meta_endpoints(struct recv_args *meta)
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

static __always_inline __s32 consume_fd(__u64 pid_tgid, void *map)
{
	__s32 *fd = bpf_map_lookup_elem(map, &pid_tgid);
	__s32 value = -1;

	if (fd)
		value = *fd;
	bpf_map_delete_elem(map, &pid_tgid);
	return value;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int tracepoint_sys_enter_sendto(struct trace_event_raw_sys_enter_compat *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__s32 fd = (__s32)ctx->args[0];

	stash_fd(pid_tgid, fd, &send_fd_map);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int tracepoint_sys_enter_sendmsg(struct trace_event_raw_sys_enter_compat *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__s32 fd = (__s32)ctx->args[0];

	stash_fd(pid_tgid, fd, &send_fd_map);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint_sys_enter_write(struct trace_event_raw_sys_enter_compat *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__s32 fd = (__s32)ctx->args[0];

	stash_fd(pid_tgid, fd, &send_fd_map);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int tracepoint_sys_enter_writev(struct trace_event_raw_sys_enter_compat *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__s32 fd = (__s32)ctx->args[0];

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
	struct recv_args meta = {};
	struct flow_state *state = NULL;
	struct iov_iter_compat iter = {};
	struct kernel_stats *stats = stats_lookup();
	__u64 sock_id = 0;
	__u64 chain_id = 0;
	__u64 seq_hint = 0;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__s32 fd = consume_fd(pid_tgid, &send_fd_map);
	char prefix[16] = {};
	int prefix_len = 0;
	__u8 direction = DIR_UNKNOWN;
	__u16 flags = EVT_FLAG_HTTP_HINT;
	__u32 frag_cursor = 0;
	__u32 message_captured = 0;
	__u8 capture_stopped = 0;

	if (stats)
		stats->send_calls += 1;
	if (extract_sk(sock_ptr, &sk) < 0)
		return 0;
	if (fill_common_meta(&meta, sk, fd) < 0)
		return 0;
	if (!matches_filter(&meta))
		return 0;
	if (read_msg_iter(msg, &iter) < 0 || !iter.count)
		return 0;

	sock_id = meta.sock_id;
	if (lookup_or_init_flow(sock_id, &state) < 0)
		return 0;

	prefix_len = read_prefix(msg, prefix, sizeof(prefix));
	direction = detect_http_direction(prefix, prefix_len);
	if (direction != DIR_RESPONSE)
		return 0;

	state->tx_cursor += iter.count;
	seq_hint = state->tx_cursor;

	chain_id = state->last_req_chain_id;
	if (!chain_id)
		chain_id = sock_id ^ seq_hint;

	meta.seq_hint = seq_hint;
	if (capture_message(ctx, msg, &meta, chain_id, seq_hint, DIR_RESPONSE,
			    &frag_cursor, &message_captured,
			    &capture_stopped, (__u32)iter.count, flags) < 0)
		return 0;

	return 0;
}

SEC("kprobe/sock_recvmsg")
/* sock_recvmsg 入口只保存上下文；
 * 真正的响应明文要等到 kretprobe 时，用户态缓冲区被内核填好之后才能读到。
 */
int BPF_KPROBE(kprobe_sock_recvmsg, void *sock_ptr, struct msghdr_compat *msg)
{
	struct sock_compat *sk = NULL;
	struct recv_args meta = {};
	struct iov_iter_compat iter = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__s32 fd = consume_fd(pid_tgid, &recv_fd_map);

	if (extract_sk(sock_ptr, &sk) < 0)
		return 0;
	if (fill_common_meta(&meta, sk, fd) < 0)
		return 0;
	if (!matches_filter(&meta))
		return 0;

	meta.msg_ptr = (__u64)msg;
	if (read_msg_iter(msg, &iter) < 0)
		return 0;
	meta.saved_iter = iter;
	if (bpf_map_update_elem(&recv_args_map, &pid_tgid, &meta, BPF_ANY) < 0)
		return 0;

	return 0;
}

/* kretprobe/sock_recvmsg 负责读取响应明文，并把请求/响应通过同一个 chain_id 关联起来。 */
SEC("kretprobe/sock_recvmsg")
int BPF_KRETPROBE(kretprobe_sock_recvmsg)
{
	struct recv_args *meta = NULL;
	struct recv_args emit_meta = {};
	struct flow_state *state = NULL;
	struct kernel_stats *stats = stats_lookup();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__s64 ret = PT_REGS_RC(ctx);
	char prefix[16] = {};
	int prefix_len = 0;
	__u8 direction = DIR_UNKNOWN;
	__u64 chain_id = 0;
	__u64 seq_hint = 0;
	__u16 flags = EVT_FLAG_HTTP_HINT;
	__u32 frag_cursor = 0;
	__u32 message_captured = 0;
	__u8 capture_stopped = 0;

	meta = bpf_map_lookup_elem(&recv_args_map, &pid_tgid);
	if (!meta)
		return 0;
	if (stats)
		stats->recv_calls += 1;
	if (ret <= 0)
		goto cleanup;
	if (lookup_or_init_flow(meta->sock_id, &state) < 0)
		goto cleanup;
	emit_meta = *meta;
	swap_meta_endpoints(&emit_meta);

	prefix_len = read_prefix_from_iter(&meta->saved_iter, prefix, sizeof(prefix));
	direction = detect_http_direction(prefix, prefix_len);
	if (direction != DIR_REQUEST)
		goto cleanup;

	state->rx_cursor += ret;
	seq_hint = state->rx_cursor;

	chain_id = meta->sock_id ^ seq_hint;
	state->last_req_chain_id = chain_id;

	emit_meta.seq_hint = seq_hint;
	{
		struct capture_call call = {};

		call.iter = &meta->saved_iter;
		call.meta = &emit_meta;
		call.chain_id = chain_id;
		call.seq_hint = seq_hint;
		call.frag_cursor = &frag_cursor;
		call.message_captured = &message_captured;
		call.capture_stopped = &capture_stopped;
		call.total_len = (__u32)ret;
		call.base_flags = flags;
		call.direction = DIR_REQUEST;
		if (capture_message_from_iter(ctx, &call) < 0)
			goto cleanup;
	}

cleanup:
	bpf_map_delete_elem(&recv_args_map, &pid_tgid);
	return 0;
}

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
	if (fill_common_meta(&meta, sk, -1) < 0)
		goto cleanup;

	chain_id = state->last_req_chain_id;
	emit_control_event(ctx, &meta, chain_id, sock_id, EVT_FLAG_CLOSE);

cleanup:
	if (stats)
		stats->close_events += 1;
	bpf_map_delete_elem(&flow_map, &sock_id);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
