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

struct bpf_map_def SEC("maps") tuple_cache = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct tuple_cache_entry),
	.max_entries = 131072,
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

struct bpf_map_def SEC("maps") connect_args_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(__u64),
	.max_entries = 65535,
};

struct bpf_map_def SEC("maps") scratch_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct http_event),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") send_scratch_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct send_capture_scratch),
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

static __always_inline __attribute__((unused)) int extract_tuple(struct sock_compat *sk, struct recv_args *meta)
{
	struct sock_common_compat common = {};
	struct kernel_stats *stats = stats_lookup();

	if (!sk)
		goto fail;
	if (bpf_probe_read(&common, sizeof(common), sk) < 0)
		goto fail;

	meta->ifindex = common.skc_bound_dev_if;
	meta->src_port = common.skc_num;
	meta->dst_port = bpf_ntohs(common.skc_dport);
	meta->family = common.skc_family;

	if (common.skc_family == AF_INET) {
		meta->src_ip = common.skc_rcv_saddr;
		meta->dst_ip = common.skc_daddr;
		if (stats)
			stats->tuple_ipv4_ok += 1;
		return 0;
	}

	/* 很多 Nginx/Java 进程会用 AF_INET6 双栈监听 IPv4 请求。
	 * 这类 socket 在 sock_common 里仍然能稳定拿到本地/对端端口，
	 * 但 IPv6 地址布局跨内核更敏感。这里先退一步：只保留端口和 ifindex，
	 * 让“按端口过滤”的流量尽量在内核里就被挡住，降低 perf 压力。
	 */
	if (common.skc_family == AF_INET6) {
		meta->src_ip = 0;
		meta->dst_ip = 0;
		if (stats)
			stats->tuple_ipv6_portonly += 1;
		return 0;
	}

fail:
	if (stats)
		stats->tuple_extract_fail += 1;
	return -1;
}

static __always_inline __attribute__((unused)) int extract_ipv4_mapped_v6(const __u8 addr[16], __u32 *ip)
{
	if (addr[0] != 0 || addr[1] != 0 || addr[2] != 0 || addr[3] != 0 ||
	    addr[4] != 0 || addr[5] != 0 || addr[6] != 0 || addr[7] != 0 ||
	    addr[8] != 0 || addr[9] != 0 || addr[10] != 0xff || addr[11] != 0xff)
		return -1;

	__builtin_memcpy(ip, &addr[12], sizeof(*ip));
	return 0;
}

static __always_inline __attribute__((unused)) int store_tuple_cache(__u64 sock_id, const struct tuple_cache_entry *entry)
{
	struct kernel_stats *stats = stats_lookup();

	if (!sock_id || !entry)
		return -1;
	if (bpf_map_update_elem(&tuple_cache, &sock_id, entry, BPF_ANY) < 0)
		return -1;
	if (stats)
		stats->tuple_cache_updates += 1;
	return 0;
}

static __always_inline __attribute__((unused)) int load_cached_tuple(__u64 sock_id, struct recv_args *meta)
{
	const struct tuple_cache_entry *entry = NULL;
	struct kernel_stats *stats = stats_lookup();

	if (!sock_id || !meta)
		return -1;
	entry = bpf_map_lookup_elem(&tuple_cache, &sock_id);
	if (!entry) {
		if (stats)
			stats->tuple_cache_misses += 1;
		return -1;
	}

	meta->src_ip = entry->src_ip;
	meta->dst_ip = entry->dst_ip;
	meta->src_port = entry->src_port;
	meta->dst_port = entry->dst_port;
	meta->family = entry->family;
	if (stats)
		stats->tuple_cache_hits += 1;
	return 0;
}

static __always_inline __attribute__((unused)) int load_best_effort_tuple(struct sock_compat *sk, struct recv_args *meta)
{
	if (!meta)
		return -1;
	if (load_cached_tuple(meta->sock_id, meta) == 0)
		return 0;
	return extract_tuple(sk, meta);
}

static __always_inline void fill_common_meta(struct recv_args *meta, struct sock_compat *sk,
					     __s32 fd, __u8 source);

static __always_inline __attribute__((unused)) int cache_tuple_from_sock(struct sock_compat *sk)
{
	struct recv_args meta = {};
	struct tuple_cache_entry entry = {};

	if (!sk)
		return -1;
	fill_common_meta(&meta, sk, -1, SRC_UNKNOWN);
	if (extract_tuple(sk, &meta) < 0)
		return -1;

	entry.src_ip = meta.src_ip;
	entry.dst_ip = meta.dst_ip;
	entry.src_port = meta.src_port;
	entry.dst_port = meta.dst_port;
	entry.family = meta.family;
	return store_tuple_cache(meta.sock_id, &entry);
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

/* 4.19 verifier 对“子函数把 map value 指针经由出参写回调用方栈，再由调用方解引用”
 * 的类型跟踪很弱，容易把 map value 指针降级成普通标量，最终出现：
 *   R7 invalid mem access 'inv'
 * 因此这里的子函数只负责确保 flow_map 中存在该项，不直接把指针传回调用方。
 * 调用方会在本地再次 bpf_map_lookup_elem，这样 verifier 能保住 map value 指针类型。
 *
 * 仍然保留 noinline，是为了把 zero 这个较大的局部对象留在子函数栈里，
 * 避免 sock_sendmsg 主链路的组合栈再次超过 4.19 的限制。
 */
static __attribute__((noinline)) int ensure_flow_exists(__u64 sock_id)
{
	struct flow_state zero = {};
	struct flow_state *state = NULL;

	state = bpf_map_lookup_elem(&flow_map, &sock_id);
	if (state)
		return 0;

	zero.conn_id = ((__u64)bpf_get_prandom_u32() << 32) ^ bpf_ktime_get_ns() ^ sock_id;
	if (bpf_map_update_elem(&flow_map, &sock_id, &zero, BPF_NOEXIST) < 0)
		return -1;

	state = bpf_map_lookup_elem(&flow_map, &sock_id);
	return state ? 0 : -1;
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
	// 请求序列号递增后参与 chain_id 计算，避免短连接复用同一个 sock 地址时重复。
	state->req_seq += 1;
	seq_component = (__u64)state->req_seq << 32;
	return state->conn_id ^ seq_component ^ state->rx_cursor;
}

static __always_inline void push_pending_request(struct flow_state *state, __u64 chain_id)
{
	if (!state || !chain_id)
		return;

	if (state->pending_count == 3) {
		state->pending_req_chain3 = chain_id;
		state->pending_count = 4;
		return;
	}
	if (state->pending_count == 2) {
		state->pending_req_chain2 = chain_id;
		state->pending_count = 3;
		return;
	}
	if (state->pending_count == 1) {
		state->pending_req_chain1 = chain_id;
		state->pending_count = 2;
		return;
	}
	if (state->pending_count == 0) {
		state->pending_req_chain0 = chain_id;
		state->pending_count = 1;
		return;
	}

	/* 队列满时丢掉最老的一条，整体左移。
	 * 固定槽位 + 显式赋值是为了兼容 4.19 verifier，避免任何回边。
	 */
	state->pending_req_chain0 = state->pending_req_chain1;
	state->pending_req_chain1 = state->pending_req_chain2;
	state->pending_req_chain2 = state->pending_req_chain3;
	state->pending_req_chain3 = chain_id;
}

static __always_inline __u64 pop_pending_request(struct flow_state *state)
{
	__u64 chain_id = 0;

	if (!state || !state->pending_count)
		return 0;

	chain_id = state->pending_req_chain0;
	if (state->pending_count > 1)
		state->pending_req_chain0 = state->pending_req_chain1;
	else
		state->pending_req_chain0 = 0;
	if (state->pending_count > 2)
		state->pending_req_chain1 = state->pending_req_chain2;
	else
		state->pending_req_chain1 = 0;
	if (state->pending_count > 3)
		state->pending_req_chain2 = state->pending_req_chain3;
	else
		state->pending_req_chain2 = 0;
	state->pending_req_chain3 = 0;
	if (state->pending_count > 0) {
		state->pending_count -= 1;
	}
	return chain_id;
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
	push_pending_request(state, chain_id);
}

static __always_inline void start_response_capture(struct flow_state *state, __u64 chain_id)
{
	if (!state)
		return;

	state->resp_chain_id = chain_id;
	state->resp_frag_idx = 0;
	state->resp_capture_bytes = 0;
	state->resp_capture_stopped = 0;
	state->resp_active = 1;
	state->req_active = 0;
}

static __always_inline int read_msg_iter(struct msghdr_compat *msg, struct iov_iter_compat *iter)
{
	if (!msg)
		return -1;
	return bpf_probe_read(iter, sizeof(*iter), &msg->msg_iter);
}

static __always_inline int is_http_prefix_padding(char c)
{
	return c == '\r' || c == '\n' || c == ' ' || c == '\t';
}

static __always_inline __u32 trim_http_prefix_padding(const char *buf, __u32 len)
{
	__u32 off = 0;

	if (len > off && is_http_prefix_padding(buf[off]))
		off++;
	if (len > off && is_http_prefix_padding(buf[off]))
		off++;
	if (len > off && is_http_prefix_padding(buf[off]))
		off++;
	if (len > off && is_http_prefix_padding(buf[off]))
		off++;
	if (len > off && is_http_prefix_padding(buf[off]))
		off++;
	if (len > off && is_http_prefix_padding(buf[off]))
		off++;
	if (len > off && is_http_prefix_padding(buf[off]))
		off++;
	if (len > off && is_http_prefix_padding(buf[off]))
		off++;

	return off;
}

#ifdef LEGACY_VERIFIER
static __always_inline __u32 read_prefix_legacy_bytes(const char *base, __u64 skip, __u64 available, char *buf, __u32 buf_len)
{
	__u32 copied = 0;

	if (!base || !buf || !buf_len || !available)
		return 0;
	if (buf_len > 0 && available > 0 && bpf_probe_read(&buf[0], 1, base + skip + 0) == 0)
		copied = 1;
	if (buf_len > 1 && available > 1 && bpf_probe_read(&buf[1], 1, base + skip + 1) == 0)
		copied = 2;
	if (buf_len > 2 && available > 2 && bpf_probe_read(&buf[2], 1, base + skip + 2) == 0)
		copied = 3;
	if (buf_len > 3 && available > 3 && bpf_probe_read(&buf[3], 1, base + skip + 3) == 0)
		copied = 4;
	if (buf_len > 4 && available > 4 && bpf_probe_read(&buf[4], 1, base + skip + 4) == 0)
		copied = 5;
	if (buf_len > 5 && available > 5 && bpf_probe_read(&buf[5], 1, base + skip + 5) == 0)
		copied = 6;
	if (buf_len > 6 && available > 6 && bpf_probe_read(&buf[6], 1, base + skip + 6) == 0)
		copied = 7;
	if (buf_len > 7 && available > 7 && bpf_probe_read(&buf[7], 1, base + skip + 7) == 0)
		copied = 8;
	if (buf_len > 8 && available > 8 && bpf_probe_read(&buf[8], 1, base + skip + 8) == 0)
		copied = 9;
	if (buf_len > 9 && available > 9 && bpf_probe_read(&buf[9], 1, base + skip + 9) == 0)
		copied = 10;
	if (buf_len > 10 && available > 10 && bpf_probe_read(&buf[10], 1, base + skip + 10) == 0)
		copied = 11;
	if (buf_len > 11 && available > 11 && bpf_probe_read(&buf[11], 1, base + skip + 11) == 0)
		copied = 12;
	if (buf_len > 12 && available > 12 && bpf_probe_read(&buf[12], 1, base + skip + 12) == 0)
		copied = 13;
	if (buf_len > 13 && available > 13 && bpf_probe_read(&buf[13], 1, base + skip + 13) == 0)
		copied = 14;
	if (buf_len > 14 && available > 14 && bpf_probe_read(&buf[14], 1, base + skip + 14) == 0)
		copied = 15;
	if (buf_len > 15 && available > 15 && bpf_probe_read(&buf[15], 1, base + skip + 15) == 0)
		copied = 16;

	return copied;
}
#endif

static __always_inline int read_prefix_from_iter(const struct iov_iter_compat *iter, char *buf, __u32 buf_len)
{
	struct iovec_compat iov0 = {};
	struct iovec_compat iov1 = {};
	struct kernel_stats *stats = stats_lookup();
	__u64 skip = 0;
	__u64 second_skip = 0;
	__u64 available = 0;
	__u32 copied = 0;

	if (!iter || !iter->iov || !iter->nr_segs)
		return 0;
	if (bpf_probe_read(&iov0, sizeof(iov0), &iter->iov[0]) < 0)
		return 0;

#ifdef LEGACY_VERIFIER
	skip = iter->iov_offset;
	if (skip < iov0.iov_len) {
		available = iov0.iov_len - skip;
		return read_prefix_legacy_bytes((const char *)iov0.iov_base, skip, available, buf, buf_len);
	}
	if (iter->nr_segs < 2)
		return 0;
	if (bpf_probe_read(&iov1, sizeof(iov1), &iter->iov[1]) < 0)
		return 0;
	second_skip = skip - iov0.iov_len;
	if (second_skip >= iov1.iov_len)
		return 0;
	available = iov1.iov_len - second_skip;
	copied = read_prefix_legacy_bytes((const char *)iov1.iov_base, second_skip, available, buf, buf_len);
	if (copied > 0 && stats)
		stats->prefix_second_iov += 1;
	return copied;
#else
	skip = iter->iov_offset;
	if (skip < iov0.iov_len) {
		available = iov0.iov_len - skip;
		if (available > buf_len)
			available = buf_len;
		if (available && bpf_probe_read(buf, available, (const char *)iov0.iov_base + skip) == 0)
			copied = available;
		second_skip = 0;
	} else {
		second_skip = skip - iov0.iov_len;
	}

	if (copied >= buf_len || iter->nr_segs < 2)
		return copied;
	if (bpf_probe_read(&iov1, sizeof(iov1), &iter->iov[1]) < 0)
		return copied;
	if (second_skip >= iov1.iov_len)
		return copied;

	available = iov1.iov_len - second_skip;
	if (available > buf_len - copied)
		available = buf_len - copied;
	if (!available)
		return copied;
	if (bpf_probe_read(buf + copied, available, (const char *)iov1.iov_base + second_skip) < 0)
		return copied;
	if (stats)
		stats->prefix_second_iov += 1;
	return copied + available;
#endif
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

static __always_inline __u8 detect_http_direction(const char *buf, __u32 len);

static __always_inline __attribute__((unused)) __u8 detect_http_direction_trimmed(const char *buf, __u32 len, __u32 *trimmed)
{
	__u32 off = trim_http_prefix_padding(buf, len);

	if (trimmed)
		*trimmed = off;

	switch (off) {
	case 0:
		return detect_http_direction(buf, len);
	case 1:
		return len > 1 ? detect_http_direction(buf + 1, len - 1) : DIR_UNKNOWN;
	case 2:
		return len > 2 ? detect_http_direction(buf + 2, len - 2) : DIR_UNKNOWN;
	case 3:
		return len > 3 ? detect_http_direction(buf + 3, len - 3) : DIR_UNKNOWN;
	case 4:
		return len > 4 ? detect_http_direction(buf + 4, len - 4) : DIR_UNKNOWN;
	case 5:
		return len > 5 ? detect_http_direction(buf + 5, len - 5) : DIR_UNKNOWN;
	case 6:
		return len > 6 ? detect_http_direction(buf + 6, len - 6) : DIR_UNKNOWN;
	case 7:
		return len > 7 ? detect_http_direction(buf + 7, len - 7) : DIR_UNKNOWN;
	default:
		return len > 8 ? detect_http_direction(buf + 8, len - 8) : DIR_UNKNOWN;
	}
}

static __always_inline __attribute__((unused)) int looks_like_http_request_prefix_trimmed(const char *buf, __u32 len, __u32 *trimmed)
{
	__u32 off = trim_http_prefix_padding(buf, len);

	if (trimmed)
		*trimmed = off;

	switch (off) {
	case 0:
		return looks_like_http_request_prefix(buf, len);
	case 1:
		return len > 1 ? looks_like_http_request_prefix(buf + 1, len - 1) : 0;
	case 2:
		return len > 2 ? looks_like_http_request_prefix(buf + 2, len - 2) : 0;
	case 3:
		return len > 3 ? looks_like_http_request_prefix(buf + 3, len - 3) : 0;
	case 4:
		return len > 4 ? looks_like_http_request_prefix(buf + 4, len - 4) : 0;
	case 5:
		return len > 5 ? looks_like_http_request_prefix(buf + 5, len - 5) : 0;
	case 6:
		return len > 6 ? looks_like_http_request_prefix(buf + 6, len - 6) : 0;
	case 7:
		return len > 7 ? looks_like_http_request_prefix(buf + 7, len - 7) : 0;
	default:
		return len > 8 ? looks_like_http_request_prefix(buf + 8, len - 8) : 0;
	}
}

/* 4.19 verifier 很容易把“读取 iov 前缀 + 判断 HTTP/”这段内联逻辑折叠成回边。
 * 单独拆成 noinline helper 后，发送主链路只拿一个布尔结果，控制流会稳定很多。
 */
static __attribute__((noinline)) int starts_with_http_response(const struct iov_iter_compat *iter)
{
	char prefix[8] = {};
	int prefix_len = 0;

	if (!iter)
		return 0;
	prefix_len = read_prefix_from_iter(iter, prefix, sizeof(prefix));
#ifdef LEGACY_VERIFIER
	return looks_like_http_response(prefix, prefix_len);
#else
	struct kernel_stats *stats = stats_lookup();
	__u32 off = trim_http_prefix_padding(prefix, prefix_len);
	if (off && stats)
		stats->prefix_trimmed += 1;
	return detect_http_direction_trimmed(prefix, prefix_len, NULL) == DIR_RESPONSE;
#endif
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
static __attribute__((noinline)) __attribute__((unused)) int emit_control_event(void *ctx, const struct recv_args *meta,
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
/* 这里直接接收 capture_call 和打包后的 fragment 元数据，避免在调用链上再额外构造
 * 一个 emit_call 大对象，降低 4.19 verifier 统计到的组合栈占用。
 */
static __attribute__((noinline)) int emit_data_event(void *ctx, const struct capture_call *call,
						     const char *src, __u32 payload_len,
						     __u32 frag_meta)
{
	struct http_event *event = NULL;
	struct kernel_stats *stats = stats_lookup();
	__u32 key = 0;
	__u32 safe_len = payload_len & MAX_PAYLOAD_MASK;
	__u16 frag_idx = (__u16)(frag_meta & 0xffff);
	__u16 flags = (__u16)(frag_meta >> 16);

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
	event->frag_idx = frag_idx;
	event->direction = call->direction;
	event->flags = flags;
	event->source = call->source;
	event->family = call->meta->family;
	__builtin_memcpy(event->comm, call->meta->comm, sizeof(event->comm));
	if (safe_len > 0 && bpf_probe_read(event->payload, safe_len, src) < 0) {
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
static __always_inline int emit_chunk_once(void *ctx, const struct capture_call *call,
					   const char **base, __u64 *seg_len,
					   __u32 *captured, __u32 *total_captured,
					   __u16 *frag_idx, __u16 common_flags,
					   __u32 capture_limit)
{
	__u32 chunk = 0;
	__u16 flags = common_flags;
	__u32 frag_meta = 0;

	if (!*seg_len || *captured >= call->total_len || *total_captured >= capture_limit)
		return 0;

	chunk = *seg_len > MAX_PAYLOAD_SIZE ? MAX_PAYLOAD_SIZE : (__u32)*seg_len;
	if (*frag_idx == *call->frag_cursor)
		flags |= EVT_FLAG_START;
	if (*captured + chunk >= call->total_len || *total_captured + chunk >= capture_limit)
		flags |= EVT_FLAG_END;
	frag_meta = ((__u32)flags << 16) | *frag_idx;
	if (emit_data_event(ctx, call, *base, chunk, frag_meta) < 0)
		return -1;

	*base += chunk;
	*seg_len -= chunk;
	*captured += chunk;
	*total_captured += chunk;
	*frag_idx += 1;
	return 0;
}

#ifdef LEGACY_VERIFIER
struct legacy_capture_state {
	const char *base;
	__u64 seg_len;
	__u32 captured;
	__u32 total_captured;
	__u16 frag_idx;
	__u16 common_flags;
	__u32 capture_limit;
};

static __attribute__((noinline)) int emit_chunk_once_legacy(void *ctx,
							    const struct capture_call *call,
							    struct legacy_capture_state *state)
{
	return emit_chunk_once(ctx, call, &state->base, &state->seg_len, &state->captured,
			       &state->total_captured, &state->frag_idx,
			       state->common_flags, state->capture_limit);
}

static __attribute__((noinline)) int capture_iov_slot0_legacy(void *ctx, struct capture_call *call,
							      struct legacy_capture_state *state)
{
	struct iovec_compat iov = {};
	__u64 seg_skip = 0;

	if (!call->iter || !call->iter->iov || call->iter->nr_segs == 0)
		return 0;
	if (state->captured >= call->total_len || state->total_captured >= state->capture_limit)
		return 0;
	if (bpf_probe_read(&iov, sizeof(iov), &call->iter->iov[0]) < 0)
		return 0;

	seg_skip = call->iter->iov_offset;
	if (seg_skip >= iov.iov_len)
		return 0;

	state->seg_len = iov.iov_len - seg_skip;
	if (state->seg_len > call->total_len - state->captured)
		state->seg_len = call->total_len - state->captured;
	if (state->seg_len > state->capture_limit - state->total_captured)
		state->seg_len = state->capture_limit - state->total_captured;
	state->base = (const char *)iov.iov_base + seg_skip;

	if (emit_chunk_once_legacy(ctx, call, state) < 0)
		return -1;
	if (emit_chunk_once_legacy(ctx, call, state) < 0)
		return -1;
	if (emit_chunk_once_legacy(ctx, call, state) < 0)
		return -1;
	if (emit_chunk_once_legacy(ctx, call, state) < 0)
		return -1;
	if (emit_chunk_once_legacy(ctx, call, state) < 0)
		return -1;
	return 0;
}

static __attribute__((noinline)) int capture_iov_slot1_legacy(void *ctx, struct capture_call *call,
							      struct legacy_capture_state *state)
{
	struct iovec_compat iov = {};

	if (!call->iter || !call->iter->iov || call->iter->nr_segs <= 1)
		return 0;
	if (state->captured >= call->total_len || state->total_captured >= state->capture_limit)
		return 0;
	if (bpf_probe_read(&iov, sizeof(iov), &call->iter->iov[1]) < 0)
		return 0;
	if (iov.iov_len == 0)
		return 0;

	state->seg_len = iov.iov_len;
	if (state->seg_len > call->total_len - state->captured)
		state->seg_len = call->total_len - state->captured;
	if (state->seg_len > state->capture_limit - state->total_captured)
		state->seg_len = state->capture_limit - state->total_captured;
	state->base = (const char *)iov.iov_base;

	if (emit_chunk_once_legacy(ctx, call, state) < 0)
		return -1;
	if (emit_chunk_once_legacy(ctx, call, state) < 0)
		return -1;
	if (emit_chunk_once_legacy(ctx, call, state) < 0)
		return -1;
	if (emit_chunk_once_legacy(ctx, call, state) < 0)
		return -1;
	if (emit_chunk_once_legacy(ctx, call, state) < 0)
		return -1;
	return 0;
}

/* 4.19 verifier 不接受 capture_message_from_iter 里编译器残留的回边。
 * legacy 对象把 iov/chunk 展开成固定分支，专门换取“稳定可加载”。
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

	{
		struct legacy_capture_state state = {};

		state.captured = captured;
		state.total_captured = total_captured;
		state.frag_idx = frag_idx;
		state.common_flags = common_flags;
		state.capture_limit = capture_limit;
		if (capture_iov_slot0_legacy(ctx, call, &state) < 0)
			return -1;
		if (capture_iov_slot1_legacy(ctx, call, &state) < 0)
			return -1;
		captured = state.captured;
		total_captured = state.total_captured;
		frag_idx = state.frag_idx;
	}

	*call->frag_cursor = frag_idx;
	if (call->message_captured)
		*call->message_captured = total_captured;
	if (call->capture_stopped && total_captured >= capture_limit)
		*call->capture_stopped = 1;
	return 0;
}
#else
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
			if (emit_chunk_once(ctx, call, &base, &seg_len, &captured,
					    &total_captured, &frag_idx,
					    common_flags, capture_limit) < 0)
				return -1;
		}
	}

	*call->frag_cursor = frag_idx;
	if (call->message_captured)
		*call->message_captured = total_captured;
	if (call->capture_stopped && total_captured >= capture_limit)
		*call->capture_stopped = 1;
	return 0;
}
#endif

/* 发送路径单独包一层 helper，把 capture_call 的本地对象挪出 handle_send_entry。
 * 4.19 verifier 统计“组合栈”时，发送主链路每少一个大局部结构体都很关键。
 */
static __attribute__((noinline)) int capture_response_message(void *ctx,
							       const struct iov_iter_compat *iter,
							       const struct recv_args *meta,
							       struct flow_state *state,
							       __u8 source)
{
	struct capture_call call = {};

	if (!iter || !meta || !state)
		return 0;

	call.iter = iter;
	call.meta = meta;
	call.chain_id = state->resp_chain_id;
	call.seq_hint = meta->seq_hint;
	call.frag_cursor = &state->resp_frag_idx;
	call.message_captured = &state->resp_capture_bytes;
	call.capture_stopped = &state->resp_capture_stopped;
	call.total_len = (__u32)iter->count;
	call.base_flags = 0;
	call.direction = DIR_RESPONSE;
	call.source = source;
	return capture_message_from_iter(ctx, &call);
}

/* fill_common_meta 统一补齐 PID/TID/FD/comm 等基础元数据。
 * 五元组仍然会在后面尝试从 sock 中 best-effort 提取，用于现代内核上的第一层粗过滤；
 * 如果提取失败，事件仍然会继续上送，由用户态基于 pid+fd+/proc 再做一次精确补全。
 * 这样既保留了现代内核上的过滤收益，也避免因为不同内核布局差异把采集链路彻底卡死。
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
#ifndef LEGACY_VERIFIER
	struct recv_args *existing = NULL;

	existing = bpf_map_lookup_elem(&recv_args_map, &pid_tgid);
	if (existing && fd < 0)
		return 0;
#endif

	fill_common_meta(&meta, sk, fd, source);
	if (load_best_effort_tuple(sk, &meta) == 0 && !matches_filter(&meta))
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

static __attribute__((noinline)) __u64 prepare_send_scratch(struct sock_compat *sk,
							    struct msghdr_compat *msg,
							    __s32 fd, __u8 source)
{
	struct send_capture_scratch *scratch = NULL;
	struct kernel_stats *stats = stats_lookup();
	__u32 key = 0;

	if (!sk)
		return 0;
	scratch = bpf_map_lookup_elem(&send_scratch_map, &key);
	if (!scratch)
		return 0;

	fill_common_meta(&scratch->meta, sk, fd, source);
	if (load_best_effort_tuple(sk, &scratch->meta) == 0 && !matches_filter(&scratch->meta))
		return 0;
	if (read_msg_iter(msg, &scratch->iter) < 0 || !scratch->iter.count) {
		if (stats)
			stats->send_iter_empty += 1;
		return 0;
	}

	return scratch->meta.sock_id;
}

// 响应链起点判断，如果请求链路已经存在，并且有 pending 请求，则优先从队首取新的 chain_id。
static __attribute__((noinline)) __u64 select_response_chain(struct flow_state *state,
							     const struct iov_iter_compat *iter)
{
	struct kernel_stats *stats = stats_lookup();
	__u64 chain_id = 0;
	int starts_new_response = starts_with_http_response(iter);
	int req_active_start = 0;

	if (!state)
		return 0;

	/* keep-alive 连接上，下一条 request 可能已经在 recv 路径里起链了，
	 * 但对应 response 的第一段 send 不一定总是从 "HTTP/1.1" 开头开始。
	 * 如果这里只看 resp_active/响应行前缀，就会把新的 response 误续到上一条 resp_chain 上，
	 * 最终在用户态表现成 orphan_resp 和 pending_no_resp 同时升高。
	 *
	 * 因此这里把 req_active 也视作“应该开启新 response”的强信号：
	 * - 只要连接上已经有新的 pending request，send 路径就优先从队首取新的 chain_id。
	 * - 这样即便 send 的第一段只带 body 或 chunk 数据，也不会继续写到上一条 response 上。
	 */
	if (state->req_active && state->pending_count)
		req_active_start = 1;

	if (req_active_start || !state->resp_active || starts_new_response) {
		chain_id = pop_pending_request(state);
		if (!chain_id) {
			if (stats)
				stats->send_no_req_chain += 1;
			return 0;
		}
		start_response_capture(state, chain_id);
		if (stats) {
			stats->send_resp_start += 1;
			if (req_active_start)
				stats->send_resp_reqactive += 1;
		}
		return chain_id;
	}

	if (stats)
		stats->send_resp_continue += 1;
	return state->resp_chain_id;
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
	if (ensure_flow_exists(meta->sock_id) < 0)
		goto cleanup;
	state = bpf_map_lookup_elem(&flow_map, &meta->sock_id);
	if (!state)
		goto cleanup;

	emit_meta = *meta;

	state->rx_cursor += ret;
	seq_hint = state->rx_cursor;

	prefix_len = read_prefix_from_iter(&meta->saved_iter, prefix, sizeof(prefix));
#ifdef LEGACY_VERIFIER
	direction = detect_http_direction(prefix, prefix_len);
	if (direction == DIR_UNKNOWN && looks_like_http_request_prefix(prefix, prefix_len))
		direction = DIR_REQUEST;
#else
	__u32 prefix_off = 0;
	direction = detect_http_direction_trimmed(prefix, prefix_len, &prefix_off);
	if (prefix_off && stats)
		stats->prefix_trimmed += 1;
	if (direction == DIR_UNKNOWN &&
	    looks_like_http_request_prefix_trimmed(prefix, prefix_len, NULL))
		direction = DIR_REQUEST;
#endif
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
	struct flow_state *state = NULL;
	struct send_capture_scratch *scratch = NULL;
	struct kernel_stats *stats = stats_lookup();
	__u32 key = 0;
	__u64 sock_id = 0;
	__u64 chain_id = 0;

	if (stats)
		stats->send_calls += 1;
	sock_id = prepare_send_scratch(sk, msg, fd, source);
	if (!sock_id)
		return 0;
	scratch = bpf_map_lookup_elem(&send_scratch_map, &key);
	if (!scratch)
		return 0;
	if (ensure_flow_exists(sock_id) < 0)
		return 0;
	state = bpf_map_lookup_elem(&flow_map, &sock_id);
	if (!state)
		return 0;

	state->tx_cursor += scratch->iter.count;
	scratch->meta.seq_hint = state->tx_cursor;
	chain_id = select_response_chain(state, &scratch->iter);
	if (!chain_id)
		return 0;
	if (!claim_send_guard(bpf_get_current_pid_tgid(), msg, source))
		return 0;

	if (capture_response_message(ctx, &scratch->iter, &scratch->meta, state, source) < 0)
		return 0;

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

SEC("tracepoint/sock/inet_sock_set_state")
int tracepoint_sock_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state_compat *ctx)
{
	struct tuple_cache_entry entry = {};
	struct kernel_stats *stats = stats_lookup();
	__u64 sock_id = (__u64)ctx->skaddr;

	if (!sock_id || ctx->protocol != IPPROTO_TCP)
		return 0;

	if (ctx->newstate == TCP_CLOSE) {
		bpf_map_delete_elem(&tuple_cache, &sock_id);
		if (stats)
			stats->tuple_cache_deletes += 1;
		return 0;
	}

	if (ctx->newstate != TCP_ESTABLISHED && ctx->newstate != TCP_SYN_RECV)
		return 0;

	entry.src_port = ctx->sport;
	entry.dst_port = ctx->dport;
	entry.family = ctx->family;

	if (ctx->family == AF_INET) {
		__builtin_memcpy(&entry.src_ip, ctx->saddr, sizeof(entry.src_ip));
		__builtin_memcpy(&entry.dst_ip, ctx->daddr, sizeof(entry.dst_ip));
	} else if (ctx->family == AF_INET6) {
		if (extract_ipv4_mapped_v6(ctx->saddr_v6, &entry.src_ip) == 0 &&
		    extract_ipv4_mapped_v6(ctx->daddr_v6, &entry.dst_ip) == 0) {
			entry.family = AF_INET;
		} else {
			entry.src_ip = 0;
			entry.dst_ip = 0;
		}
	} else {
		return 0;
	}

	store_tuple_cache(sock_id, &entry);
	return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe_tcp_v4_connect, struct sock_compat *sk)
{
#ifdef LEGACY_VERIFIER
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 sock_id = (__u64)sk;

	if (!sock_id)
		return 0;
	bpf_map_update_elem(&connect_args_map, &pid_tgid, &sock_id, BPF_ANY);
#endif
	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(kretprobe_tcp_v4_connect)
{
#ifdef LEGACY_VERIFIER
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 *sock_id = NULL;
	__s64 ret = PT_REGS_RC(ctx);

	sock_id = bpf_map_lookup_elem(&connect_args_map, &pid_tgid);
	if (!sock_id)
		return 0;
	if (ret == 0)
		cache_tuple_from_sock((struct sock_compat *)*sock_id);
	bpf_map_delete_elem(&connect_args_map, &pid_tgid);
#endif
	return 0;
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(kprobe_tcp_v6_connect, struct sock_compat *sk)
{
#ifdef LEGACY_VERIFIER
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 sock_id = (__u64)sk;

	if (!sock_id)
		return 0;
	bpf_map_update_elem(&connect_args_map, &pid_tgid, &sock_id, BPF_ANY);
#endif
	return 0;
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(kretprobe_tcp_v6_connect)
{
#ifdef LEGACY_VERIFIER
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 *sock_id = NULL;
	__s64 ret = PT_REGS_RC(ctx);

	sock_id = bpf_map_lookup_elem(&connect_args_map, &pid_tgid);
	if (!sock_id)
		return 0;
	if (ret == 0)
		cache_tuple_from_sock((struct sock_compat *)*sock_id);
	bpf_map_delete_elem(&connect_args_map, &pid_tgid);
#endif
	return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(kretprobe_inet_csk_accept)
{
#ifdef LEGACY_VERIFIER
	struct sock_compat *newsk = (struct sock_compat *)PT_REGS_RC(ctx);

	if (!newsk)
		return 0;
	cache_tuple_from_sock(newsk);
#endif
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
#ifdef LEGACY_VERIFIER
	return 0;
#else
	struct flow_state *state = NULL;
	struct recv_args meta = {};
	struct kernel_stats *stats = stats_lookup();
	__u64 chain_id = 0;
	__u64 sock_id = (__u64)sk;

	state = bpf_map_lookup_elem(&flow_map, &sock_id);
	if (!state)
		return 0;
	if (!state->last_req_chain_id && !state->req_active && !state->resp_active) {
		bpf_map_delete_elem(&flow_map, &sock_id);
		return 0;
	}
	fill_common_meta(&meta, sk, -1, SRC_TCP_CLOSE);
	
	if (load_best_effort_tuple(sk, &meta) == 0 && !matches_filter(&meta)) {
		bpf_map_delete_elem(&flow_map, &sock_id);
		bpf_map_delete_elem(&tuple_cache, &sock_id);
		return 0;
	}

	chain_id = state->last_req_chain_id;
	emit_control_event(ctx, &meta, chain_id, sock_id, EVT_FLAG_CLOSE);

	if (stats)
		stats->close_events += 1;
	bpf_map_delete_elem(&flow_map, &sock_id);
	bpf_map_delete_elem(&tuple_cache, &sock_id);
	return 0;
#endif
}

char LICENSE[] SEC("license") = "GPL";
