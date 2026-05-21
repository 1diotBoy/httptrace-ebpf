#include "include/compat.h"

struct tls_ssl_key {
	__u32 tgid;
	__u32 pad0;
	__u64 ssl_ptr;
};

struct tls_fd_entry {
	__s32 read_fd;
	__s32 write_fd;
};

struct tls_rw_args {
	struct tls_ssl_key key;
	__u64 buf_ptr;
	__u64 size_ptr;
	__u32 requested;
	__u8 source;
	__u8 pad0[3];
	char comm[16];
};

struct tls_fd_args {
	struct tls_ssl_key key;
	__s32 fd;
	__u8 source;
	__u8 pad0[3];
};

struct tls_config {
	__u32 request_capture_bytes;
	__u32 response_capture_bytes;
	char comm[16];
};

struct bpf_map_def SEC("maps") events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1024,
};

struct bpf_map_def SEC("maps") tls_config_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct tls_config),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") tls_flow_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct tls_ssl_key),
	.value_size = sizeof(struct flow_state),
	.max_entries = 65535,
};

struct bpf_map_def SEC("maps") tls_rw_args_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct tls_rw_args),
	.max_entries = 65535,
};

struct bpf_map_def SEC("maps") tls_fd_args_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct tls_fd_args),
	.max_entries = 65535,
};

struct bpf_map_def SEC("maps") tls_fd_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct tls_ssl_key),
	.value_size = sizeof(struct tls_fd_entry),
	.max_entries = 65535,
};

struct bpf_map_def SEC("maps") scratch_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct http_event),
	.max_entries = 1,
};

/*
 * Older verifiers struggle to keep precise upper bounds for variable-length
 * helper copies into map values. Keep each TLS plaintext perf fragment within
 * an 8-bit length so the verifier can always prove the map write stays inside
 * http_event.payload.
 */
#define TLS_EVENT_COPY_MAX 255
#define TLS_EVENT_MAX_FRAGMENTS 6
#define TLS_EVENT_CAPTURE_MAX_BYTES (TLS_EVENT_COPY_MAX * TLS_EVENT_MAX_FRAGMENTS)

#define EMIT_TLS_FRAGMENT_STEP()                                                                  \
	do {                                                                                      \
		if (emit_offset < emit_budget) {                                                  \
			emit_len32 = emit_budget - emit_offset;                                   \
			if (emit_len32 > TLS_EVENT_COPY_MAX)                                       \
				emit_len32 = TLS_EVENT_COPY_MAX;                                   \
			emit_len32 &= TLS_EVENT_COPY_MAX;                                          \
			if (emit_len32 > 0) {                                                      \
				emit_len = (__u8)emit_len32;                                       \
				frag_flags = 0;                                                    \
				if (frag_cursor == 0)                                              \
					frag_flags |= EVT_FLAG_START;                               \
				if (emit_offset + emit_len32 >= emit_budget)                        \
					frag_flags |= final_flags;                                  \
				if (emit_data_event(ctx, args, fd_entry, chain_id, seq_hint,        \
					   observed_bytes, direction, source, frag_cursor,        \
					   frag_flags, total_len, emit_len,                       \
					   args->buf_ptr + emit_offset) < 0)                      \
					return -1;                                                \
				frag_cursor += 1;                                                 \
				emit_offset += emit_len32;                                        \
			}                                                                     \
		}                                                                             \
	} while (0)

static __always_inline int read_tls_config(struct tls_config *cfg)
{
	__u32 key = 0;
	struct tls_config *value = bpf_map_lookup_elem(&tls_config_map, &key);

	if (!value)
		return -1;
	bpf_probe_read(cfg, sizeof(*cfg), value);
	return 0;
}

static __always_inline int comm_allowed(char comm[16])
{
	struct tls_config cfg = {};

	if (read_tls_config(&cfg) < 0 || cfg.comm[0] == 0)
		return 1;

	if (cfg.comm[0] != comm[0])
		return 0;
	if ((cfg.comm[1] == 0 && comm[1] == 0) || cfg.comm[1] == comm[1]) {
		if ((cfg.comm[2] == 0 && comm[2] == 0) || cfg.comm[2] == comm[2]) {
			if ((cfg.comm[3] == 0 && comm[3] == 0) || cfg.comm[3] == comm[3]) {
				if ((cfg.comm[4] == 0 && comm[4] == 0) || cfg.comm[4] == comm[4]) {
					if ((cfg.comm[5] == 0 && comm[5] == 0) || cfg.comm[5] == comm[5]) {
						if ((cfg.comm[6] == 0 && comm[6] == 0) || cfg.comm[6] == comm[6]) {
							if ((cfg.comm[7] == 0 && comm[7] == 0) || cfg.comm[7] == comm[7]) {
								if ((cfg.comm[8] == 0 && comm[8] == 0) || cfg.comm[8] == comm[8]) {
									if ((cfg.comm[9] == 0 && comm[9] == 0) || cfg.comm[9] == comm[9]) {
										if ((cfg.comm[10] == 0 && comm[10] == 0) || cfg.comm[10] == comm[10]) {
											if ((cfg.comm[11] == 0 && comm[11] == 0) || cfg.comm[11] == comm[11]) {
												if ((cfg.comm[12] == 0 && comm[12] == 0) || cfg.comm[12] == comm[12]) {
													if ((cfg.comm[13] == 0 && comm[13] == 0) || cfg.comm[13] == comm[13]) {
														if ((cfg.comm[14] == 0 && comm[14] == 0) || cfg.comm[14] == comm[14]) {
															if ((cfg.comm[15] == 0 && comm[15] == 0) || cfg.comm[15] == comm[15])
																return 1;
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return 0;
}

static __always_inline __u32 request_capture_limit(void)
{
	struct tls_config cfg = {};

	if (read_tls_config(&cfg) < 0 || cfg.request_capture_bytes == 0)
		return DEFAULT_MESSAGE_LIMIT;
	return cfg.request_capture_bytes;
}

static __always_inline __u32 response_capture_limit(void)
{
	struct tls_config cfg = {};

	if (read_tls_config(&cfg) < 0 || cfg.response_capture_bytes == 0)
		return DEFAULT_MESSAGE_LIMIT;
	return cfg.response_capture_bytes;
}

static __always_inline void fill_ssl_key(struct tls_ssl_key *key, __u64 pid_tgid, void *ssl)
{
	if (!key)
		return;
	key->tgid = pid_tgid >> 32;
	key->ssl_ptr = (__u64)ssl;
}

static __always_inline __u64 flow_conn_id(const struct tls_ssl_key *key)
{
	if (!key)
		return 0;
	return ((__u64)key->tgid << 32) ^ key->ssl_ptr ^ bpf_ktime_get_ns() ^ ((__u64)bpf_get_prandom_u32() << 32);
}

static __attribute__((noinline)) int ensure_tls_flow_exists(const struct tls_ssl_key *key)
{
	struct flow_state zero = {};
	struct flow_state *state = NULL;

	if (!key)
		return -1;
	state = bpf_map_lookup_elem(&tls_flow_map, key);
	if (state)
		return 0;

	zero.conn_id = flow_conn_id(key);
	if (bpf_map_update_elem(&tls_flow_map, key, &zero, BPF_NOEXIST) < 0)
		return -1;

	state = bpf_map_lookup_elem(&tls_flow_map, key);
	if (state)
		return 0;
	return -1;
}

static __always_inline __u64 next_chain_id(struct flow_state *state)
{
	__u64 seq_component = 0;

	if (!state)
		return 0;
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
	if (state->pending_count > 0)
		state->pending_count -= 1;
	return chain_id;
}

static __always_inline void start_request_capture(struct flow_state *state, __u64 chain_id)
{
	if (!state)
		return;

	state->last_req_chain_id = chain_id;
	state->req_frag_idx = 0;
	state->req_capture_bytes = 0;
	state->req_observed_bytes = 0;
	state->req_reported_bytes = 0;
	state->req_capture_stopped = 0;
	state->req_active = 1;
	/*
	 * A newly observed request means the previous response phase on this
	 * keep-alive TLS connection has ended. We must retire response-active
	 * state here, otherwise every follow-on SSL_read body chunk will keep
	 * satisfying "state->resp_active" and incorrectly fork a fresh chain_id.
	 *
	 * Keep the pending request queue intact; only reset the response-side
	 * capture state that belongs to the completed exchange.
	 */
	state->resp_chain_id = 0;
	state->resp_frag_idx = 0;
	state->resp_capture_bytes = 0;
	state->resp_observed_bytes = 0;
	state->resp_reported_bytes = 0;
	state->resp_capture_stopped = 0;
	state->resp_active = 0;
	push_pending_request(state, chain_id);
}

static __always_inline void start_response_capture(struct flow_state *state, __u64 chain_id)
{
	if (!state)
		return;

	state->resp_chain_id = chain_id;
	state->resp_frag_idx = 0;
	state->resp_capture_bytes = 0;
	state->resp_observed_bytes = 0;
	state->resp_reported_bytes = 0;
	state->resp_capture_stopped = 0;
	state->resp_active = 1;
	state->req_active = 0;
}

static __always_inline __u32 read_tls_prefix_legacy_bytes(__u64 base, __u32 available, char *buf, __u32 buf_len)
{
	__u32 copied = 0;

	if (!base || !buf || !buf_len || !available)
		return 0;
	if (buf_len > 0 && available > 0 && bpf_probe_read_user(&buf[0], 1, (const void *)(base + 0)) == 0)
		copied = 1;
	if (buf_len > 1 && available > 1 && bpf_probe_read_user(&buf[1], 1, (const void *)(base + 1)) == 0)
		copied = 2;
	if (buf_len > 2 && available > 2 && bpf_probe_read_user(&buf[2], 1, (const void *)(base + 2)) == 0)
		copied = 3;
	if (buf_len > 3 && available > 3 && bpf_probe_read_user(&buf[3], 1, (const void *)(base + 3)) == 0)
		copied = 4;
	if (buf_len > 4 && available > 4 && bpf_probe_read_user(&buf[4], 1, (const void *)(base + 4)) == 0)
		copied = 5;
	if (buf_len > 5 && available > 5 && bpf_probe_read_user(&buf[5], 1, (const void *)(base + 5)) == 0)
		copied = 6;
	if (buf_len > 6 && available > 6 && bpf_probe_read_user(&buf[6], 1, (const void *)(base + 6)) == 0)
		copied = 7;
	if (buf_len > 7 && available > 7 && bpf_probe_read_user(&buf[7], 1, (const void *)(base + 7)) == 0)
		copied = 8;
	if (buf_len > 8 && available > 8 && bpf_probe_read_user(&buf[8], 1, (const void *)(base + 8)) == 0)
		copied = 9;
	if (buf_len > 9 && available > 9 && bpf_probe_read_user(&buf[9], 1, (const void *)(base + 9)) == 0)
		copied = 10;
	if (buf_len > 10 && available > 10 && bpf_probe_read_user(&buf[10], 1, (const void *)(base + 10)) == 0)
		copied = 11;
	if (buf_len > 11 && available > 11 && bpf_probe_read_user(&buf[11], 1, (const void *)(base + 11)) == 0)
		copied = 12;
	if (buf_len > 12 && available > 12 && bpf_probe_read_user(&buf[12], 1, (const void *)(base + 12)) == 0)
		copied = 13;
	if (buf_len > 13 && available > 13 && bpf_probe_read_user(&buf[13], 1, (const void *)(base + 13)) == 0)
		copied = 14;
	if (buf_len > 14 && available > 14 && bpf_probe_read_user(&buf[14], 1, (const void *)(base + 14)) == 0)
		copied = 15;
	if (buf_len > 15 && available > 15 && bpf_probe_read_user(&buf[15], 1, (const void *)(base + 15)) == 0)
		copied = 16;

	return copied;
}

static __always_inline __u32 read_tls_prefix(__u64 base, __u32 available, char *buf, __u32 buf_len)
{
	return read_tls_prefix_legacy_bytes(base, available, buf, buf_len);
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

static __always_inline int tls_starts_with_http_request(const struct tls_rw_args *args, __u32 size)
{
	char prefix[16] = {};
	__u32 prefix_len = 0;

	if (!args)
		return 0;
	if (!args->buf_ptr)
		return 0;
	if (size == 0)
		return 0;
	prefix_len = size;
	if (prefix_len > sizeof(prefix))
		prefix_len = sizeof(prefix);
	prefix_len = read_tls_prefix(args->buf_ptr, prefix_len, prefix, sizeof(prefix));
	if (prefix_len == 0)
		return 0;
	if (looks_like_http_request(prefix, prefix_len))
		return 1;
	return looks_like_http_request_prefix(prefix, prefix_len);
}

static __always_inline int tls_starts_with_http_response(const struct tls_rw_args *args, __u32 size)
{
	char prefix[8] = {};
	__u32 prefix_len = 0;

	if (!args)
		return 0;
	if (!args->buf_ptr)
		return 0;
	if (size == 0)
		return 0;
	prefix_len = size;
	if (prefix_len > sizeof(prefix))
		prefix_len = sizeof(prefix);
	prefix_len = read_tls_prefix(args->buf_ptr, prefix_len, prefix, sizeof(prefix));
	if (prefix_len == 0)
		return 0;
	return looks_like_http_response(prefix, prefix_len);
}

static __always_inline __u64 select_tls_response_chain(const struct tls_rw_args *args,
						       struct flow_state *state, __u32 size)
{
	__u64 chain_id = 0;
	int starts_new_response = 0;
	int req_active_start = 0;

	if (!state)
		return 0;
	starts_new_response = tls_starts_with_http_response(args, size);
	if (state->req_active && state->pending_count)
		req_active_start = 1;

	if (req_active_start || !state->resp_active || starts_new_response) {
		chain_id = pop_pending_request(state);
		if (chain_id)
			return chain_id;
	}

	if (state->resp_chain_id)
		return state->resp_chain_id;
	return state->last_req_chain_id;
}

/*
 * TLS capture intentionally follows nginx server-side semantics:
 * SSL_read* receives client requests and SSL_write* sends upstream responses.
 *
 * This keeps the kernel program small and verifier-friendly on 4.19 while
 * still reusing the existing user-space HTTP reassembly and parsing path.
 */

static __always_inline void fill_common_event_meta(struct http_event *event,
						  const struct tls_rw_args *args,
						  const struct tls_fd_entry *fd_entry,
						  __u64 chain_id, __u64 seq_hint,
						  __u64 observed_bytes, __u8 direction,
						  __u8 flags, __u8 source,
						  __u16 payload_len, __u16 total_len,
						  __u16 frag_idx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	if (!event)
		return;
	if (!args)
		return;
	event->ts_ns = bpf_ktime_get_ns();
	event->chain_id = chain_id;
	event->sock_id = args->key.ssl_ptr;
	event->seq_hint = seq_hint;
	event->observed_message_bytes = observed_bytes;
	event->pid = args->key.tgid;
	event->tid = (__u32)pid_tgid;
	event->fd = -1;
	if (fd_entry) {
		if (direction == DIR_REQUEST)
			event->fd = fd_entry->read_fd;
		else if (direction == DIR_RESPONSE)
			event->fd = fd_entry->write_fd;
	}
	event->ifindex = 0;
	event->src_ip = 0;
	event->dst_ip = 0;
	event->src_port = 0;
	event->dst_port = 0;
	event->payload_len = payload_len;
	event->total_len = total_len;
	event->frag_idx = frag_idx;
	event->direction = direction;
	event->flags = flags;
	event->source = source;
	event->family = 0;
	__builtin_memcpy(event->comm, args->comm, sizeof(event->comm));
}

static __attribute__((noinline)) int copy_tls_payload(struct http_event *event,
						      __u64 buf_ptr, __u32 copy_len)
{
	__u32 safe_len = 0;
	__u32 helper_len = 0;

	if (!event)
		return -1;
	if (copy_len == 0)
		return 0;
	safe_len = copy_len;
	safe_len &= TLS_EVENT_COPY_MAX;
	if (safe_len == 0)
		return 0;
	helper_len = safe_len;
	helper_len <<= 24;
	helper_len >>= 24;
	if (bpf_probe_read_user(event->payload, helper_len, (const void *)(buf_ptr)) < 0)
		return -1;
	return 0;
}

static __always_inline int emit_data_event(void *ctx, const struct tls_rw_args *args,
					  const struct tls_fd_entry *fd_entry,
					  __u64 chain_id, __u64 seq_hint,
					  __u64 observed_bytes, __u8 direction,
					  __u8 source, __u16 frag_idx,
					  __u16 flags, __u16 total_len,
					  __u8 chunk_len, __u64 buf_ptr)
{
	struct http_event *event = NULL;
	__u32 payload_copy_len = 0;
	__u32 helper_copy_len = 0;
	__u16 payload_len16 = 0;
	__u32 key = 0;

	event = bpf_map_lookup_elem(&scratch_heap, &key);
	if (!event)
		return -1;
	if (chunk_len == 0)
		return 0;
	payload_copy_len = (__u32)chunk_len;
	if (payload_copy_len > TLS_EVENT_COPY_MAX)
		payload_copy_len = TLS_EVENT_COPY_MAX;
	payload_copy_len &= TLS_EVENT_COPY_MAX;
	payload_len16 = payload_copy_len;
	fill_common_event_meta(event, args, fd_entry, chain_id, seq_hint, observed_bytes,
				      direction, flags, source, payload_len16, total_len, frag_idx);
	helper_copy_len = payload_copy_len;
	if (copy_tls_payload(event, buf_ptr, helper_copy_len) < 0)
		return -1;
	if (bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event)) < 0)
		return -1;
	return 0;
}

static __always_inline int emit_size_progress_event(void *ctx, const struct tls_rw_args *args,
						    const struct tls_fd_entry *fd_entry,
						    __u64 chain_id, __u64 seq_hint,
						    __u64 observed_bytes, __u8 direction,
						    __u8 source, __u8 end_flag)
{
	struct http_event *event = NULL;
	__u32 key = 0;
	__u8 flags = EVT_FLAG_SIZE_ONLY;

	if (end_flag)
		flags |= EVT_FLAG_END;
	event = bpf_map_lookup_elem(&scratch_heap, &key);
	if (!event)
		return -1;
	fill_common_event_meta(event, args, fd_entry, chain_id, seq_hint, observed_bytes,
			      direction, flags, source, 0, 0, 0);
	if (bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event)) < 0)
		return -1;
	return 0;
}

static __always_inline __attribute__((unused)) int emit_control_event(void *ctx, const struct tls_rw_args *args,
						      const struct tls_fd_entry *fd_entry,
						      __u64 chain_id, __u8 source)
{
	struct http_event *event = NULL;
	__u32 key = 0;

	event = bpf_map_lookup_elem(&scratch_heap, &key);
	if (!event)
		return -1;
	fill_common_event_meta(event, args, fd_entry, chain_id, 0, 0,
			      DIR_UNKNOWN, EVT_FLAG_CONTROL | EVT_FLAG_CLOSE,
			      source, 0, 0, 0);
	if (bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event)) < 0)
		return -1;
	return 0;
}

static __always_inline int capture_plaintext(void *ctx, const struct tls_rw_args *args,
					     const struct tls_fd_entry *fd_entry,
					     struct flow_state *state,
					     __u64 chain_id, __u64 seq_hint,
					     __u8 direction, __u8 source,
					     __u32 size)
{
	__u32 limit = 0;
	__u32 remaining = size;
	__u32 captured = 0;
	__u32 already = 0;
	__u16 frag_cursor = 0;
	__u8 capture_stopped = 0;
	__u64 observed_bytes = 0;
	__u32 allowed = 0;
	__u32 chunk = 0;
	__u32 emit_budget = 0;
	__u32 emit_offset = 0;
	__u32 emit_len32 = 0;
	__u8 emit_len = 0;
	__u16 total_len = (__u16)size;
	__u16 final_flags = 0;
	__u16 frag_flags = 0;
	int is_request = direction == DIR_REQUEST;

	if (size > 0xffff)
		total_len = 0xffff;
	if (is_request)
		limit = request_capture_limit();
	else
		limit = response_capture_limit();

	if (is_request) {
		already = state->req_capture_bytes;
		frag_cursor = state->req_frag_idx;
		capture_stopped = state->req_capture_stopped;
		observed_bytes = state->req_observed_bytes;
	} else {
		already = state->resp_capture_bytes;
		frag_cursor = state->resp_frag_idx;
		capture_stopped = state->resp_capture_stopped;
		observed_bytes = state->resp_observed_bytes;
	}

	if (capture_stopped) {
		return emit_size_progress_event(ctx, args, fd_entry, chain_id, seq_hint, observed_bytes,
					       direction, source, 0);
	}
	if (limit <= already) {
		if (is_request)
			state->req_capture_stopped = 1;
		else
			state->resp_capture_stopped = 1;
		return emit_size_progress_event(ctx, args, fd_entry, chain_id, seq_hint, observed_bytes,
					       direction, source, 0);
	}

	allowed = limit - already;
	if (remaining > allowed) {
		final_flags |= EVT_FLAG_CAPTURE_TRUNC;
		capture_stopped = 1;
	}
	chunk = remaining;
	if (chunk > allowed)
		chunk = allowed;
	/*
	 * Do not stop TLS capture just because one SSL_write/SSL_read call is larger
	 * than a single event payload. TLS plaintext is emitted as multiple perf
	 * fragments, so later calls should still be able to contribute payload bytes
	 * until the overall request/response capture limit is reached.
	 */
	emit_budget = chunk;
	if (emit_budget > TLS_EVENT_CAPTURE_MAX_BYTES) {
		emit_budget = TLS_EVENT_CAPTURE_MAX_BYTES;
		final_flags |= EVT_FLAG_CAPTURE_TRUNC;
	}
	if (emit_budget == 0)
		return emit_size_progress_event(ctx, args, fd_entry, chain_id, seq_hint, observed_bytes,
					       direction, source, 0);

	EMIT_TLS_FRAGMENT_STEP();
	EMIT_TLS_FRAGMENT_STEP();
	EMIT_TLS_FRAGMENT_STEP();
	EMIT_TLS_FRAGMENT_STEP();
	EMIT_TLS_FRAGMENT_STEP();
	EMIT_TLS_FRAGMENT_STEP();
	captured = emit_offset;

	if (is_request) {
		state->req_capture_bytes = already + captured;
		state->req_frag_idx = frag_cursor;
		state->req_capture_stopped = capture_stopped;
	} else {
		state->resp_capture_bytes = already + captured;
		state->resp_frag_idx = frag_cursor;
		state->resp_capture_stopped = capture_stopped;
	}

	return 0;
}

static __always_inline int should_trace_current_task(char comm[16])
{
	if (bpf_get_current_comm(comm, 16) < 0)
		return 0;
	return comm_allowed(comm);
}

static __always_inline int store_rw_args(void *ssl, void *buf, __u64 requested,
					 __u64 size_ptr, __u8 source)
{
	struct tls_rw_args args = {};
	char comm[16] = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	if (!ssl)
		return 0;
	if (!buf)
		return 0;
	if (requested == 0)
		return 0;
	if (!should_trace_current_task(comm))
		return 0;

	fill_ssl_key(&args.key, pid_tgid, ssl);
	args.buf_ptr = (__u64)buf;
	args.size_ptr = size_ptr;
	args.requested = requested;
	args.source = source;
	__builtin_memcpy(args.comm, comm, sizeof(args.comm));
	return bpf_map_update_elem(&tls_rw_args_map, &pid_tgid, &args, BPF_ANY);
}

static __always_inline int store_fd_args(void *ssl, __s32 fd, __u8 source)
{
	struct tls_fd_args args = {};
	char comm[16] = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	if (!ssl)
		return 0;
	if (fd < 0)
		return 0;
	if (!should_trace_current_task(comm))
		return 0;

	fill_ssl_key(&args.key, pid_tgid, ssl);
	args.fd = fd;
	args.source = source;
	return bpf_map_update_elem(&tls_fd_args_map, &pid_tgid, &args, BPF_ANY);
}

static __always_inline __u32 resolve_plaintext_size(const struct tls_rw_args *args, long ret)
{
	__u64 processed = 0;

	if (!args)
		return 0;
	if (ret <= 0)
		return 0;
	if (args->source == SRC_TLS_SSL_READ_EX || args->source == SRC_TLS_SSL_WRITE_EX) {
		if (!args->size_ptr)
			return 0;
		if (bpf_probe_read_user(&processed, sizeof(processed), (const void *)args->size_ptr) < 0)
			return 0;
		if (processed > args->requested)
			processed = args->requested;
		return processed;
	}
	if ((__u64)ret > args->requested)
		return args->requested;
	return ret;
}

static __always_inline int handle_tls_request(void *ctx, const struct tls_rw_args *args, __u32 size)
{
	struct flow_state *state = NULL;
	const struct tls_fd_entry *fd_entry = NULL;
	__u64 chain_id = 0;
	__u64 seq_hint = 0;
	int starts_new_request = 0;

	if (ensure_tls_flow_exists(&args->key) < 0)
		return 0;
	state = bpf_map_lookup_elem(&tls_flow_map, &args->key);
	if (!state)
		return 0;
	fd_entry = bpf_map_lookup_elem(&tls_fd_map, &args->key);

	state->rx_cursor += size;
	seq_hint = state->rx_cursor;
	starts_new_request = tls_starts_with_http_request(args, size);
	if (starts_new_request || !state->req_active || state->resp_active || !state->last_req_chain_id) {
		chain_id = next_chain_id(state);
		start_request_capture(state, chain_id);
	} else {
		chain_id = state->last_req_chain_id;
	}
	state->req_observed_bytes += size;

	return capture_plaintext(ctx, args, fd_entry, state, chain_id, seq_hint,
					DIR_REQUEST, args->source, size);
}

static __always_inline int handle_tls_response(void *ctx, const struct tls_rw_args *args, __u32 size)
{
	struct flow_state *state = NULL;
	const struct tls_fd_entry *fd_entry = NULL;
	__u64 chain_id = 0;
	__u64 seq_hint = 0;

	if (ensure_tls_flow_exists(&args->key) < 0)
		return 0;
	state = bpf_map_lookup_elem(&tls_flow_map, &args->key);
	if (!state)
		return 0;
	fd_entry = bpf_map_lookup_elem(&tls_fd_map, &args->key);

	state->tx_cursor += size;
	seq_hint = state->tx_cursor;
	chain_id = select_tls_response_chain(args, state, size);
	if (!chain_id)
		return 0;
	if (!state->resp_active || state->resp_chain_id != chain_id)
		start_response_capture(state, chain_id);
	state->last_req_chain_id = chain_id;
	state->resp_observed_bytes += size;

	return capture_plaintext(ctx, args, fd_entry, state, chain_id, seq_hint,
					DIR_RESPONSE, args->source, size);
}

static __always_inline int handle_rw_return(struct pt_regs *ctx)
{
	struct tls_rw_args *args = NULL;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 size = 0;
	long ret = PT_REGS_RC(ctx);

	args = bpf_map_lookup_elem(&tls_rw_args_map, &pid_tgid);
	if (!args)
		return 0;

	size = resolve_plaintext_size(args, ret);
	if (size > 0) {
		if (args->source == SRC_TLS_SSL_READ || args->source == SRC_TLS_SSL_READ_EX)
			handle_tls_request(ctx, args, size);
		else
			handle_tls_response(ctx, args, size);
	}

	bpf_map_delete_elem(&tls_rw_args_map, &pid_tgid);
	return 0;
}

static __always_inline int handle_fd_return(struct pt_regs *ctx)
{
	struct tls_fd_args *args = NULL;
	struct tls_fd_entry entry = {};
	struct tls_fd_entry *current = NULL;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	long ret = PT_REGS_RC(ctx);

	args = bpf_map_lookup_elem(&tls_fd_args_map, &pid_tgid);
	if (!args)
		return 0;

	if (ret == 1) {
		current = bpf_map_lookup_elem(&tls_fd_map, &args->key);
		if (current)
			entry = *current;
		if (args->source == SRC_TLS_SSL_READ)
			entry.read_fd = args->fd;
		else if (args->source == SRC_TLS_SSL_WRITE)
			entry.write_fd = args->fd;
		else {
			entry.read_fd = args->fd;
			entry.write_fd = args->fd;
		}
		bpf_map_update_elem(&tls_fd_map, &args->key, &entry, BPF_ANY);
	}

	bpf_map_delete_elem(&tls_fd_args_map, &pid_tgid);
	return 0;
}

static __always_inline int cleanup_tls_state(struct pt_regs *ctx, void *ssl)
{
	struct tls_ssl_key key = {};
	char comm[16] = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	(void)ctx;
	if (!ssl)
		return 0;
	if (!should_trace_current_task(comm))
		return 0;

	/*
	 * Keep SSL_free/SSL_shutdown cleanup deliberately simple for older
	 * verifiers such as 4.19. Close-delimited TLS responses still flush via
	 * user-space response stall timeout; this hook's main job is to retire
	 * per-SSL bookkeeping without perturbing HTTPS capture.
	 */
	fill_ssl_key(&key, pid_tgid, ssl);
	bpf_map_delete_elem(&tls_flow_map, &key);
	bpf_map_delete_elem(&tls_fd_map, &key);
	return 0;
}

SEC("uprobe/SSL_read")
int uprobe_ssl_read(struct pt_regs *ctx)
{
	return store_rw_args((void *)PT_REGS_PARM1(ctx), (void *)PT_REGS_PARM2(ctx),
			    PT_REGS_PARM3(ctx), 0, SRC_TLS_SSL_READ);
}

SEC("uretprobe/SSL_read")
int uretprobe_ssl_read(struct pt_regs *ctx)
{
	return handle_rw_return(ctx);
}

SEC("uprobe/SSL_write")
int uprobe_ssl_write(struct pt_regs *ctx)
{
	return store_rw_args((void *)PT_REGS_PARM1(ctx), (void *)PT_REGS_PARM2(ctx),
			    PT_REGS_PARM3(ctx), 0, SRC_TLS_SSL_WRITE);
}

SEC("uretprobe/SSL_write")
int uretprobe_ssl_write(struct pt_regs *ctx)
{
	return handle_rw_return(ctx);
}

SEC("uprobe/SSL_read_ex")
int uprobe_ssl_read_ex(struct pt_regs *ctx)
{
	return store_rw_args((void *)PT_REGS_PARM1(ctx), (void *)PT_REGS_PARM2(ctx),
			    PT_REGS_PARM3(ctx), PT_REGS_PARM4(ctx), SRC_TLS_SSL_READ_EX);
}

SEC("uretprobe/SSL_read_ex")
int uretprobe_ssl_read_ex(struct pt_regs *ctx)
{
	return handle_rw_return(ctx);
}

SEC("uprobe/SSL_write_ex")
int uprobe_ssl_write_ex(struct pt_regs *ctx)
{
	return store_rw_args((void *)PT_REGS_PARM1(ctx), (void *)PT_REGS_PARM2(ctx),
			    PT_REGS_PARM3(ctx), PT_REGS_PARM4(ctx), SRC_TLS_SSL_WRITE_EX);
}

SEC("uretprobe/SSL_write_ex")
int uretprobe_ssl_write_ex(struct pt_regs *ctx)
{
	return handle_rw_return(ctx);
}

SEC("uprobe/SSL_set_fd")
int uprobe_ssl_set_fd(struct pt_regs *ctx)
{
	return store_fd_args((void *)PT_REGS_PARM1(ctx), (__s32)PT_REGS_PARM2(ctx), SRC_UNKNOWN);
}

SEC("uretprobe/SSL_set_fd")
int uretprobe_ssl_set_fd(struct pt_regs *ctx)
{
	return handle_fd_return(ctx);
}

SEC("uprobe/SSL_set_rfd")
int uprobe_ssl_set_rfd(struct pt_regs *ctx)
{
	return store_fd_args((void *)PT_REGS_PARM1(ctx), (__s32)PT_REGS_PARM2(ctx), SRC_TLS_SSL_READ);
}

SEC("uretprobe/SSL_set_rfd")
int uretprobe_ssl_set_rfd(struct pt_regs *ctx)
{
	return handle_fd_return(ctx);
}

SEC("uprobe/SSL_set_wfd")
int uprobe_ssl_set_wfd(struct pt_regs *ctx)
{
	return store_fd_args((void *)PT_REGS_PARM1(ctx), (__s32)PT_REGS_PARM2(ctx), SRC_TLS_SSL_WRITE);
}

SEC("uretprobe/SSL_set_wfd")
int uretprobe_ssl_set_wfd(struct pt_regs *ctx)
{
	return handle_fd_return(ctx);
}

SEC("uprobe/SSL_shutdown")
int uprobe_ssl_shutdown(struct pt_regs *ctx)
{
	return cleanup_tls_state(ctx, (void *)PT_REGS_PARM1(ctx));
}

SEC("uprobe/SSL_free")
int uprobe_ssl_free(struct pt_regs *ctx)
{
	return cleanup_tls_state(ctx, (void *)PT_REGS_PARM1(ctx));
}

char LICENSE[] SEC("license") = "GPL";
