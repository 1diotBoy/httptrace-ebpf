#ifndef __HTTP_TRACE_COMPAT_H__
#define __HTTP_TRACE_COMPAT_H__

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#define DEFAULT_MESSAGE_LIMIT (10 * 1024)
/*
 * 为了兼容 4.19 上更严格的 verifier，这里把单次展开的分支数控制在可加载范围内。
 * 当前策略优先保证“单 iov 场景下最多采到 10KB”，这是大多数普通 HTTP 请求/响应的常见路径。
 */
#define MAX_PAYLOAD_SIZE 1024
#define MAX_IOVECS 2
#define MAX_CHUNKS_PER_IOV 5
#define MAX_FRAGMENTS (MAX_IOVECS * MAX_CHUNKS_PER_IOV)
#define MAX_CAPTURE_BYTES_PER_CALL (MAX_PAYLOAD_SIZE * MAX_FRAGMENTS)
#define MAX_PENDING_REQ 8

enum http_direction {
	DIR_UNKNOWN = 0,
	DIR_REQUEST = 1,
	DIR_RESPONSE = 2,
};

enum http_event_flags {
	EVT_FLAG_START = 1 << 0,
	EVT_FLAG_END = 1 << 1,
	EVT_FLAG_CAPTURE_TRUNC = 1 << 2,
	EVT_FLAG_HTTP_HINT = 1 << 3,
	EVT_FLAG_CONTROL = 1 << 4,
	EVT_FLAG_CLOSE = 1 << 5,
};

struct iovec_compat {
	void *iov_base;
	__u64 iov_len;
};

struct iov_iter_compat {
	int type;
	__u64 iov_offset;
	__u64 count;
	union {
		const struct iovec_compat *iov;
		const void *kvec;
		const void *bvec;
		const void *pipe;
	};
	union {
		unsigned long nr_segs;
		struct {
			unsigned int idx;
			unsigned int start_idx;
		};
	};
};

struct msghdr_compat {
	void *msg_name;
	int msg_namelen;
	struct iov_iter_compat msg_iter;
	void *msg_control;
	__u64 msg_controllen;
	unsigned int msg_flags;
};

struct socket_compat {
	__u16 state;
	__u16 type;
	__u32 pad0;
	__u64 flags;
	void *file;
	void *sk;
};

struct sock_common_compat {
	union {
		__u64 skc_addrpair;
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		__u32 skc_hash;
		__u16 skc_u16hashes[2];
	};
	union {
		__u32 skc_portpair;
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	__u16 skc_family;
	volatile __u8 skc_state;
	__u8 skc_flags_byte;
	int skc_bound_dev_if;
};

struct sock_compat {
	struct sock_common_compat __sk_common;
};

struct filter_config {
	__u32 ifindex;
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u32 capture_bytes;
};

struct flow_state {
	__u64 tx_cursor;
	__u64 rx_cursor;
	__u64 last_req_chain_id;
};

struct recv_args {
	__u64 sock_id;
	__u64 msg_ptr;
	struct iov_iter_compat saved_iter;
	__u64 seq_hint;
	__u32 pid;
	__u32 tid;
	__s32 fd;
	__u32 ifindex;
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u16 family;
	__u16 pad0;
	char comm[16];
};

struct emit_call {
	const struct recv_args *meta;
	__u64 chain_id;
	__u64 seq_hint;
	__u16 frag_idx;
	__u16 flags;
	__u16 total_len;
	__u8 direction;
	const char *src;
	__u32 payload_len;
};

struct capture_call {
	const struct iov_iter_compat *iter;
	const struct recv_args *meta;
	__u64 chain_id;
	__u64 seq_hint;
	__u32 *frag_cursor;
	__u32 *message_captured;
	__u8 *capture_stopped;
	__u32 total_len;
	__u16 base_flags;
	__u8 direction;
};

struct http_event {
	__u64 ts_ns;
	__u64 chain_id;
	__u64 sock_id;
	__u64 seq_hint;
	__u32 pid;
	__u32 tid;
	__s32 fd;
	__u32 ifindex;
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u16 payload_len;
	__u16 total_len;
	__u16 frag_idx;
	__u8 direction;
	__u8 flags;
	__u16 family;
	char comm[16];
	unsigned char payload[MAX_PAYLOAD_SIZE];
};

struct kernel_stats {
	__u64 send_calls;
	__u64 recv_calls;
	__u64 send_events;
	__u64 recv_events;
	__u64 filtered;
	__u64 perf_errors;
	__u64 truncations;
	__u64 close_events;
};

struct trace_event_raw_sys_enter_compat {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	__s64 id;
	unsigned long args[6];
};

#endif
