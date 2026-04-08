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

#ifndef AF_INET6
#define AF_INET6 10
#endif

#define DEFAULT_MESSAGE_LIMIT (10 * 1024)
/*
 * 为了兼容 4.19 上更严格的 verifier，这里把单次展开的分支数控制在可加载范围内。
 * 当前策略优先保证“单 iov 场景下最多采到 10KB”，这是大多数普通 HTTP 请求/响应的常见路径。
 */
#define EVENT_PAYLOAD_SIZE 1024
#define MAX_PAYLOAD_SIZE 1023
#define MAX_PAYLOAD_MASK 1023
#define MAX_IOVECS 2
#define MAX_CHUNKS_PER_IOV 5
#define MAX_FRAGMENTS (MAX_IOVECS * MAX_CHUNKS_PER_IOV)
#define MAX_CAPTURE_BYTES_PER_CALL (MAX_PAYLOAD_SIZE * MAX_FRAGMENTS)
/* 4.19 verifier 对带循环/变量索引的队列实现非常敏感。
 * 这里把待响应请求队列固定成 4 个槽位，后面用纯分支赋值实现，
 * 避免生成任何 back-edge。
 */
#define MAX_PENDING_REQ 4

enum http_direction {
	DIR_UNKNOWN = 0,
	DIR_REQUEST = 1,
	DIR_RESPONSE = 2,
};

enum capture_source {
	SRC_UNKNOWN = 0,
	SRC_SOCK_SENDMSG = 1,
	SRC_TCP_SENDMSG = 2,
	SRC_SOCK_RECVMSG = 3,
	SRC_TCP_RECVMSG = 4,
	SRC_TCP_CLOSE = 5,
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
	__u64 conn_id;
	__u64 tx_cursor;
	__u64 rx_cursor;
	__u64 last_req_chain_id;
	__u64 resp_chain_id;
	__u64 pending_req_chain0;
	__u64 pending_req_chain1;
	__u64 pending_req_chain2;
	__u64 pending_req_chain3;
	__u32 req_seq;
	__u32 req_capture_bytes;
	__u32 resp_capture_bytes;
	__u32 req_frag_idx;
	__u32 resp_frag_idx;
	__u8 pending_count;
	__u8 req_active;
	__u8 resp_active;
	__u8 req_capture_stopped;
	__u8 resp_capture_stopped;
	__u8 pad0[3];
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
	__u8 source;
	__u8 pad0;
	char comm[16];
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
	__u8 source;
};

struct send_capture_scratch {
	struct recv_args meta;
	struct iov_iter_compat iter;
};

struct send_guard {
	__u64 msg_ptr;
	__u8 source;
	__u8 pad0[7];
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
	__u8 source;
	__u8 pad0;
	__u16 family;
	char comm[16];
	unsigned char payload[EVENT_PAYLOAD_SIZE];
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
	__u64 sock_send_hits;
	__u64 tcp_send_hits;
	__u64 sock_recv_hits;
	__u64 tcp_recv_hits;
	__u64 recv_store_ok;
	__u64 recv_store_no_iter;
	__u64 recv_store_meta_fail;
	__u64 recv_ret_no_meta;
	__u64 recv_dir_request;
	__u64 recv_dir_response;
	__u64 recv_dir_unknown;
	__u64 recv_fallback_local;
	__u64 recv_fallback_keepalive;
	__u64 send_no_req_chain;
	__u64 send_resp_start;
	__u64 send_resp_continue;
	__u64 send_resp_reqactive;
	__u64 send_iter_empty;
	__u64 tuple_ipv4_ok;
	__u64 tuple_ipv6_portonly;
	__u64 tuple_extract_fail;
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
