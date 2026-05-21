package bpfgen

type HttpTraceFilterConfig struct {
	Ifindex              uint32
	SrcIp                uint32
	DstIp                uint32
	SrcPort              uint16
	DstPort              uint16
	RequestCaptureBytes  uint32
	ResponseCaptureBytes uint32
	DebugFlags           uint32
}

// 事件结构
type HttpTraceHttpEvent struct {
	TsNs                 uint64
	ChainId              uint64
	SockId               uint64
	SeqHint              uint64
	ObservedMessageBytes uint64
	Pid                  uint32
	Tid                  uint32
	Fd                   int32
	Ifindex              uint32
	SrcIp                uint32
	DstIp                uint32
	SrcPort              uint16
	DstPort              uint16
	PayloadLen           uint16
	TotalLen             uint16
	FragIdx              uint16
	Direction            uint8
	Flags                uint8
	Source               uint8
	Pad0                 uint8
	Family               uint16
	Comm                 [16]int8
	Payload              [4096]uint8 // 明文
}

type HttpTraceKernelStats struct {
	SendCalls             uint64
	RecvCalls             uint64
	SendEvents            uint64
	RecvEvents            uint64
	Filtered              uint64
	PerfErrors            uint64
	Truncations           uint64
	CloseEvents           uint64
	SockSendHits          uint64
	TcpSendHits           uint64
	SockRecvHits          uint64
	TcpRecvHits           uint64
	RecvStoreOk           uint64
	RecvStoreNoIter       uint64
	RecvStoreMetaFail     uint64
	RecvRetNoMeta         uint64
	RecvDirRequest        uint64
	RecvDirResponse       uint64
	RecvDirUnknown        uint64
	RecvFallbackLocal     uint64
	RecvFallbackKeepalive uint64
	SendNoReqChain        uint64
	SendRespStart         uint64
	SendRespContinue      uint64
	SendRespReqactive     uint64
	SendIterEmpty         uint64
	TupleIpv4Ok           uint64
	TupleIpv6Portonly     uint64
	TupleExtractFail      uint64
	TupleCacheUpdates     uint64
	TupleCacheDeletes     uint64
	TupleCacheHits        uint64
	TupleCacheMisses      uint64
	PrefixSecondIov       uint64
	PrefixTrimmed         uint64
	SendSizeOnlyEvents    uint64
	RecvSizeOnlyEvents    uint64
	SendGuardDuplicates   uint64
	SendGuardUpgrades     uint64
	RecvGuardDuplicates   uint64
	RecvGuardUpgrades     uint64
	IterUbuf              uint64
	IterIovec             uint64
	IterKvec              uint64
	IterBvec              uint64
	IterUnsupported       uint64
	IterLoadFail          uint64
}

type HttpTraceDebugSnapshot struct {
	Seq                uint64
	TsNs               uint64
	PidTgid            uint64
	SockId             uint64
	MsgPtr             uint64
	ChainId            uint64
	IterCount          uint64
	IterNrSegs         uint64
	IterIovOffset      uint64
	IterVecPtr         uint64
	Seg0Base           uint64
	Seg0Len            uint64
	Seg1Base           uint64
	Seg1Len            uint64
	Fd                 int32
	PendingCount       uint32
	Source             uint8
	Stage              uint8
	ReqActive          uint8
	RespActive         uint8
	IterType           uint8
	StartedNewResponse uint8
	LoadSeg0Rc         uint8
	LoadSeg1Rc         uint8
	PrefixLen          uint8
	Pad0               [3]uint8
	Prefix             [16]byte
	MsgRaw             [64]byte
	IterRaw            [64]byte
}
