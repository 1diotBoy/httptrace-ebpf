package bpfgen

type HttpTraceFilterConfig struct {
	Ifindex      uint32
	SrcIp        uint32
	DstIp        uint32
	SrcPort      uint16
	DstPort      uint16
	CaptureBytes uint32
}

type HttpTraceHttpEvent struct {
	TsNs       uint64
	ChainId    uint64
	SockId     uint64
	SeqHint    uint64
	Pid        uint32
	Tid        uint32
	Fd         int32
	Ifindex    uint32
	SrcIp      uint32
	DstIp      uint32
	SrcPort    uint16
	DstPort    uint16
	PayloadLen uint16
	TotalLen   uint16
	FragIdx    uint16
	Direction  uint8
	Flags      uint8
	Family     uint16
	Comm       [16]int8
	Payload    [1024]uint8
}

type HttpTraceKernelStats struct {
	SendCalls            uint64
	RecvCalls            uint64
	SendEvents           uint64
	RecvEvents           uint64
	Filtered             uint64
	PerfErrors           uint64
	Truncations          uint64
	CloseEvents          uint64
	SockSendHits         uint64
	TcpSendHits          uint64
	SockRecvHits         uint64
	TcpRecvHits          uint64
	RecvStoreOk          uint64
	RecvStoreNoIter      uint64
	RecvStoreMetaFail    uint64
	RecvRetNoMeta        uint64
	RecvDirRequest       uint64
	RecvDirResponse      uint64
	RecvDirUnknown       uint64
	RecvFallbackLocal    uint64
	RecvFallbackKeepalive uint64
	SendNoReqChain       uint64
	SendRespStart        uint64
	SendRespContinue     uint64
	SendIterEmpty        uint64
}
