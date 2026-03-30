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
	SendCalls   uint64
	RecvCalls   uint64
	SendEvents  uint64
	RecvEvents  uint64
	Filtered    uint64
	PerfErrors  uint64
	Truncations uint64
	CloseEvents uint64
}
