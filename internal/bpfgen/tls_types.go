package bpfgen

type TlsTraceConfig struct {
	RequestCaptureBytes  uint32
	ResponseCaptureBytes uint32
	Comm                 [16]int8
}
