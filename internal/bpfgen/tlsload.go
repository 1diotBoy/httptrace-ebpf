package bpfgen

import "github.com/cilium/ebpf"

type LoadedTLSObjects struct {
	Events       *ebpf.Map
	TLSConfigMap *ebpf.Map

	UprobeSslRead     *ebpf.Program
	UretprobeSslRead  *ebpf.Program
	UprobeSslWrite    *ebpf.Program
	UretprobeSslWrite *ebpf.Program

	UprobeSslReadEx     *ebpf.Program
	UretprobeSslReadEx  *ebpf.Program
	UprobeSslWriteEx    *ebpf.Program
	UretprobeSslWriteEx *ebpf.Program

	UprobeSslSetFd     *ebpf.Program
	UretprobeSslSetFd  *ebpf.Program
	UprobeSslSetRfd    *ebpf.Program
	UretprobeSslSetRfd *ebpf.Program
	UprobeSslSetWfd    *ebpf.Program
	UretprobeSslSetWfd *ebpf.Program
	UprobeSslShutdown  *ebpf.Program
	UprobeSslFree      *ebpf.Program
	closer             closer
}

func (o *LoadedTLSObjects) Close() error {
	if o == nil || o.closer == nil {
		return nil
	}
	return o.closer.Close()
}

func LoadTLSObjects(opts *ebpf.CollectionOptions) (*LoadedTLSObjects, error) {
	opts = withVerifierLogs(opts)

	var raw TlsTraceObjects
	if err := LoadTlsTraceObjects(&raw, opts); err != nil {
		return nil, err
	}

	return &LoadedTLSObjects{
		Events:              raw.Events,
		TLSConfigMap:        raw.TlsConfigMap,
		UprobeSslRead:       raw.UprobeSslRead,
		UretprobeSslRead:    raw.UretprobeSslRead,
		UprobeSslWrite:      raw.UprobeSslWrite,
		UretprobeSslWrite:   raw.UretprobeSslWrite,
		UprobeSslReadEx:     raw.UprobeSslReadEx,
		UretprobeSslReadEx:  raw.UretprobeSslReadEx,
		UprobeSslWriteEx:    raw.UprobeSslWriteEx,
		UretprobeSslWriteEx: raw.UretprobeSslWriteEx,
		UprobeSslSetFd:      raw.UprobeSslSetFd,
		UretprobeSslSetFd:   raw.UretprobeSslSetFd,
		UprobeSslSetRfd:     raw.UprobeSslSetRfd,
		UretprobeSslSetRfd:  raw.UretprobeSslSetRfd,
		UprobeSslSetWfd:     raw.UprobeSslSetWfd,
		UretprobeSslSetWfd:  raw.UretprobeSslSetWfd,
		UprobeSslShutdown:   raw.UprobeSslShutdown,
		UprobeSslFree:       raw.UprobeSslFree,
		closer:              &raw,
	}, nil
}
