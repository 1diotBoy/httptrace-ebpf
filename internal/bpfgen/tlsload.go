package bpfgen

import (
	"log"

	"github.com/cilium/ebpf"
)

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

	UprobeSslClear          *ebpf.Program
	UprobeSslSetFd          *ebpf.Program
	UretprobeSslSetFd       *ebpf.Program
	UprobeSslSetAcceptState *ebpf.Program
	UprobeSslSetRfd         *ebpf.Program
	UretprobeSslSetRfd      *ebpf.Program
	UprobeSslSetWfd         *ebpf.Program
	UretprobeSslSetWfd      *ebpf.Program
	UprobeSslShutdown       *ebpf.Program
	UprobeSslFree           *ebpf.Program
	closer                  closer
}

func (o *LoadedTLSObjects) Close() error {
	if o == nil || o.closer == nil {
		return nil
	}
	return o.closer.Close()
}

func LoadTLSObjects(opts *ebpf.CollectionOptions) (*LoadedTLSObjects, error) {
	opts = withVerifierLogs(opts)
	version := detectKernelVersion()

	if version.Major == 4 {
		log.Printf("tls legacy kernel detected: load legacy TLS eBPF objects directly kernel=%s", version.Release)
		legacy, err := loadTLSLegacy(opts)
		if err != nil {
			return nil, err
		}
		log.Printf("tls eBPF objects loaded variant=legacy-4.x kernel=%s", version.Release)
		return legacy, nil
	}

	objs, err := loadTLSModern(opts)
	if err == nil {
		log.Printf("tls eBPF objects loaded variant=modern kernel=%s", version.Release)
		return objs, nil
	}

	if !shouldFallbackToLegacy(err) {
		return nil, err
	}
	log.Printf("tls modern objects load failed, trying legacy fallback: %v", err)

	legacy, legacyErr := loadTLSLegacy(opts)
	if legacyErr == nil {
		log.Printf("tls eBPF objects loaded variant=legacy-4.x kernel=%s", version.Release)
		return legacy, nil
	}
	return nil, legacyErr
}

func loadTLSModern(opts *ebpf.CollectionOptions) (*LoadedTLSObjects, error) {
	var raw TlsTraceObjects

	if err := LoadTlsTraceObjects(&raw, opts); err != nil {
		return nil, err
	}

	return &LoadedTLSObjects{
		Events:                  raw.Events,
		TLSConfigMap:            raw.TlsConfigMap,
		UprobeSslRead:           raw.UprobeSslRead,
		UretprobeSslRead:        raw.UretprobeSslRead,
		UprobeSslWrite:          raw.UprobeSslWrite,
		UretprobeSslWrite:       raw.UretprobeSslWrite,
		UprobeSslReadEx:         raw.UprobeSslReadEx,
		UretprobeSslReadEx:      raw.UretprobeSslReadEx,
		UprobeSslWriteEx:        raw.UprobeSslWriteEx,
		UretprobeSslWriteEx:     raw.UretprobeSslWriteEx,
		UprobeSslClear:          raw.UprobeSslClear,
		UprobeSslSetFd:          raw.UprobeSslSetFd,
		UretprobeSslSetFd:       raw.UretprobeSslSetFd,
		UprobeSslSetAcceptState: raw.UprobeSslSetAcceptState,
		UprobeSslSetRfd:         raw.UprobeSslSetRfd,
		UretprobeSslSetRfd:      raw.UretprobeSslSetRfd,
		UprobeSslSetWfd:         raw.UprobeSslSetWfd,
		UretprobeSslSetWfd:      raw.UretprobeSslSetWfd,
		UprobeSslShutdown:       raw.UprobeSslShutdown,
		UprobeSslFree:           raw.UprobeSslFree,
		closer:                  &raw,
	}, nil
}

func loadTLSLegacy(opts *ebpf.CollectionOptions) (*LoadedTLSObjects, error) {
	var raw TlsTraceLegacyObjects

	if err := LoadTlsTraceLegacyObjects(&raw, opts); err != nil {
		return nil, err
	}

	return &LoadedTLSObjects{
		Events:                  raw.Events,
		TLSConfigMap:            raw.TlsConfigMap,
		UprobeSslRead:           raw.UprobeSslRead,
		UretprobeSslRead:        raw.UretprobeSslRead,
		UprobeSslWrite:          raw.UprobeSslWrite,
		UretprobeSslWrite:       raw.UretprobeSslWrite,
		UprobeSslReadEx:         raw.UprobeSslReadEx,
		UretprobeSslReadEx:      raw.UretprobeSslReadEx,
		UprobeSslWriteEx:        raw.UprobeSslWriteEx,
		UretprobeSslWriteEx:     raw.UretprobeSslWriteEx,
		UprobeSslClear:          raw.UprobeSslClear,
		UprobeSslSetFd:          raw.UprobeSslSetFd,
		UretprobeSslSetFd:       raw.UretprobeSslSetFd,
		UprobeSslSetAcceptState: raw.UprobeSslSetAcceptState,
		UprobeSslSetRfd:         raw.UprobeSslSetRfd,
		UretprobeSslSetRfd:      raw.UretprobeSslSetRfd,
		UprobeSslSetWfd:         raw.UprobeSslSetWfd,
		UretprobeSslSetWfd:      raw.UretprobeSslSetWfd,
		UprobeSslShutdown:       raw.UprobeSslShutdown,
		UprobeSslFree:           raw.UprobeSslFree,
		closer:                  &raw,
	}, nil
}
