package bpfgen

import (
	"fmt"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
)

type closer interface {
	Close() error
}

// LoadedObjects 把 modern/legacy 两套 bpf2go 产物统一成同一组句柄，
// 上层业务不需要关心当前实际加载的是哪一版 eBPF 对象。
type LoadedObjects struct {
	Variant string

	Events         *ebpf.Map
	FilterMap      *ebpf.Map
	KernelStatsMap *ebpf.Map

	KprobeSockRecvmsg    *ebpf.Program
	KprobeSockSendmsg    *ebpf.Program
	KprobeTcpClose       *ebpf.Program
	KprobeTcpSendmsg     *ebpf.Program
	KprobeTcpV4Connect   *ebpf.Program
	KretprobeTcpV4Connect *ebpf.Program
	KprobeTcpV6Connect   *ebpf.Program
	KretprobeTcpV6Connect *ebpf.Program
	KretprobeInetCskAccept *ebpf.Program
	KretprobeSockRecvmsg *ebpf.Program

	TracepointSockInetSockSetState *ebpf.Program
	TracepointSysEnterRead     *ebpf.Program
	TracepointSysEnterReadv    *ebpf.Program
	TracepointSysEnterRecvfrom *ebpf.Program
	TracepointSysEnterRecvmsg  *ebpf.Program
	TracepointSysEnterSendmsg  *ebpf.Program
	TracepointSysEnterSendto   *ebpf.Program
	TracepointSysEnterWrite    *ebpf.Program
	TracepointSysEnterWritev   *ebpf.Program

	closer closer
}

func (o *LoadedObjects) Close() error {
	if o == nil || o.closer == nil {
		return nil
	}
	return o.closer.Close()
}

func LoadObjects(opts *ebpf.CollectionOptions) (*LoadedObjects, error) {
	if prefersLegacyVerifierObject() {
		objs, err := loadLegacyObjects(opts)
		if err != nil {
			return nil, err
		}
		return objs, nil
	}

	objs, err := loadModernObjects(opts)
	if err == nil {
		return objs, nil
	}

	if shouldFallbackToLegacy(err) {
		legacy, legacyErr := loadLegacyObjects(opts)
		if legacyErr == nil {
			return legacy, nil
		}
		return nil, fmt.Errorf("load modern objects: %w; load legacy fallback: %v", err, legacyErr)
	}

	return nil, err
}

func loadModernObjects(opts *ebpf.CollectionOptions) (*LoadedObjects, error) {
	var raw HttpTraceObjects

	if err := LoadHttpTraceObjects(&raw, opts); err != nil {
		return nil, err
	}
	return &LoadedObjects{
		Variant:                  "modern",
		Events:                   raw.Events,
		FilterMap:                raw.FilterMap,
		KernelStatsMap:           raw.KernelStatsMap,
		KprobeSockRecvmsg:        raw.KprobeSockRecvmsg,
		KprobeSockSendmsg:        raw.KprobeSockSendmsg,
		KprobeTcpClose:           raw.KprobeTcpClose,
		KprobeTcpSendmsg:         raw.KprobeTcpSendmsg,
		KprobeTcpV4Connect:       raw.KprobeTcpV4Connect,
		KretprobeTcpV4Connect:    raw.KretprobeTcpV4Connect,
		KprobeTcpV6Connect:       raw.KprobeTcpV6Connect,
		KretprobeTcpV6Connect:    raw.KretprobeTcpV6Connect,
		KretprobeInetCskAccept:   raw.KretprobeInetCskAccept,
		KretprobeSockRecvmsg:     raw.KretprobeSockRecvmsg,
		TracepointSockInetSockSetState: raw.TracepointSockInetSockSetState,
		TracepointSysEnterRead:     raw.TracepointSysEnterRead,
		TracepointSysEnterReadv:    raw.TracepointSysEnterReadv,
		TracepointSysEnterRecvfrom: raw.TracepointSysEnterRecvfrom,
		TracepointSysEnterRecvmsg:  raw.TracepointSysEnterRecvmsg,
		TracepointSysEnterSendmsg:  raw.TracepointSysEnterSendmsg,
		TracepointSysEnterSendto:   raw.TracepointSysEnterSendto,
		TracepointSysEnterWrite:    raw.TracepointSysEnterWrite,
		TracepointSysEnterWritev:   raw.TracepointSysEnterWritev,
		closer:                  &raw,
	}, nil
}

func loadLegacyObjects(opts *ebpf.CollectionOptions) (*LoadedObjects, error) {
	var raw HttpTraceLegacyObjects

	if err := LoadHttpTraceLegacyObjects(&raw, opts); err != nil {
		return nil, err
	}
	return &LoadedObjects{
		Variant:                  "legacy-4.x",
		Events:                   raw.Events,
		FilterMap:                raw.FilterMap,
		KernelStatsMap:           raw.KernelStatsMap,
		KprobeSockRecvmsg:        raw.KprobeSockRecvmsg,
		KprobeSockSendmsg:        raw.KprobeSockSendmsg,
		KprobeTcpClose:           raw.KprobeTcpClose,
		KprobeTcpSendmsg:         raw.KprobeTcpSendmsg,
		KprobeTcpV4Connect:       raw.KprobeTcpV4Connect,
		KretprobeTcpV4Connect:    raw.KretprobeTcpV4Connect,
		KprobeTcpV6Connect:       raw.KprobeTcpV6Connect,
		KretprobeTcpV6Connect:    raw.KretprobeTcpV6Connect,
		KretprobeInetCskAccept:   raw.KretprobeInetCskAccept,
		KretprobeSockRecvmsg:     raw.KretprobeSockRecvmsg,
		TracepointSockInetSockSetState: raw.TracepointSockInetSockSetState,
		TracepointSysEnterRead:     raw.TracepointSysEnterRead,
		TracepointSysEnterReadv:    raw.TracepointSysEnterReadv,
		TracepointSysEnterRecvfrom: raw.TracepointSysEnterRecvfrom,
		TracepointSysEnterRecvmsg:  raw.TracepointSysEnterRecvmsg,
		TracepointSysEnterSendmsg:  raw.TracepointSysEnterSendmsg,
		TracepointSysEnterSendto:   raw.TracepointSysEnterSendto,
		TracepointSysEnterWrite:    raw.TracepointSysEnterWrite,
		TracepointSysEnterWritev:   raw.TracepointSysEnterWritev,
		closer:                  &raw,
	}, nil
}

func prefersLegacyVerifierObject() bool {
	var uts syscall.Utsname

	if err := syscall.Uname(&uts); err != nil {
		return false
	}

	release := strings.TrimSpace(cStringInt8(uts.Release[:]))
	return strings.HasPrefix(release, "4.")
}

func shouldFallbackToLegacy(err error) bool {
	if err == nil {
		return false
	}

	msg := err.Error()
	return strings.Contains(msg, "back-edge") ||
		strings.Contains(msg, "program is too large") ||
		strings.Contains(msg, "argument list too long") ||
		strings.Contains(msg, "jump out of range")
}

func cStringInt8(raw []int8) string {
	var b strings.Builder
	for _, c := range raw {
		if c == 0 {
			break
		}
		b.WriteByte(byte(c))
	}
	return b.String()
}
