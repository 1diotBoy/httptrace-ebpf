package bpfgen

import "github.com/cilium/ebpf"

func LoadObjects(opts *ebpf.CollectionOptions) (*HttpTraceObjects, error) {
	var objs HttpTraceObjects

	if err := LoadHttpTraceObjects(&objs, opts); err != nil {
		return nil, err
	}
	return &objs, nil
}
