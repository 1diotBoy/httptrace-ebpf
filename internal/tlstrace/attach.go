package tlstrace

import (
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"power-ebpf/internal/bpfgen"
)

// AttachAll wires TLS uprobes to the provided libssl shared objects.
func AttachAll(objs *bpfgen.LoadedTLSObjects, libPaths []string) ([]link.Link, error) {
	if objs == nil {
		return nil, fmt.Errorf("tls objects are nil")
	}
	if len(libPaths) == 0 {
		return nil, fmt.Errorf("no tls library path resolved")
	}

	attached := make([]link.Link, 0, len(libPaths)*12)
	for _, path := range libPaths {
		links, err := attachLibrary(objs, path)
		if err != nil {
			closeLinks(attached)
			return nil, err
		}
		attached = append(attached, links...)
	}
	return attached, nil
}

func attachLibrary(objs *bpfgen.LoadedTLSObjects, path string) ([]link.Link, error) {
	exe, err := link.OpenExecutable(path)
	if err != nil {
		return nil, fmt.Errorf("open tls library %s: %w", path, err)
	}

	attached := make([]link.Link, 0, 16)
	required := []struct {
		symbol string
		ret    bool
		prog   *ebpf.Program
	}{
		{symbol: "SSL_read", prog: objs.UprobeSslRead},
		{symbol: "SSL_read", ret: true, prog: objs.UretprobeSslRead},
		{symbol: "SSL_write", prog: objs.UprobeSslWrite},
		{symbol: "SSL_write", ret: true, prog: objs.UretprobeSslWrite},
		{symbol: "SSL_free", prog: objs.UprobeSslFree},
	}
	for _, item := range required {
		l, err := attachSymbol(exe, path, item.symbol, item.ret, item.prog)
		if err != nil {
			closeLinks(attached)
			return nil, err
		}
		attached = append(attached, l)
	}

	optional := []struct {
		symbol string
		ret    bool
		prog   *ebpf.Program
	}{
		{symbol: "SSL_read_ex", prog: objs.UprobeSslReadEx},
		{symbol: "SSL_read_ex", ret: true, prog: objs.UretprobeSslReadEx},
		{symbol: "SSL_write_ex", prog: objs.UprobeSslWriteEx},
		{symbol: "SSL_write_ex", ret: true, prog: objs.UretprobeSslWriteEx},
		{symbol: "SSL_set_fd", prog: objs.UprobeSslSetFd},
		{symbol: "SSL_set_fd", ret: true, prog: objs.UretprobeSslSetFd},
		{symbol: "SSL_set_rfd", prog: objs.UprobeSslSetRfd},
		{symbol: "SSL_set_rfd", ret: true, prog: objs.UretprobeSslSetRfd},
		{symbol: "SSL_set_wfd", prog: objs.UprobeSslSetWfd},
		{symbol: "SSL_set_wfd", ret: true, prog: objs.UretprobeSslSetWfd},
		{symbol: "SSL_shutdown", prog: objs.UprobeSslShutdown},
	}
	for _, item := range optional {
		if item.prog == nil {
			continue
		}
		l, err := attachSymbol(exe, path, item.symbol, item.ret, item.prog)
		if err != nil {
			if errors.Is(err, link.ErrNoSymbol) {
				log.Printf("skip optional tls uprobe %s on %s: %v", item.symbol, path, err)
				continue
			}
			closeLinks(attached)
			return nil, err
		}
		attached = append(attached, l)
	}

	log.Printf("attached tls uprobes on %s", path)
	return attached, nil
}

func attachSymbol(exe *link.Executable, path, symbol string, ret bool, prog *ebpf.Program) (link.Link, error) {
	if exe == nil || prog == nil {
		return nil, fmt.Errorf("invalid uprobe attach arguments for %s:%s", path, symbol)
	}

	if ret {
		l, err := exe.Uretprobe(symbol, prog, nil)
		if err != nil {
			return nil, fmt.Errorf("attach uretprobe %s on %s: %w", symbol, path, err)
		}
		return l, nil
	}

	l, err := exe.Uprobe(symbol, prog, nil)
	if err != nil {
		return nil, fmt.Errorf("attach uprobe %s on %s: %w", symbol, path, err)
	}
	return l, nil
}

func closeLinks(links []link.Link) {
	for _, l := range links {
		if l != nil {
			_ = l.Close()
		}
	}
}
