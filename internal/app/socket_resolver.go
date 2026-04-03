package app

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"power-ebpf/internal/httptrace"
)

type socketResolver struct {
	ttl   time.Duration
	mu    sync.RWMutex
	cache map[socketKey]cachedSocketTuple
}

type resolveSource uint8

const (
	resolveMiss resolveSource = iota
	resolveFromCache
	resolveFromProc
)

type socketKey struct {
	pid    uint32
	fd     int32
	sockID uint64
}

type cachedSocketTuple struct {
	localIP    string
	remoteIP   string
	localPort  uint16
	remotePort uint16
	expiresAt  time.Time
}

func newSocketResolver(ttl time.Duration) *socketResolver {
	if ttl <= 0 {
		ttl = 15 * time.Second
	}
	return &socketResolver{
		ttl:   ttl,
		cache: make(map[socketKey]cachedSocketTuple),
	}
}

func missingTuple(event httptrace.Event) bool {
	srcMissing := event.SrcIP == "" || event.SrcIP == "0.0.0.0" || event.SrcPort == 0
	dstMissing := event.DstIP == "" || event.DstIP == "0.0.0.0" || event.DstPort == 0
	return srcMissing || dstMissing
}

func (r *socketResolver) Resolve(event httptrace.Event) (httptrace.Event, resolveSource) {
	if event.PID == 0 || event.FD < 0 || !missingTuple(event) {
		return event, resolveMiss
	}

	key := socketKey{pid: event.PID, fd: event.FD, sockID: event.SockID}
	if tuple, ok := r.lookupCache(key); ok {
		return applyResolvedTuple(event, tuple), resolveFromCache
	}

	tuple, ok := resolveSocketTuple(event.PID, event.FD)
	if !ok {
		return event, resolveMiss
	}
	r.storeCache(key, tuple)
	return applyResolvedTuple(event, tuple), resolveFromProc
}

func (r *socketResolver) lookupCache(key socketKey) (cachedSocketTuple, bool) {
	now := time.Now()

	r.mu.RLock()
	value, ok := r.cache[key]
	r.mu.RUnlock()
	if !ok {
		return cachedSocketTuple{}, false
	}
	if now.After(value.expiresAt) {
		r.mu.Lock()
		delete(r.cache, key)
		r.mu.Unlock()
		return cachedSocketTuple{}, false
	}
	return value, true
}

func (r *socketResolver) storeCache(key socketKey, tuple cachedSocketTuple) {
	tuple.expiresAt = time.Now().Add(r.ttl)
	r.mu.Lock()
	r.cache[key] = tuple
	r.mu.Unlock()
}

func applyResolvedTuple(event httptrace.Event, tuple cachedSocketTuple) httptrace.Event {
	switch event.Direction {
	case httptrace.DirectionRequest:
		event.SrcIP = tuple.remoteIP
		event.DstIP = tuple.localIP
		event.SrcPort = tuple.remotePort
		event.DstPort = tuple.localPort
	case httptrace.DirectionResponse:
		event.SrcIP = tuple.localIP
		event.DstIP = tuple.remoteIP
		event.SrcPort = tuple.localPort
		event.DstPort = tuple.remotePort
	default:
		event.SrcIP = tuple.localIP
		event.DstIP = tuple.remoteIP
		event.SrcPort = tuple.localPort
		event.DstPort = tuple.remotePort
	}
	return event
}

func resolveSocketTuple(pid uint32, fd int32) (cachedSocketTuple, bool) {
	inode, ok := resolveSocketInode(pid, fd)
	if !ok {
		return cachedSocketTuple{}, false
	}
	return lookupSocketTuple(pid, inode)
}

func resolveSocketInode(pid uint32, fd int32) (string, bool) {
	link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
	if err != nil {
		return "", false
	}
	if !strings.HasPrefix(link, "socket:[") || !strings.HasSuffix(link, "]") {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), true
}

func lookupSocketTuple(pid uint32, inode string) (cachedSocketTuple, bool) {
	paths := []string{
		fmt.Sprintf("/proc/%d/net/tcp", pid),
		fmt.Sprintf("/proc/%d/net/tcp6", pid),
		"/proc/net/tcp",
		"/proc/net/tcp6",
	}
	for _, path := range paths {
		if tuple, ok := lookupSocketTupleInFile(path, inode); ok {
			return tuple, true
		}
	}
	return cachedSocketTuple{}, false
}

func lookupSocketTupleInFile(path, inode string) (cachedSocketTuple, bool) {
	file, err := os.Open(path)
	if err != nil {
		return cachedSocketTuple{}, false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	first := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if first {
			first = false
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[9] != inode {
			continue
		}
		localIP, localPort, ok := parseProcAddr(fields[1])
		if !ok {
			return cachedSocketTuple{}, false
		}
		remoteIP, remotePort, ok := parseProcAddr(fields[2])
		if !ok {
			return cachedSocketTuple{}, false
		}
		return cachedSocketTuple{
			localIP:    localIP,
			remoteIP:   remoteIP,
			localPort:  localPort,
			remotePort: remotePort,
		}, true
	}
	return cachedSocketTuple{}, false
}

func parseProcAddr(raw string) (string, uint16, bool) {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return "", 0, false
	}
	ipHex, portHex := parts[0], parts[1]
	if len(ipHex) == 8 {
		ip, ok := parseIPv4HexLE(ipHex)
		if !ok {
			return "", 0, false
		}
		port, ok := parsePortHex(portHex)
		if !ok {
			return "", 0, false
		}
		return ip, port, true
	}
	if len(ipHex) == 32 {
		ip, ok := parseIPv6ProcHex(ipHex)
		if !ok {
			return "", 0, false
		}
		port, ok := parsePortHex(portHex)
		if !ok {
			return "", 0, false
		}
		return ip, port, true
	}
	return "", 0, false
}

func parseIPv4HexLE(raw string) (string, bool) {
	if len(raw) != 8 {
		return "", false
	}
	b0, err := strconv.ParseUint(raw[6:8], 16, 8)
	if err != nil {
		return "", false
	}
	b1, err := strconv.ParseUint(raw[4:6], 16, 8)
	if err != nil {
		return "", false
	}
	b2, err := strconv.ParseUint(raw[2:4], 16, 8)
	if err != nil {
		return "", false
	}
	b3, err := strconv.ParseUint(raw[0:2], 16, 8)
	if err != nil {
		return "", false
	}
	return fmt.Sprintf("%d.%d.%d.%d", b0, b1, b2, b3), true
}

func parsePortHex(raw string) (uint16, bool) {
	v, err := strconv.ParseUint(raw, 16, 16)
	if err != nil {
		return 0, false
	}
	return uint16(v), true
}

func parseIPv6ProcHex(raw string) (string, bool) {
	if len(raw) != 32 {
		return "", false
	}
	data, err := hex.DecodeString(raw)
	if err != nil || len(data) != 16 {
		return "", false
	}
	// /proc/net/tcp6 以 4 个 32-bit word 输出，每个 word 需要按本机字节序翻转回网络序。
	for i := 0; i < 16; i += 4 {
		data[i+0], data[i+1], data[i+2], data[i+3] = data[i+3], data[i+2], data[i+1], data[i+0]
	}
	ip := net.IP(data)
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), true
	}
	if len(data) == net.IPv6len &&
		data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 0 &&
		data[4] == 0 && data[5] == 0 && data[6] == 0 && data[7] == 0 &&
		data[8] == 0 && data[9] == 0 && data[10] == 0xff && data[11] == 0xff {
		return net.IP(data[12:16]).String(), true
	}
	return ip.String(), true
}
