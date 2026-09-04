package bpfgen

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
)

type closer interface {
	Close() error
}

type collectionCloser struct {
	collection *ebpf.Collection
}

func (c collectionCloser) Close() error {
	if c.collection != nil {
		c.collection.Close()
	}
	return nil
}

type HookStrategy string

const (
	HookStrategyLegacySock    HookStrategy = "legacy-sock"
	HookStrategyLegacyTCPSend HookStrategy = "legacy-tcp-send"
	HookStrategyLegacyTCPBoth HookStrategy = "legacy-tcp-both"
	HookStrategyTCPOnly       HookStrategy = "tcp-only"
)

const objectVariantEnv = "POWER_EBPF_OBJECT_VARIANT"

type kernelVersion struct {
	Release string
	Major   int
	Minor   int
}

type kernelProfile struct {
	Name     string
	Match    func(kernelVersion) bool
	Variants []string
}

type variantPlan struct {
	Name         string
	HookStrategy HookStrategy
	Load         func(*ebpf.CollectionOptions) (*LoadedObjects, error)
}

var knownKernelProfiles = []kernelProfile{
	{
		Name: "vendor-4.19.90-52.42-ky10-aarch64",
		Match: func(version kernelVersion) bool {
			return preferLegacyUserRead(version.Release)
		},
		Variants: []string{"legacy-4.x-userread", "legacy-4.x"},
	},
	{
		Name: "vendor-4.19.90-24.4-ky10",
		Match: func(version kernelVersion) bool {
			return preferLegacyTCPBoth(version.Release)
		},
		Variants: []string{"legacy-4.x-tcp-both", "legacy-4.x-tcp-send", "legacy-4.x"},
	},
	{
		Name: "vendor-4.19.90-2403-uel20",
		Match: func(version kernelVersion) bool {
			return preferLegacyTCPSend(version.Release)
		},
		Variants: []string{"legacy-4.x-tcp-send", "legacy-4.x"},
	},
}

// LoadedObjects 把 modern/legacy 两套 bpf2go 产物统一成同一组句柄，
// 上层业务不需要关心当前实际加载的是哪一版 eBPF 对象。
type LoadedObjects struct {
	Variant      string       // 变体名称
	HookStrategy HookStrategy // 钩子策略

	Events           *ebpf.Map // 事件映射
	FilterMap        *ebpf.Map // 过滤映射
	KernelStatsMap   *ebpf.Map // 内核统计映射
	DebugSnapshotMap *ebpf.Map // 调试快照映射

	KprobeSockRecvmsg      *ebpf.Program
	KprobeSockSendmsg      *ebpf.Program
	KprobeTcpClose         *ebpf.Program
	KprobeTcpRecvmsg       *ebpf.Program
	KprobeTcpSendmsg       *ebpf.Program
	KprobeTcpV4Connect     *ebpf.Program
	KretprobeTcpV4Connect  *ebpf.Program
	KprobeTcpV6Connect     *ebpf.Program
	KretprobeTcpV6Connect  *ebpf.Program
	KretprobeInetCskAccept *ebpf.Program
	KretprobeSockRecvmsg   *ebpf.Program
	KretprobeTcpRecvmsg    *ebpf.Program

	TracepointSockInetSockSetState *ebpf.Program
	TracepointSysEnterRead         *ebpf.Program
	TracepointSysEnterReadv        *ebpf.Program
	TracepointSysEnterRecvfrom     *ebpf.Program
	TracepointSysEnterRecvmsg      *ebpf.Program
	TracepointSysEnterSendmsg      *ebpf.Program
	TracepointSysEnterSendto       *ebpf.Program
	TracepointSysEnterWrite        *ebpf.Program
	TracepointSysEnterWritev       *ebpf.Program

	closer closer
}

func (o *LoadedObjects) Close() error {
	if o == nil || o.closer == nil {
		return nil
	}
	return o.closer.Close()
}

func LoadObjects(opts *ebpf.CollectionOptions) (*LoadedObjects, error) {
	opts = withVerifierLogs(opts)

	version := detectKernelVersion()
	plans := chooseVariantPlans(version)
	if len(plans) == 0 {
		return nil, fmt.Errorf("no eBPF object variant available for kernel %s", version.Release)
	}

	var errs []string
	for _, plan := range plans {
		log.Printf("正在加载 eBPF 对象：variant=%s kernel=%s hook_strategy=%s", plan.Name, version.Release, plan.HookStrategy)
		objs, err := plan.Load(opts)
		if err == nil {
			log.Printf("eBPF 对象加载完成：variant=%s kernel=%s hook_strategy=%s", plan.Name, version.Release, plan.HookStrategy)
			return objs, nil
		}

		// Collection 加载会将实际程序加载错误包装为失败字段名。普通返回错误保持简洁，
		// 但在这里输出完整的 verifier/errno 诊断，使旧内核返回的 EINVAL 不会只显示为“无效参数”。
		logKernelLoadFailure(version, plan, err)
		errs = append(errs, fmt.Sprintf("%s: %v", plan.Name, err))
		if !shouldTryNextVariant(plan.Name, err) {
			return nil, fmt.Errorf("load %s objects: %w", plan.Name, err)
		}
		log.Printf("加载 variant=%s 失败，尝试下一个候选项：%v", plan.Name, err)
	}

	return nil, fmt.Errorf("load bpf variants for kernel %s: %s", version.Release, strings.Join(errs, "; "))
}

// logKernelLoadFailure 输出生成的 bpf2go LoadAndAssign 包装器默认隐藏的信息。
// cilium/ebpf 收到 verifier 拒绝时可以提供 verifier 日志，并默认使用诊断日志重试加载；
// 排障时可通过 POWER_EBPF_VERIFIER_LOG 请求更大的指令级缓冲区。
func logKernelLoadFailure(version kernelVersion, plan variantPlan, err error) {
	if err == nil {
		return
	}

	log.Printf("eBPF 加载失败：variant=%s hook_strategy=%s kernel=%s (%d.%d) error_type=%T error=%v",
		plan.Name, plan.HookStrategy, version.Release, version.Major, version.Minor, err, err)

	var verifierErr *ebpf.VerifierError
	if errors.As(err, &verifierErr) {
		if len(verifierErr.Log) == 0 {
			log.Printf("eBPF verifier 日志不可用：内核在输出 verifier 信息前拒绝了请求；请设置 POWER_EBPF_VERIFIER_LOG=1 后重试")
		} else {
			const maxPrintedVerifierLog = 1 << 20
			text := strings.Join(verifierErr.Log, "\n")
			if len(text) > maxPrintedVerifierLog {
				log.Printf("eBPF verifier 日志（共 %d 字节，前 %d 字节）：\n%s", len(text), maxPrintedVerifierLog, text[:maxPrintedVerifierLog])
				log.Printf("eBPF verifier 日志已截断；POWER_EBPF_VERIFIER_LOG 控制采集缓冲区大小，当前缓冲区可能包含完整日志")
			} else {
				log.Printf("eBPF verifier 日志（%d 字节）：\n%s", len(text), text)
			}
		}
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		log.Printf("eBPF 加载 errno：%d（%s）；EINVAL 通常表示当前内核不支持某个 helper/程序属性，或 verifier 拒绝了程序",
			errno, errno)
	}
}

func loadModernObjects(opts *ebpf.CollectionOptions) (*LoadedObjects, error) {
	var raw HttpTraceObjects

	if err := LoadHttpTraceObjects(&raw, opts); err != nil {
		return nil, err
	}
	return &LoadedObjects{
		Variant:                        "modern-mixed",
		HookStrategy:                   HookStrategyTCPOnly,
		Events:                         raw.Events,
		FilterMap:                      raw.FilterMap,
		KernelStatsMap:                 raw.KernelStatsMap,
		DebugSnapshotMap:               raw.DebugSnapshotMap,
		KprobeSockRecvmsg:              raw.KprobeSockRecvmsg,
		KprobeSockSendmsg:              raw.KprobeSockSendmsg,
		KprobeTcpClose:                 raw.KprobeTcpClose,
		KprobeTcpRecvmsg:               raw.KprobeTcpRecvmsg,
		KprobeTcpSendmsg:               raw.KprobeTcpSendmsg,
		KprobeTcpV4Connect:             raw.KprobeTcpV4Connect,
		KretprobeTcpV4Connect:          raw.KretprobeTcpV4Connect,
		KprobeTcpV6Connect:             raw.KprobeTcpV6Connect,
		KretprobeTcpV6Connect:          raw.KretprobeTcpV6Connect,
		KretprobeInetCskAccept:         raw.KretprobeInetCskAccept,
		KretprobeSockRecvmsg:           raw.KretprobeSockRecvmsg,
		KretprobeTcpRecvmsg:            raw.KretprobeTcpRecvmsg,
		TracepointSockInetSockSetState: raw.TracepointSockInetSockSetState,
		TracepointSysEnterRead:         raw.TracepointSysEnterRead,
		TracepointSysEnterReadv:        raw.TracepointSysEnterReadv,
		TracepointSysEnterRecvfrom:     raw.TracepointSysEnterRecvfrom,
		TracepointSysEnterRecvmsg:      raw.TracepointSysEnterRecvmsg,
		TracepointSysEnterSendmsg:      raw.TracepointSysEnterSendmsg,
		TracepointSysEnterSendto:       raw.TracepointSysEnterSendto,
		TracepointSysEnterWrite:        raw.TracepointSysEnterWrite,
		TracepointSysEnterWritev:       raw.TracepointSysEnterWritev,
		closer:                         &raw,
	}, nil
}

func loadLegacyObjects(opts *ebpf.CollectionOptions) (*LoadedObjects, error) {
	var raw HttpTraceLegacyObjects

	if err := LoadHttpTraceLegacyObjects(&raw, opts); err != nil {
		return nil, err
	}
	return &LoadedObjects{
		Variant:                        "legacy-4.x",
		HookStrategy:                   HookStrategyLegacySock,
		Events:                         raw.Events,
		FilterMap:                      raw.FilterMap,
		KernelStatsMap:                 raw.KernelStatsMap,
		DebugSnapshotMap:               raw.DebugSnapshotMap,
		KprobeSockRecvmsg:              raw.KprobeSockRecvmsg,
		KprobeSockSendmsg:              raw.KprobeSockSendmsg,
		KprobeTcpClose:                 raw.KprobeTcpClose,
		KprobeTcpRecvmsg:               raw.KprobeTcpRecvmsg,
		KprobeTcpSendmsg:               raw.KprobeTcpSendmsg,
		KprobeTcpV4Connect:             raw.KprobeTcpV4Connect,
		KretprobeTcpV4Connect:          raw.KretprobeTcpV4Connect,
		KprobeTcpV6Connect:             raw.KprobeTcpV6Connect,
		KretprobeTcpV6Connect:          raw.KretprobeTcpV6Connect,
		KretprobeInetCskAccept:         raw.KretprobeInetCskAccept,
		KretprobeSockRecvmsg:           raw.KretprobeSockRecvmsg,
		KretprobeTcpRecvmsg:            raw.KretprobeTcpRecvmsg,
		TracepointSockInetSockSetState: raw.TracepointSockInetSockSetState,
		TracepointSysEnterRead:         raw.TracepointSysEnterRead,
		TracepointSysEnterReadv:        raw.TracepointSysEnterReadv,
		TracepointSysEnterRecvfrom:     raw.TracepointSysEnterRecvfrom,
		TracepointSysEnterRecvmsg:      raw.TracepointSysEnterRecvmsg,
		TracepointSysEnterSendmsg:      raw.TracepointSysEnterSendmsg,
		TracepointSysEnterSendto:       raw.TracepointSysEnterSendto,
		TracepointSysEnterWrite:        raw.TracepointSysEnterWrite,
		TracepointSysEnterWritev:       raw.TracepointSysEnterWritev,
		closer:                         &raw,
	}, nil
}

func loadLegacyUserReadObjects(opts *ebpf.CollectionOptions) (*LoadedObjects, error) {
	var raw HttpTraceLegacyUserReadObjects

	if err := LoadHttpTraceLegacyUserReadObjects(&raw, opts); err != nil {
		return nil, err
	}
	return &LoadedObjects{
		Variant:                        "legacy-4.x-userread",
		HookStrategy:                   HookStrategyLegacySock,
		Events:                         raw.Events,
		FilterMap:                      raw.FilterMap,
		KernelStatsMap:                 raw.KernelStatsMap,
		DebugSnapshotMap:               raw.DebugSnapshotMap,
		KprobeSockRecvmsg:              raw.KprobeSockRecvmsg,
		KprobeSockSendmsg:              raw.KprobeSockSendmsg,
		KprobeTcpClose:                 raw.KprobeTcpClose,
		KprobeTcpRecvmsg:               raw.KprobeTcpRecvmsg,
		KprobeTcpSendmsg:               raw.KprobeTcpSendmsg,
		KprobeTcpV4Connect:             raw.KprobeTcpV4Connect,
		KretprobeTcpV4Connect:          raw.KretprobeTcpV4Connect,
		KprobeTcpV6Connect:             raw.KprobeTcpV6Connect,
		KretprobeTcpV6Connect:          raw.KretprobeTcpV6Connect,
		KretprobeInetCskAccept:         raw.KretprobeInetCskAccept,
		KretprobeSockRecvmsg:           raw.KretprobeSockRecvmsg,
		KretprobeTcpRecvmsg:            raw.KretprobeTcpRecvmsg,
		TracepointSockInetSockSetState: raw.TracepointSockInetSockSetState,
		TracepointSysEnterRead:         raw.TracepointSysEnterRead,
		TracepointSysEnterReadv:        raw.TracepointSysEnterReadv,
		TracepointSysEnterRecvfrom:     raw.TracepointSysEnterRecvfrom,
		TracepointSysEnterRecvmsg:      raw.TracepointSysEnterRecvmsg,
		TracepointSysEnterSendmsg:      raw.TracepointSysEnterSendmsg,
		TracepointSysEnterSendto:       raw.TracepointSysEnterSendto,
		TracepointSysEnterWrite:        raw.TracepointSysEnterWrite,
		TracepointSysEnterWritev:       raw.TracepointSysEnterWritev,
		closer:                         &raw,
	}, nil
}

func loadLegacyTCPSendObjects(opts *ebpf.CollectionOptions) (*LoadedObjects, error) {
	var raw HttpTraceLegacyObjects

	if err := LoadHttpTraceLegacyObjects(&raw, opts); err != nil {
		return nil, err
	}
	return &LoadedObjects{
		Variant:                        "legacy-4.x-tcp-send",
		HookStrategy:                   HookStrategyLegacyTCPSend,
		Events:                         raw.Events,
		FilterMap:                      raw.FilterMap,
		KernelStatsMap:                 raw.KernelStatsMap,
		DebugSnapshotMap:               raw.DebugSnapshotMap,
		KprobeSockRecvmsg:              raw.KprobeSockRecvmsg,
		KprobeSockSendmsg:              raw.KprobeSockSendmsg,
		KprobeTcpClose:                 raw.KprobeTcpClose,
		KprobeTcpRecvmsg:               raw.KprobeTcpRecvmsg,
		KprobeTcpSendmsg:               raw.KprobeTcpSendmsg,
		KprobeTcpV4Connect:             raw.KprobeTcpV4Connect,
		KretprobeTcpV4Connect:          raw.KretprobeTcpV4Connect,
		KprobeTcpV6Connect:             raw.KprobeTcpV6Connect,
		KretprobeTcpV6Connect:          raw.KretprobeTcpV6Connect,
		KretprobeInetCskAccept:         raw.KretprobeInetCskAccept,
		KretprobeSockRecvmsg:           raw.KretprobeSockRecvmsg,
		KretprobeTcpRecvmsg:            raw.KretprobeTcpRecvmsg,
		TracepointSockInetSockSetState: raw.TracepointSockInetSockSetState,
		TracepointSysEnterRead:         raw.TracepointSysEnterRead,
		TracepointSysEnterReadv:        raw.TracepointSysEnterReadv,
		TracepointSysEnterRecvfrom:     raw.TracepointSysEnterRecvfrom,
		TracepointSysEnterRecvmsg:      raw.TracepointSysEnterRecvmsg,
		TracepointSysEnterSendmsg:      raw.TracepointSysEnterSendmsg,
		TracepointSysEnterSendto:       raw.TracepointSysEnterSendto,
		TracepointSysEnterWrite:        raw.TracepointSysEnterWrite,
		TracepointSysEnterWritev:       raw.TracepointSysEnterWritev,
		closer:                         &raw,
	}, nil
}

func loadLegacyTCPBothObjects(opts *ebpf.CollectionOptions) (*LoadedObjects, error) {
	var raw HttpTraceLegacyObjects

	if err := LoadHttpTraceLegacyObjects(&raw, opts); err != nil {
		return nil, err
	}
	return &LoadedObjects{
		Variant:                        "legacy-4.x-tcp-both",
		HookStrategy:                   HookStrategyLegacyTCPBoth,
		Events:                         raw.Events,
		FilterMap:                      raw.FilterMap,
		KernelStatsMap:                 raw.KernelStatsMap,
		DebugSnapshotMap:               raw.DebugSnapshotMap,
		KprobeSockRecvmsg:              raw.KprobeSockRecvmsg,
		KprobeSockSendmsg:              raw.KprobeSockSendmsg,
		KprobeTcpClose:                 raw.KprobeTcpClose,
		KprobeTcpRecvmsg:               raw.KprobeTcpRecvmsg,
		KprobeTcpSendmsg:               raw.KprobeTcpSendmsg,
		KprobeTcpV4Connect:             raw.KprobeTcpV4Connect,
		KretprobeTcpV4Connect:          raw.KretprobeTcpV4Connect,
		KprobeTcpV6Connect:             raw.KprobeTcpV6Connect,
		KretprobeTcpV6Connect:          raw.KretprobeTcpV6Connect,
		KretprobeInetCskAccept:         raw.KretprobeInetCskAccept,
		KretprobeSockRecvmsg:           raw.KretprobeSockRecvmsg,
		KretprobeTcpRecvmsg:            raw.KretprobeTcpRecvmsg,
		TracepointSockInetSockSetState: raw.TracepointSockInetSockSetState,
		TracepointSysEnterRead:         raw.TracepointSysEnterRead,
		TracepointSysEnterReadv:        raw.TracepointSysEnterReadv,
		TracepointSysEnterRecvfrom:     raw.TracepointSysEnterRecvfrom,
		TracepointSysEnterRecvmsg:      raw.TracepointSysEnterRecvmsg,
		TracepointSysEnterSendmsg:      raw.TracepointSysEnterSendmsg,
		TracepointSysEnterSendto:       raw.TracepointSysEnterSendto,
		TracepointSysEnterWrite:        raw.TracepointSysEnterWrite,
		TracepointSysEnterWritev:       raw.TracepointSysEnterWritev,
		closer:                         &raw,
	}, nil
}

func loadTCPOnlyObjects(opts *ebpf.CollectionOptions) (*LoadedObjects, error) {
	spec, err := LoadHttpTraceTCPOnly()
	if err != nil {
		return nil, err
	}
	return loadTCPOnlyCollectionSpec(spec, opts, "tcp-5.15+")
}

func loadTCPOnlyCompactObjects(opts *ebpf.CollectionOptions) (*LoadedObjects, error) {
	spec, err := LoadHttpTraceTCPOnlyCompact()
	if err != nil {
		return nil, err
	}
	return loadTCPOnlyCollectionSpec(spec, opts, "tcp-5.15-compact")
}

func loadTCPOnlyV6Objects(opts *ebpf.CollectionOptions) (*LoadedObjects, error) {
	spec, err := LoadHttpTraceTCPOnlyV6()
	if err != nil {
		return nil, err
	}
	return loadTCPOnlyCollectionSpec(spec, opts, "tcp-6.x")
}

func loadTCPOnlyV66Objects(opts *ebpf.CollectionOptions) (*LoadedObjects, error) {
	spec, err := LoadHttpTraceTCPOnlyV66()
	if err != nil {
		return nil, err
	}
	return loadTCPOnlyCollectionSpec(spec, opts, "tcp-6.6")
}

func loadTCPOnlyV6CompactObjects(opts *ebpf.CollectionOptions) (*LoadedObjects, error) {
	spec, err := LoadHttpTraceTCPOnlyV6Compact()
	if err != nil {
		return nil, err
	}
	return loadTCPOnlyCollectionSpec(spec, opts, "tcp-6.x-compact")
}

func loadTCPOnlyV66CompactObjects(opts *ebpf.CollectionOptions) (*LoadedObjects, error) {
	spec, err := LoadHttpTraceTCPOnlyV66Compact()
	if err != nil {
		return nil, err
	}
	return loadTCPOnlyCollectionSpec(spec, opts, "tcp-6.6-compact")
}

func loadTCPOnlyCollectionSpec(spec *ebpf.CollectionSpec, opts *ebpf.CollectionOptions, variant string) (*LoadedObjects, error) {
	for _, name := range []string{
		"kprobe_sock_recvmsg",
		"kprobe_sock_sendmsg",
		"kprobe_tcp_v4_connect",
		"kprobe_tcp_v6_connect",
		"kretprobe_inet_csk_accept",
		"kretprobe_sock_recvmsg",
		"kretprobe_tcp_v4_connect",
		"kretprobe_tcp_v6_connect",
	} {
		delete(spec.Programs, name)
	}
	delete(spec.Maps, "connect_args_map")

	collection, err := ebpf.NewCollectionWithOptions(spec, derefCollectionOptions(opts))
	if err != nil {
		return nil, err
	}

	objects, err := loadedObjectsFromCollection(collection, variant, HookStrategyTCPOnly)
	if err != nil {
		collection.Close()
		return nil, err
	}
	return objects, nil
}

func shouldFallbackToLegacy(err error) bool {
	if err == nil {
		return false
	}

	msg := err.Error()
	return strings.Contains(msg, "back-edge") ||
		strings.Contains(msg, "program is too large") ||
		strings.Contains(msg, "argument list too long") ||
		strings.Contains(msg, "jump out of range") ||
		strings.Contains(msg, "pointer prohibited") ||
		strings.Contains(msg, "bitwise operator |= on pointer prohibited") ||
		strings.Contains(msg, "bitwise operator") ||
		strings.Contains(msg, "unbounded memory access") ||
		strings.Contains(msg, "min value is negative")
}

func shouldTryNextVariant(current string, err error) bool {
	if err == nil {
		return false
	}
	if current == "legacy-4.x" {
		return false
	}
	return shouldFallbackToLegacy(err)
}

func chooseVariantPlans(version kernelVersion) []variantPlan {
	if forced := strings.TrimSpace(os.Getenv(objectVariantEnv)); forced != "" {
		plan, ok := variantPlanByName(forced)
		if !ok {
			log.Printf("忽略未知的 %s=%q，继续自动选择 variant", objectVariantEnv, forced)
		} else {
			return []variantPlan{plan}
		}
	}

	if profile, ok := matchKernelProfile(version); ok {
		log.Printf("匹配到内核配置：profile=%s release=%s", profile.Name, version.Release)
		return plansForVariantNames(profile.Variants)
	}

	if version.Major == 4 {
		return []variantPlan{
			{Name: "legacy-4.x", HookStrategy: HookStrategyLegacySock, Load: loadLegacyObjects},
		}
	}

	if version.Major >= 6 {
		if version.Minor == 6 {
			return []variantPlan{
				{Name: "tcp-6.6-compact", HookStrategy: HookStrategyTCPOnly, Load: loadTCPOnlyV66CompactObjects},
				{Name: "tcp-6.6", HookStrategy: HookStrategyTCPOnly, Load: loadTCPOnlyV66Objects},
				{Name: "tcp-6.x-compact", HookStrategy: HookStrategyTCPOnly, Load: loadTCPOnlyV6CompactObjects},
				{Name: "tcp-6.x", HookStrategy: HookStrategyTCPOnly, Load: loadTCPOnlyV6Objects},
				{Name: "tcp-5.15+", HookStrategy: HookStrategyTCPOnly, Load: loadTCPOnlyObjects},
			}
		}
		return []variantPlan{
			{Name: "tcp-6.x-compact", HookStrategy: HookStrategyTCPOnly, Load: loadTCPOnlyV6CompactObjects},
			{Name: "tcp-6.x", HookStrategy: HookStrategyTCPOnly, Load: loadTCPOnlyV6Objects},
			{Name: "tcp-5.15+", HookStrategy: HookStrategyTCPOnly, Load: loadTCPOnlyObjects},
		}
	}

	if version.Major == 5 {
		return []variantPlan{
			{Name: "tcp-5.15-compact", HookStrategy: HookStrategyTCPOnly, Load: loadTCPOnlyCompactObjects},
			{Name: "tcp-5.15+", HookStrategy: HookStrategyTCPOnly, Load: loadTCPOnlyObjects},
		}
	}

	return []variantPlan{
		{Name: "tcp-5.15+", HookStrategy: HookStrategyTCPOnly, Load: loadTCPOnlyObjects},
		{Name: "legacy-4.x", HookStrategy: HookStrategyLegacySock, Load: loadLegacyObjects},
	}
}

func matchKernelProfile(version kernelVersion) (kernelProfile, bool) {
	for _, profile := range knownKernelProfiles {
		if profile.Match != nil && profile.Match(version) {
			return profile, true
		}
	}
	return kernelProfile{}, false
}

func plansForVariantNames(names []string) []variantPlan {
	plans := make([]variantPlan, 0, len(names))
	for _, name := range names {
		plan, ok := variantPlanByName(name)
		if !ok {
			log.Printf("忽略内核配置计划中的未知 variant：%q", name)
			continue
		}
		plans = append(plans, plan)
	}
	return plans
}

func variantPlanByName(name string) (variantPlan, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "legacy", "legacy-4.x", "4.x":
		return variantPlan{Name: "legacy-4.x", HookStrategy: HookStrategyLegacySock, Load: loadLegacyObjects}, true
	case "legacy-4.x-userread", "legacy-userread", "4.x-userread":
		return variantPlan{Name: "legacy-4.x-userread", HookStrategy: HookStrategyLegacySock, Load: loadLegacyUserReadObjects}, true
	case "legacy-4.x-tcp-send", "legacy-tcp-send", "4.x-tcp-send", "legacy-hybrid":
		return variantPlan{Name: "legacy-4.x-tcp-send", HookStrategy: HookStrategyLegacyTCPSend, Load: loadLegacyTCPSendObjects}, true
	case "legacy-4.x-tcp-both", "legacy-tcp-both", "4.x-tcp-both", "legacy-tcp":
		return variantPlan{Name: "legacy-4.x-tcp-both", HookStrategy: HookStrategyLegacyTCPBoth, Load: loadLegacyTCPBothObjects}, true
	case "tcp-5", "tcp-5.15-compact", "compact", "5":
		return variantPlan{Name: "tcp-5.15-compact", HookStrategy: HookStrategyTCPOnly, Load: loadTCPOnlyCompactObjects}, true
	case "tcp-6-compact", "tcp-6.x-compact", "v6compact":
		return variantPlan{Name: "tcp-6.x-compact", HookStrategy: HookStrategyTCPOnly, Load: loadTCPOnlyV6CompactObjects}, true
	case "tcp-6.6-compact", "tcp-6-6-compact", "v66compact":
		return variantPlan{Name: "tcp-6.6-compact", HookStrategy: HookStrategyTCPOnly, Load: loadTCPOnlyV66CompactObjects}, true
	case "tcp-6", "tcp-6.x", "v6", "6":
		return variantPlan{Name: "tcp-6.x", HookStrategy: HookStrategyTCPOnly, Load: loadTCPOnlyV6Objects}, true
	case "tcp-6.6", "tcp-6-6", "v66":
		return variantPlan{Name: "tcp-6.6", HookStrategy: HookStrategyTCPOnly, Load: loadTCPOnlyV66Objects}, true
	case "tcp", "tcp-only", "tcp-5.15+", "5.x", "6.x":
		return variantPlan{Name: "tcp-5.15+", HookStrategy: HookStrategyTCPOnly, Load: loadTCPOnlyObjects}, true
	case "modern", "modern-mixed":
		return variantPlan{Name: "modern-mixed", HookStrategy: HookStrategyTCPOnly, Load: loadModernObjects}, true
	default:
		return variantPlan{}, false
	}
}

func preferLegacyTCPSend(release string) bool {
	lower := strings.ToLower(strings.TrimSpace(release))
	if lower == "" {
		return false
	}
	return strings.HasPrefix(lower, "4.19.90-2403.") && strings.Contains(lower, "uel20")
}

func preferLegacyUserRead(release string) bool {
	lower := strings.ToLower(strings.TrimSpace(release))
	if lower == "" {
		return false
	}
	return strings.HasPrefix(lower, "4.19.90-52.42.") && strings.Contains(lower, "v2207") && strings.Contains(lower, "ky10")
}

func preferLegacyTCPBoth(release string) bool {
	lower := strings.ToLower(strings.TrimSpace(release))
	if lower == "" {
		return false
	}
	return strings.HasPrefix(lower, "4.19.90-24.4.") && strings.Contains(lower, "v2101") && strings.Contains(lower, "ky10")
}

func detectKernelVersion() kernelVersion {
	var uts syscall.Utsname

	if err := syscall.Uname(&uts); err != nil {
		return kernelVersion{}
	}

	release := strings.TrimSpace(cStringInt8(uts.Release[:]))
	major, minor := parseKernelRelease(release)
	return kernelVersion{
		Release: release,
		Major:   major,
		Minor:   minor,
	}
}

func parseKernelRelease(release string) (int, int) {
	parts := strings.Split(release, ".")
	if len(parts) < 2 {
		return 0, 0
	}

	major, err := strconv.Atoi(readLeadingDigits(parts[0]))
	if err != nil {
		return 0, 0
	}
	minor, err := strconv.Atoi(readLeadingDigits(parts[1]))
	if err != nil {
		return major, 0
	}
	return major, minor
}

func readLeadingDigits(part string) string {
	var b strings.Builder
	for _, r := range part {
		if r < '0' || r > '9' {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
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

func withVerifierLogs(opts *ebpf.CollectionOptions) *ebpf.CollectionOptions {
	const verifierLogSize = 32 << 20
	const verifierLogEnv = "POWER_EBPF_VERIFIER_LOG"

	enabled := false
	if raw := strings.TrimSpace(os.Getenv(verifierLogEnv)); raw != "" && raw != "0" && !strings.EqualFold(raw, "false") {
		enabled = true
	}

	if !enabled {
		if opts == nil {
			return nil
		}
		return opts
	}

	log.Printf("已通过 %s 开启 verifier 调试日志", verifierLogEnv)

	if opts == nil {
		return &ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogLevel:     ebpf.LogLevelInstruction,
				LogSizeStart: verifierLogSize,
			},
		}
	}

	cloned := *opts
	if cloned.Programs.LogDisabled {
		return &cloned
	}
	if cloned.Programs.LogLevel == 0 {
		cloned.Programs.LogLevel = ebpf.LogLevelInstruction
	}
	if cloned.Programs.LogSizeStart < verifierLogSize {
		cloned.Programs.LogSizeStart = verifierLogSize
	}
	return &cloned
}

func derefCollectionOptions(opts *ebpf.CollectionOptions) ebpf.CollectionOptions {
	if opts == nil {
		return ebpf.CollectionOptions{}
	}
	return *opts
}

func loadedObjectsFromCollection(collection *ebpf.Collection, variant string, hookStrategy HookStrategy) (*LoadedObjects, error) {
	if collection == nil {
		return nil, fmt.Errorf("nil ebpf collection")
	}

	events, err := requiredMap(collection, "events")
	if err != nil {
		return nil, err
	}
	filterMap, err := requiredMap(collection, "filter_map")
	if err != nil {
		return nil, err
	}
	kernelStatsMap, err := requiredMap(collection, "kernel_stats_map")
	if err != nil {
		return nil, err
	}
	debugSnapshotMap, err := requiredMap(collection, "debug_snapshot_map")
	if err != nil {
		return nil, err
	}
	kprobeTcpRecvmsg, err := requiredProgram(collection, "kprobe_tcp_recvmsg")
	if err != nil {
		return nil, err
	}
	kretprobeTcpRecvmsg, err := requiredProgram(collection, "kretprobe_tcp_recvmsg")
	if err != nil {
		return nil, err
	}
	kprobeTcpSendmsg, err := requiredProgram(collection, "kprobe_tcp_sendmsg")
	if err != nil {
		return nil, err
	}

	return &LoadedObjects{
		Variant:                        variant,
		HookStrategy:                   hookStrategy,
		Events:                         events,
		FilterMap:                      filterMap,
		KernelStatsMap:                 kernelStatsMap,
		DebugSnapshotMap:               debugSnapshotMap,
		KprobeSockRecvmsg:              collection.Programs["kprobe_sock_recvmsg"],
		KprobeSockSendmsg:              collection.Programs["kprobe_sock_sendmsg"],
		KprobeTcpClose:                 collection.Programs["kprobe_tcp_close"],
		KprobeTcpRecvmsg:               kprobeTcpRecvmsg,
		KprobeTcpSendmsg:               kprobeTcpSendmsg,
		KprobeTcpV4Connect:             collection.Programs["kprobe_tcp_v4_connect"],
		KretprobeTcpV4Connect:          collection.Programs["kretprobe_tcp_v4_connect"],
		KprobeTcpV6Connect:             collection.Programs["kprobe_tcp_v6_connect"],
		KretprobeTcpV6Connect:          collection.Programs["kretprobe_tcp_v6_connect"],
		KretprobeInetCskAccept:         collection.Programs["kretprobe_inet_csk_accept"],
		KretprobeSockRecvmsg:           collection.Programs["kretprobe_sock_recvmsg"],
		KretprobeTcpRecvmsg:            kretprobeTcpRecvmsg,
		TracepointSockInetSockSetState: collection.Programs["tracepoint_sock_inet_sock_set_state"],
		TracepointSysEnterRead:         collection.Programs["tracepoint_sys_enter_read"],
		TracepointSysEnterReadv:        collection.Programs["tracepoint_sys_enter_readv"],
		TracepointSysEnterRecvfrom:     collection.Programs["tracepoint_sys_enter_recvfrom"],
		TracepointSysEnterRecvmsg:      collection.Programs["tracepoint_sys_enter_recvmsg"],
		TracepointSysEnterSendmsg:      collection.Programs["tracepoint_sys_enter_sendmsg"],
		TracepointSysEnterSendto:       collection.Programs["tracepoint_sys_enter_sendto"],
		TracepointSysEnterWrite:        collection.Programs["tracepoint_sys_enter_write"],
		TracepointSysEnterWritev:       collection.Programs["tracepoint_sys_enter_writev"],
		closer:                         collectionCloser{collection: collection},
	}, nil
}

func requiredProgram(collection *ebpf.Collection, name string) (*ebpf.Program, error) {
	prog := collection.Programs[name]
	if prog == nil {
		return nil, fmt.Errorf("required program %q missing from collection", name)
	}
	return prog, nil
}

func requiredMap(collection *ebpf.Collection, name string) (*ebpf.Map, error) {
	m := collection.Maps[name]
	if m == nil {
		return nil, fmt.Errorf("required map %q missing from collection", name)
	}
	return m, nil
}
