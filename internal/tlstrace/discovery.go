package tlstrace

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// DiscoveryOptions 控制 TLS uprobe 的 libssl 路径解析方式。
//
// uprobe 必须挂载到目标进程实际映射的共享对象 inode。即使在当前二进制中附带一份
// 私有 libssl 副本也没有帮助，因为 nginx 不会执行该私有 inode 中的代码。
//
// 尽力解析策略如下：
// 1. 如果提供 --tls-lib-path，则优先使用显式路径；
// 2. 检查运行中的目标进程，复用其已映射的 libssl 路径；
// 3. 最后回退到常见系统库目录。
type DiscoveryOptions struct {
	ExplicitPaths []string
	ProcessComm   string
	ProcRoot      string
	SearchDirs    []string
}

// ResolveLibraryPaths 返回适合挂载 uprobe 且已去重的 libssl 路径。
/*
1.首选 --tls-lib-path，
2.不填时自动从 nginx 的 /proc/<pid>/maps 里找它真正加载的 libssl.so，
3.再回退到常见系统目录。
*/
func ResolveLibraryPaths(opts DiscoveryOptions) ([]string, error) {
	if len(opts.ExplicitPaths) > 0 {
		paths := normalizeExistingPaths(opts.ExplicitPaths)
		if len(paths) == 0 {
			return nil, fmt.Errorf("none of the explicit tls library paths exist")
		}
		return paths, nil
	}

	procRoot := opts.ProcRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	processComm := ResolveTargetComm(opts.ProcessComm)

	candidates := make([]string, 0, 8)
	candidates = append(candidates, discoverMappedLibraries(procRoot, processComm)...)
	candidates = append(candidates, discoverFallbackLibraries(defaultSearchDirs(opts.SearchDirs))...)

	paths := normalizeExistingPaths(candidates)
	if len(paths) == 0 {
		return nil, fmt.Errorf("no libssl path found for comm=%q", processComm)
	}
	return paths, nil
}

// SplitCSVPaths 解析 --tls-lib-path 等以逗号分隔的命令行参数值。
func SplitCSVPaths(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

// ResolveTargetComm 有意保持 TLS uprobe 的匹配策略保守。首版只支持单个精确 comm 匹配，
// 默认值为 nginx。
func ResolveTargetComm(raw string) string {
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			return part
		}
	}
	return "nginx"
}

func discoverMappedLibraries(procRoot, targetComm string) []string {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}

	candidates := make([]string, 0, 4)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}

		commPath := filepath.Join(procRoot, entry.Name(), "comm")
		commBytes, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(commBytes)) != targetComm {
			continue
		}

		candidates = append(candidates, discoverMappedLibrariesForPID(filepath.Join(procRoot, entry.Name(), "maps"))...)
	}
	return candidates
}

func discoverMappedLibrariesForPID(mapsPath string) []string {
	file, err := os.Open(mapsPath)
	if err != nil {
		return nil
	}
	defer file.Close()

	var candidates []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		path := fields[len(fields)-1]
		if !strings.HasPrefix(path, "/") {
			continue
		}
		if !isSupportedTLSLibrary(path) {
			continue
		}
		candidates = append(candidates, path)
	}
	return candidates
}

func discoverFallbackLibraries(searchDirs []string) []string {
	candidates := make([]string, 0, 8)
	for _, dir := range searchDirs {
		matches, err := filepath.Glob(filepath.Join(dir, "libssl.so*"))
		if err != nil {
			continue
		}
		for _, match := range matches {
			if isSupportedTLSLibrary(match) {
				candidates = append(candidates, match)
			}
		}
	}
	return candidates
}

func defaultSearchDirs(custom []string) []string {
	if len(custom) > 0 {
		return custom
	}

	dirs := []string{
		"/lib",
		"/lib64",
		"/usr/lib",
		"/usr/lib64",
	}
	switch runtime.GOARCH {
	case "amd64":
		dirs = append(dirs, "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu")
	case "arm64":
		dirs = append(dirs, "/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu")
	}
	return dirs
}

func normalizeExistingPaths(paths []string) []string {
	type keyedPath struct {
		key  string
		path string
	}

	dedup := make(map[string]keyedPath, len(paths))
	for _, path := range paths {
		if path == "" {
			continue
		}
		path = filepath.Clean(path)
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		if !isSupportedTLSLibrary(path) {
			continue
		}

		resolved := path
		if realPath, err := filepath.EvalSymlinks(path); err == nil && realPath != "" {
			resolved = realPath
		}
		dedup[resolved] = keyedPath{
			key:  resolved,
			path: resolved,
		}
	}

	keys := make([]string, 0, len(dedup))
	for key := range dedup {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, dedup[key].path)
	}
	return out
}

func isSupportedTLSLibrary(path string) bool {
	base := filepath.Base(path)
	if strings.HasPrefix(base, "libssl.so") {
		return true
	}
	// Debian / Ubuntu 可能将 libssl3.so 作为实际的 ELF SONAME。
	return base == "libssl3.so"
}
