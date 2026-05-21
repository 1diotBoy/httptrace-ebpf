package tlstrace

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSplitCSVPaths(t *testing.T) {
	got := SplitCSVPaths(" /a/libssl.so.3, ,/b/libssl.so ")
	want := []string{"/a/libssl.so.3", "/b/libssl.so"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SplitCSVPaths mismatch: got=%v want=%v", got, want)
	}
}

func TestResolveTargetComm(t *testing.T) {
	if got := ResolveTargetComm(""); got != "nginx" {
		t.Fatalf("ResolveTargetComm empty = %q, want nginx", got)
	}
	if got := ResolveTargetComm(" nginx , php-fpm "); got != "nginx" {
		t.Fatalf("ResolveTargetComm csv = %q, want nginx", got)
	}
}

func TestResolveLibraryPathsUsesExplicitOverride(t *testing.T) {
	root := t.TempDir()
	lib := filepath.Join(root, "libssl.so.3")
	if err := os.WriteFile(lib, []byte("elf"), 0o644); err != nil {
		t.Fatalf("write explicit lib: %v", err)
	}

	got, err := ResolveLibraryPaths(DiscoveryOptions{
		ExplicitPaths: []string{lib},
	})
	if err != nil {
		t.Fatalf("ResolveLibraryPaths explicit error: %v", err)
	}
	want := []string{lib}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveLibraryPaths explicit mismatch: got=%v want=%v", got, want)
	}
}

func TestResolveLibraryPathsDiscoversMappedNginxLibrary(t *testing.T) {
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	pidDir := filepath.Join(procRoot, "123")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatalf("mkdir pid dir: %v", err)
	}

	libDir := filepath.Join(root, "lib")
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatalf("mkdir lib dir: %v", err)
	}
	lib := filepath.Join(libDir, "libssl.so.3")
	if err := os.WriteFile(lib, []byte("elf"), 0o644); err != nil {
		t.Fatalf("write lib: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte("nginx\n"), 0o644); err != nil {
		t.Fatalf("write comm: %v", err)
	}
	mapsBody := "7fa0-7fb0 r-xp 00000000 08:02 123 /tmp/other\n" +
		"7fb0-7fc0 r-xp 00000000 08:02 124 " + lib + "\n"
	if err := os.WriteFile(filepath.Join(pidDir, "maps"), []byte(mapsBody), 0o644); err != nil {
		t.Fatalf("write maps: %v", err)
	}

	got, err := ResolveLibraryPaths(DiscoveryOptions{
		ProcessComm: "nginx",
		ProcRoot:    procRoot,
		SearchDirs:  []string{filepath.Join(root, "missing")},
	})
	if err != nil {
		t.Fatalf("ResolveLibraryPaths mapped error: %v", err)
	}
	want := []string{lib}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveLibraryPaths mapped mismatch: got=%v want=%v", got, want)
	}
}

func TestResolveLibraryPathsFallsBackToSearchDirs(t *testing.T) {
	root := t.TempDir()
	libDir := filepath.Join(root, "lib")
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatalf("mkdir lib dir: %v", err)
	}
	lib := filepath.Join(libDir, "libssl.so")
	if err := os.WriteFile(lib, []byte("elf"), 0o644); err != nil {
		t.Fatalf("write lib: %v", err)
	}

	got, err := ResolveLibraryPaths(DiscoveryOptions{
		ProcessComm: "nginx",
		ProcRoot:    filepath.Join(root, "empty-proc"),
		SearchDirs:  []string{libDir},
	})
	if err != nil {
		t.Fatalf("ResolveLibraryPaths fallback error: %v", err)
	}
	want := []string{lib}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveLibraryPaths fallback mismatch: got=%v want=%v", got, want)
	}
}
