package bpfgen

import "testing"

func TestParseKernelRelease(t *testing.T) {
	t.Parallel()

	tests := []struct {
		release string
		major   int
		minor   int
	}{
		{release: "4.19.0-23-amd64", major: 4, minor: 19},
		{release: "5.15.0-173-generic", major: 5, minor: 15},
		{release: "6.8.0-52-generic", major: 6, minor: 8},
		{release: "6.12-rc1", major: 6, minor: 12},
		{release: "invalid", major: 0, minor: 0},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.release, func(t *testing.T) {
			t.Parallel()

			major, minor := parseKernelRelease(tc.release)
			if major != tc.major || minor != tc.minor {
				t.Fatalf("parseKernelRelease(%q) = (%d, %d), want (%d, %d)", tc.release, major, minor, tc.major, tc.minor)
			}
		})
	}
}

func TestChooseVariantPlans(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		version   kernelVersion
		wantNames []string
	}{
		{
			name:      "legacy-4x",
			version:   kernelVersion{Release: "4.19.0", Major: 4, Minor: 19},
			wantNames: []string{"legacy-4.x"},
		},
		{
			name:      "tcp-first-5x",
			version:   kernelVersion{Release: "5.15.0", Major: 5, Minor: 15},
			wantNames: []string{"tcp-5.15-compact", "tcp-5.15+"},
		},
		{
			name:      "tcp-first-6x",
			version:   kernelVersion{Release: "6.8.0", Major: 6, Minor: 8},
			wantNames: []string{"tcp-6.x-compact", "tcp-6.x", "tcp-5.15+"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			plans := chooseVariantPlans(tc.version)
			if len(plans) != len(tc.wantNames) {
				t.Fatalf("len(plans) = %d, want %d", len(plans), len(tc.wantNames))
			}
			for i := range tc.wantNames {
				if plans[i].Name != tc.wantNames[i] {
					t.Fatalf("plans[%d].Name = %q, want %q", i, plans[i].Name, tc.wantNames[i])
				}
			}
		})
	}
}

func TestChooseVariantPlansHonorsOverride(t *testing.T) {
	t.Setenv(objectVariantEnv, "legacy")

	plans := chooseVariantPlans(kernelVersion{Release: "6.8.0", Major: 6, Minor: 8})
	if len(plans) != 1 {
		t.Fatalf("len(plans) = %d, want 1", len(plans))
	}
	if plans[0].Name != "legacy-4.x" {
		t.Fatalf("plans[0].Name = %q, want legacy-4.x", plans[0].Name)
	}
}

func TestVariantPlanByName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		want string
		ok   bool
	}{
		{name: "legacy", want: "legacy-4.x", ok: true},
		{name: "tcp-5.15-compact", want: "tcp-5.15-compact", ok: true},
		{name: "tcp-6.x-compact", want: "tcp-6.x-compact", ok: true},
		{name: "tcp-6.x", want: "tcp-6.x", ok: true},
		{name: "tcp-only", want: "tcp-5.15+", ok: true},
		{name: "modern", want: "modern-mixed", ok: true},
		{name: "unknown", ok: false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			plan, ok := variantPlanByName(tc.name)
			if ok != tc.ok {
				t.Fatalf("variantPlanByName(%q) ok = %t, want %t", tc.name, ok, tc.ok)
			}
			if ok && plan.Name != tc.want {
				t.Fatalf("variantPlanByName(%q) name = %q, want %q", tc.name, plan.Name, tc.want)
			}
		})
	}
}

func TestChooseVariantPlansIgnoresUnknownOverride(t *testing.T) {
	t.Setenv(objectVariantEnv, "does-not-exist")

	plans := chooseVariantPlans(kernelVersion{Release: "5.15.0", Major: 5, Minor: 15})
	if len(plans) == 0 {
		t.Fatal("expected fallback auto plan selection")
	}
	if plans[0].Name != "tcp-5.15-compact" {
		t.Fatalf("plans[0].Name = %q, want tcp-5.15-compact", plans[0].Name)
	}
}
