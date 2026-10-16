package identity

import (
	"os"
	"testing"
	"time"
)

func TestExtractFlatpakID(t *testing.T) {
	tests := []struct {
		cgroup   string
		expected string
	}{
		{
			cgroup:   "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-org.mozilla.firefox-12345.scope",
			expected: "org.mozilla.firefox",
		},
		{
			cgroup:   "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-com.spotify.Client.scope",
			expected: "com.spotify.Client",
		},
		{
			cgroup:   "0::/system.slice/NetworkManager.service",
			expected: "",
		},
	}

	for _, tc := range tests {
		actual := extractFlatpakID(tc.cgroup)
		if actual != tc.expected {
			t.Errorf("extractFlatpakID(%q) = %q, expected %q", tc.cgroup, actual, tc.expected)
		}
	}
}

func TestExtractSystemdService(t *testing.T) {
	tests := []struct {
		cgroup   string
		expected string
	}{
		{
			cgroup:   "0::/system.slice/NetworkManager.service",
			expected: "NetworkManager.service",
		},
		{
			cgroup:   "0::/system.slice/systemd-resolved.service/resolved",
			expected: "systemd-resolved.service",
		},
		{
			cgroup:   "0::/user.slice/user-1000.slice/session-2.scope",
			expected: "",
		},
	}

	for _, tc := range tests {
		actual := extractSystemdService(tc.cgroup)
		if actual != tc.expected {
			t.Errorf("extractSystemdService(%q) = %q, expected %q", tc.cgroup, actual, tc.expected)
		}
	}
}

func TestPIDZeroUnattributed(t *testing.T) {
	resolver := NewResolver()
	ident := resolver.ResolvePID(0)

	if ident.AppKey != "unknown:unattributed" {
		t.Errorf("expected app_key unknown:unattributed, got %q", ident.AppKey)
	}
	if ident.Category != "unknown" {
		t.Errorf("expected category unknown, got %q", ident.Category)
	}
}

func TestCurrentProcessResolution(t *testing.T) {
	resolver := NewResolver()
	myPID := uint32(os.Getpid())

	ident := resolver.ResolvePID(myPID)
	if ident == nil {
		t.Fatal("expected non-nil identity for current process")
	}
	if ident.AppKey == "" || ident.DisplayName == "" {
		t.Errorf("expected populated appKey and displayName, got key=%q name=%q", ident.AppKey, ident.DisplayName)
	}
}

func TestShortLivedProcessFallback(t *testing.T) {
	resolver := NewResolver()
	// Set fallback simulating eBPF LRU metadata
	resolver.SetBPFLookup(func(pid uint32) (string, uint64, bool) {
		if pid == 999999 {
			return "curl", 1234, true
		}
		return "", 0, false
	})

	ident := resolver.ResolvePID(999999)
	if ident == nil {
		t.Fatal("expected identity from BPF fallback")
	}
	if ident.DisplayName != "curl" {
		t.Errorf("expected displayName 'curl', got %q", ident.DisplayName)
	}
	if ident.AppKey != "exec:short_lived:curl" {
		t.Errorf("expected appKey 'exec:short_lived:curl', got %q", ident.AppKey)
	}
}

func TestExitedProcessRetainsKnownIdentity(t *testing.T) {
	r := NewResolver()
	pid := uint32(4294967294) // Cannot be a live Linux PID.
	r.procCache[pid] = procSnapshot{PID: pid, Comm: "sleep", ExePath: "/usr/bin/sleep", CachedAt: time.Now()}
	r.SetBPFLookup(func(uint32) (string, uint64, bool) { return "sleep", 1, true })
	ident := r.ResolvePID(pid)
	if ident.AppKey != "exec:/usr/bin/sleep" {
		t.Fatalf("cached identity replaced: %+v", ident)
	}
}

func TestFallbackGroupingRequiresUniquePath(t *testing.T) {
	r := NewResolver()
	r.SeedIdentities([]*AppIdentity{{AppKey: "exec:/usr/bin/gh"}})
	r.SetBPFLookup(func(uint32) (string, uint64, bool) { return "gh", 1, true })
	got := r.ResolvePID(4294967294)
	if got.AppKey != "exec:/usr/bin/gh" || got.Category != "cli_tool" {
		t.Fatalf("fallback=%+v", got)
	}
	r.SeedIdentities([]*AppIdentity{{AppKey: "exec:/opt/other/gh"}})
	got = r.ResolvePID(4294967293)
	if got.AppKey != "exec:short_lived:gh" {
		t.Fatalf("ambiguous fallback guessed a path: %+v", got)
	}
	candidates := []*AppIdentity{{AppKey: "exec:/usr/bin/gh"}, {AppKey: "exec:/opt/other/gh"}}
	if got := MatchFallback("exec:gh", candidates); got != "" {
		t.Fatalf("ambiguous alias=%q", got)
	}
	if got := MatchFallback("exec:/usr/bin/gh", candidates); got != "" {
		t.Fatal("full executable paths must never be aliased")
	}
}

func TestCategoriesUseEvidence(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"gh", "cli_tool"}, {"node-MainThread", "cli_tool"}, {"language_server", "cli_tool"},
		{"discord", "desktop_app"}, {"friend", "unknown"}, {"sync", "unknown"}, {"Brave", "web_browser"},
	} {
		if got := classifyAppCategory(tc.name, ""); got != tc.want {
			t.Errorf("%s=%s want %s", tc.name, got, tc.want)
		}
	}
	if got := CategoryForIdentity(&AppIdentity{AppKey: "exec:/usr/bin/node", CgroupPath: "0::/system.slice/example.service"}); got != "system_service" {
		t.Fatalf("service evidence ignored: %s", got)
	}
}

func TestPIDReuseDoesNotInheritExecutable(t *testing.T) {
	r := NewResolver()
	pid := uint32(456)
	r.readProcess = func(uint32) (*procSnapshot, error) {
		return &procSnapshot{PID: pid, StartTime: 1, Comm: "tool", ExePath: "/one/tool"}, nil
	}
	if got := r.ResolvePID(pid); got.AppKey != "exec:/one/tool" {
		t.Fatal(got)
	}
	// Same process, transient readlink failure: retain its known executable.
	r.readProcess = func(uint32) (*procSnapshot, error) { return &procSnapshot{PID: pid, StartTime: 1, Comm: "tool"}, nil }
	if got := r.ResolvePID(pid); got.AppKey != "exec:/one/tool" {
		t.Fatal(got)
	}
	// Different process generation, same comm: the old path is not evidence.
	r.readProcess = func(uint32) (*procSnapshot, error) { return &procSnapshot{PID: pid, StartTime: 2, Comm: "tool"}, nil }
	if got := r.ResolvePID(pid); got.AppKey == "exec:/one/tool" {
		t.Fatalf("reused PID inherited path: %+v", got)
	}
}
