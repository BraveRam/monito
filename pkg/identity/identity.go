package identity

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AppIdentity represents a stable application identity
type AppIdentity struct {
	AppKey         string    `json:"app_key"`
	DisplayName    string    `json:"display_name"`
	Category       string    `json:"category"`
	IconOrType     string    `json:"icon_or_type"`
	ExecutablePath string    `json:"executable_path"`
	CgroupPath     string    `json:"cgroup_path"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
}

type procSnapshot struct {
	PID       uint32
	PPID      uint32
	StartTime uint64
	Comm      string
	ExePath   string
	Cgroup    string
	CachedAt  time.Time
}

// Resolver resolves temporary PIDs and system metadata into stable AppIdentities
type Resolver struct {
	mu           sync.RWMutex
	procCache    map[uint32]procSnapshot
	appCache     map[string]*AppIdentity
	desktopNames map[string]string // binary basename -> human name
	bpfLookup    func(pid uint32) (comm string, cgroupId uint64, ok bool)
}

// NewResolver creates and initializes an identity resolver
func NewResolver() *Resolver {
	r := &Resolver{
		procCache:    make(map[uint32]procSnapshot),
		appCache:     make(map[string]*AppIdentity),
		desktopNames: make(map[string]string),
	}
	r.loadDesktopMetadata()
	return r
}

// SetBPFLookup registers a fallback lookup for short-lived processes from eBPF
func (r *Resolver) SetBPFLookup(lookup func(pid uint32) (comm string, cgroupId uint64, ok bool)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bpfLookup = lookup
}

// loadDesktopMetadata indexes desktop applications from standard XDG paths
func (r *Resolver) loadDesktopMetadata() {
	dirs := []string{
		"/usr/share/applications",
		"/usr/local/share/applications",
		filepath.Join(os.Getenv("HOME"), ".local/share/applications"),
		"/var/lib/flatpak/exports/share/applications",
	}

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".desktop") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			r.parseDesktopFile(path)
		}
	}
}

func (r *Resolver) parseDesktopFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	var name, exec string
	scanner := bufio.NewScanner(file)
	inMainSection := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[Desktop Entry]") {
			inMainSection = true
			continue
		} else if strings.HasPrefix(line, "[") {
			inMainSection = false
			continue
		}

		if !inMainSection {
			continue
		}

		if strings.HasPrefix(line, "Name=") && name == "" {
			name = strings.TrimPrefix(line, "Name=")
		} else if strings.HasPrefix(line, "Exec=") && exec == "" {
			parts := strings.Fields(strings.TrimPrefix(line, "Exec="))
			if len(parts) > 0 {
				exec = filepath.Base(parts[0])
			}
		}
	}

	if name != "" && exec != "" {
		r.desktopNames[exec] = name
	}
}

// ResolvePID determines the stable AppIdentity for a given PID
func (r *Resolver) ResolvePID(pid uint32) *AppIdentity {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now().UTC()

	// 1. PID 0 is kernel / unattributed
	if pid == 0 {
		return r.getOrCreateIdentity("unknown:unattributed", "Unattributed Traffic", "unknown", "system", "", "", now)
	}

	// 2. Read live process metadata from /proc/<pid>
	snap, err := r.readProc(pid)
	if err != nil {
		// Preserve already resolved metadata for late deltas after exit.
		if cached, ok := r.procCache[pid]; ok {
			snap = &cached
		} else {
			if r.bpfLookup != nil {
				if comm, cgroupID, ok := r.bpfLookup(pid); ok && comm != "" {
					return r.getOrCreateIdentity("exec:short_lived:"+comm,
						r.lookupDisplayName(comm, ""), "cli_tool", "cli", comm,
						fmt.Sprintf("cgroup-%d", cgroupID), now)
				}
			}
			return r.getOrCreateIdentity(fmt.Sprintf("unknown:pid_%d", pid),
				fmt.Sprintf("Process [PID %d]", pid), "unknown", "cli", "", "", now)
		}
	} else {
		// Update cache
		r.procCache[pid] = *snap
	}

	// 3. Check for Flatpak application from cgroup
	if flatpakID := extractFlatpakID(snap.Cgroup); flatpakID != "" {
		appKey := fmt.Sprintf("flatpak:%s", flatpakID)
		dispName := r.lookupDisplayName(flatpakID, flatpakID)
		return r.getOrCreateIdentity(appKey, dispName, "desktop_app", "app", snap.ExePath, snap.Cgroup, now)
	}

	// 4. Check for Systemd system service from cgroup
	if serviceName := extractSystemdService(snap.Cgroup); serviceName != "" {
		appKey := fmt.Sprintf("systemd:%s", serviceName)
		return r.getOrCreateIdentity(appKey, serviceName, "system_service", "service", snap.ExePath, snap.Cgroup, now)
	}

	// 5. Follow process ancestry for multi-process applications (Chrome, Firefox, Electron)
	rootSnap := snap
	if isMultiProcessChild(snap.Comm, snap.ExePath) && snap.PPID > 1 {
		if parentSnap, err := r.readProc(snap.PPID); err == nil {
			if isSameApplicationTree(snap.ExePath, parentSnap.ExePath) {
				rootSnap = parentSnap
			}
		}
	}

	// 6. Standard binary / CLI tool identity
	var exePath string
	var binName string
	if rootSnap.ExePath != "" {
		exePath = rootSnap.ExePath
		binName = filepath.Base(rootSnap.ExePath)
	} else {
		binName = rootSnap.Comm
		exePath = rootSnap.Comm
	}

	appKey := fmt.Sprintf("exec:%s", exePath)
	dispName := r.lookupDisplayName(binName, exePath)
	category := classifyAppCategory(binName, exePath)
	iconType := classifyIconType(category)

	return r.getOrCreateIdentity(appKey, dispName, category, iconType, exePath, rootSnap.Cgroup, now)
}

func (r *Resolver) lookupDisplayName(binName, exePath string) string {
	if name, ok := r.desktopNames[binName]; ok {
		return name
	}
	base := filepath.Base(binName)
	if name, ok := r.desktopNames[base]; ok {
		return name
	}

	// Humanize common binaries
	switch strings.ToLower(binName) {
	case "firefox", "firefox-bin":
		return "Firefox"
	case "chrome", "google-chrome", "google-chrome-stable":
		return "Google Chrome"
	case "chromium", "chromium-browser":
		return "Chromium"
	case "brave", "brave-browser":
		return "Brave Browser"
	case "code", "vscode":
		return "Visual Studio Code"
	case "slack":
		return "Slack"
	case "spotify":
		return "Spotify"
	case "discord":
		return "Discord"
	case "tailscaled":
		return "Tailscale Daemon"
	case "curl":
		return "curl"
	case "git":
		return "git"
	case "ssh":
		return "SSH Client"
	}

	return binName
}

func (r *Resolver) getOrCreateIdentity(key, dispName, category, iconType, exePath, cgroup string, now time.Time) *AppIdentity {
	if existing, ok := r.appCache[key]; ok {
		existing.LastSeen = now
		if exePath != "" && existing.ExecutablePath == "" {
			existing.ExecutablePath = exePath
		}
		if cgroup != "" && existing.CgroupPath == "" {
			existing.CgroupPath = cgroup
		}
		copy := *existing
		return &copy
	}

	ident := &AppIdentity{
		AppKey:         key,
		DisplayName:    dispName,
		Category:       category,
		IconOrType:     iconType,
		ExecutablePath: exePath,
		CgroupPath:     cgroup,
		FirstSeen:      now,
		LastSeen:       now,
	}
	r.appCache[key] = ident
	copy := *ident
	return &copy
}

func (r *Resolver) readProc(pid uint32) (*procSnapshot, error) {
	procDir := fmt.Sprintf("/proc/%d", pid)

	// Read /proc/<pid>/stat for starttime and ppid
	statBytes, err := os.ReadFile(filepath.Join(procDir, "stat"))
	if err != nil {
		return nil, err
	}
	statStr := string(statBytes)

	// Format: pid (comm) state ppid ... starttime (field 22)
	lastParen := strings.LastIndex(statStr, ")")
	if lastParen == -1 || lastParen >= len(statStr)-2 {
		return nil, fmt.Errorf("malformed stat for pid %d", pid)
	}

	firstParen := strings.Index(statStr, "(")
	comm := ""
	if firstParen != -1 && lastParen > firstParen {
		comm = statStr[firstParen+1 : lastParen]
	}

	fields := strings.Fields(statStr[lastParen+2:])
	var ppid uint32
	var startTime uint64
	if len(fields) > 1 {
		if p, err := strconv.ParseUint(fields[1], 10, 32); err == nil {
			ppid = uint32(p)
		}
	}
	// starttime is field 22 in full stat (so index 22 - 3 = 19 in fields after comm)
	if len(fields) > 19 {
		if s, err := strconv.ParseUint(fields[19], 10, 64); err == nil {
			startTime = s
		}
	}

	// Read /proc/<pid>/exe symlink
	exePath, _ := os.Readlink(filepath.Join(procDir, "exe"))

	// Read /proc/<pid>/cgroup
	cgroup := ""
	if cgBytes, err := os.ReadFile(filepath.Join(procDir, "cgroup")); err == nil {
		cgroup = strings.TrimSpace(string(cgBytes))
	}

	return &procSnapshot{
		PID:       pid,
		PPID:      ppid,
		StartTime: startTime,
		Comm:      comm,
		ExePath:   exePath,
		Cgroup:    cgroup,
		CachedAt:  time.Now(),
	}, nil
}

func extractFlatpakID(cgroup string) string {
	// Look for app-flatpak-<id>-<pid>.scope or similar
	lines := strings.Split(cgroup, "\n")
	for _, line := range lines {
		idx := strings.Index(line, "app-flatpak-")
		if idx != -1 {
			sub := line[idx+len("app-flatpak-"):]
			endIdx := strings.Index(sub, "-")
			if endIdx != -1 {
				return sub[:endIdx]
			}
			scopeIdx := strings.Index(sub, ".scope")
			if scopeIdx != -1 {
				return sub[:scopeIdx]
			}
		}
	}
	return ""
}

func extractSystemdService(cgroup string) string {
	lines := strings.Split(cgroup, "\n")
	for _, line := range lines {
		if strings.Contains(line, "/system.slice/") {
			parts := strings.Split(line, "/system.slice/")
			if len(parts) > 1 {
				unit := strings.Split(parts[1], "/")[0]
				if strings.HasSuffix(unit, ".service") {
					return unit
				}
			}
		}
	}
	return ""
}

func isMultiProcessChild(comm, exePath string) bool {
	lowerComm := strings.ToLower(comm)
	lowerExe := strings.ToLower(exePath)

	multiProcs := []string{
		"chrome", "chromium", "firefox", "brave", "code", "electron", "slack", "discord",
	}

	for _, mp := range multiProcs {
		if strings.Contains(lowerComm, mp) || strings.Contains(lowerExe, mp) {
			return true
		}
	}
	return false
}

func isSameApplicationTree(childExe, parentExe string) bool {
	if childExe == "" || parentExe == "" {
		return false
	}
	return filepath.Base(childExe) == filepath.Base(parentExe) ||
		strings.Contains(parentExe, filepath.Base(childExe)) ||
		strings.Contains(childExe, filepath.Base(parentExe))
}

func classifyAppCategory(binName, exePath string) string {
	lower := strings.ToLower(binName)
	if strings.Contains(lower, "chrome") || strings.Contains(lower, "firefox") ||
		strings.Contains(lower, "brave") || strings.Contains(lower, "chromium") ||
		strings.Contains(lower, "browser") {
		return "web_browser"
	}
	if strings.Contains(lower, "curl") || strings.Contains(lower, "wget") ||
		strings.Contains(lower, "ssh") || strings.Contains(lower, "git") ||
		strings.Contains(lower, "nc") || strings.Contains(lower, "socat") {
		return "cli_tool"
	}
	if strings.HasSuffix(lower, "d") || strings.Contains(lower, "service") ||
		strings.Contains(lower, "systemd") || strings.Contains(lower, "daemon") {
		return "system_service"
	}
	return "desktop_app"
}

func classifyIconType(category string) string {
	switch category {
	case "web_browser":
		return "browser"
	case "system_service":
		return "service"
	case "cli_tool":
		return "cli"
	default:
		return "app"
	}
}
