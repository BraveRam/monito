package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"monito/pkg/api"
	"monito/pkg/bpf"
	"monito/pkg/identity"
	"monito/pkg/storage"
	"monito/pkg/util"
)

type flowCollector interface {
	DrainDeltas() ([]bpf.FlowDelta, error)
	StopAccounting() error
	ReadCounters() bpf.DiagnosticCounters
}

type collectorDaemon struct {
	mu             sync.RWMutex
	store          *storage.Storage
	resolver       *identity.Resolver
	bpfCollector   flowCollector
	startTime      time.Time
	lastFlushTime  time.Time
	liveStatus     api.LiveStatus
	diag           bpf.DiagnosticCounters
	activeApps     int
	pidFile        *os.File
	mockMode       bool
	pendingRecords []storage.IngestionRecord
}

func (d *collectorDaemon) GetLiveStatus() api.LiveStatus {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.liveStatus
}

func (d *collectorDaemon) GetCollectorStatus() api.CollectorStatus {
	d.mu.RLock()
	defer d.mu.RUnlock()

	status := api.CollectorStatus{
		UptimeSeconds:  int64(time.Since(d.startTime).Seconds()),
		StartTime:      d.startTime,
		LastFlushTime:  d.lastFlushTime,
		ActiveAppCount: d.activeApps,
		Version:        "1.0.0",
	}

	if d.bpfCollector != nil {
		diag := d.bpfCollector.ReadCounters()
		status.TotalIngressPackets = diag.TotalIngressPackets
		status.TotalEgressPackets = diag.TotalEgressPackets
		status.SocketsRegistered = diag.SocketsRegistered
		status.UnattributedIngress = diag.UnattributedIngress
		status.UnattributedEgress = diag.UnattributedEgress
		status.MapErrors = diag.MapErrors
	}
	return status
}

func (d *collectorDaemon) GetDoctorReport() api.DoctorReport {
	report := api.DoctorReport{
		CgroupV2Mounted: isCgroupV2Mounted(),
		BTFAvailable:    isBTFAvailable(),
		SELinuxStatus:   checkSELinux(),
		SocketReachable: true,
		DBWritable:      true,
	}

	if kver, err := os.ReadFile("/proc/version"); err == nil {
		report.KernelVersion = strings.TrimSpace(string(kver))
	}

	if !report.CgroupV2Mounted {
		report.Warnings = append(report.Warnings, "cgroup v2 is not mounted at /sys/fs/cgroup")
	}
	if !report.BTFAvailable {
		report.Warnings = append(report.Warnings, "BTF (/sys/kernel/btf/vmlinux) not found")
	}
	if d.mockMode {
		report.Warnings = append(report.Warnings, "Collector running in MOCK / PREVIEW mode without eBPF capabilities")
	}
	return report
}

func isCgroupV2Mounted() bool {
	_, err := os.Stat("/sys/fs/cgroup/cgroup.controllers")
	return err == nil
}

func isBTFAvailable() bool {
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	return err == nil
}

func checkSELinux() string {
	if _, err := os.Stat("/sys/fs/selinux"); err == nil {
		if data, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
			if strings.TrimSpace(string(data)) == "1" {
				return "enforcing"
			}
			return "permissive"
		}
		return "enabled"
	}
	return "disabled"
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	defaultDB := "/var/lib/monito/monito.db"
	defaultSocket := "/run/monito/monito.sock"
	if os.Geteuid() != 0 {
		home := os.Getenv("HOME")
		defaultDB = filepath.Join(home, ".local/share/monito/monito.db")
		defaultSocket = api.UserSocketPath()
	}

	dbPath := flag.String("db", defaultDB, "Path to SQLite database")
	sockPath := flag.String("socket", defaultSocket, "Path to Unix domain socket")
	cgroupPath := flag.String("cgroup", "/sys/fs/cgroup", "Path to cgroup v2 mount")
	flushSec := flag.Int("flush-interval", 5, "Database flush interval in seconds")
	mock := flag.Bool("mock", false, "Run in clearly-labeled mock preview mode (for testing without root/capabilities)")
	flag.Parse()
	if *flushSec <= 0 {
		return fmt.Errorf("flush-interval must be greater than zero")
	}

	fmt.Println("=== Monito Privileged Collector Daemon ===")
	fmt.Printf("Database: %s\n", *dbPath)
	fmt.Printf("Socket:   %s\n", *sockPath)

	// Acquire PID lockfile to prevent multiple concurrent collectors
	pidPath := *sockPath + ".pid"
	if err := os.MkdirAll(filepath.Dir(pidPath), 0755); err != nil {
		return fmt.Errorf("create run directory: %w", err)
	}
	pidFile, err := os.OpenFile(pidPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("open pid file %s: %w", pidPath, err)
	}
	if err := syscall.Flock(int(pidFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = pidFile.Close()
		return fmt.Errorf("another instance of monitod is already running on %s", *sockPath)
	}
	defer func() {
		_ = syscall.Flock(int(pidFile.Fd()), syscall.LOCK_UN)
		_ = pidFile.Close()
	}()
	_ = pidFile.Truncate(0)
	_, _ = pidFile.WriteString(fmt.Sprintf("%d\n", os.Getpid()))

	// Initialize Storage
	store, err := storage.NewStorage(*dbPath)
	if err != nil {
		return fmt.Errorf("initialize storage: %w", err)
	}
	defer store.Close()

	// Initialize Identity Resolver
	resolver := identity.NewResolver()

	daemon := &collectorDaemon{
		store:         store,
		resolver:      resolver,
		startTime:     time.Now().UTC(),
		lastFlushTime: time.Now().UTC(),
		pidFile:       pidFile,
		mockMode:      *mock,
	}

	// Preview mode never loads or attaches kernel programs.
	if *mock {
		fmt.Println("Running in MOCK / PREVIEW MODE (no kernel accounting)")
	} else {
		bpfCol, err := bpf.NewBPFCollector(*cgroupPath)
		if err != nil {
			return fmt.Errorf("load eBPF collector (requires CAP_BPF+CAP_NET_ADMIN): %w", err)
		}
		daemon.bpfCollector = bpfCol
		defer bpfCol.Close()
		fmt.Println("eBPF programs loaded and attached to cgroup v2")
		resolver.SetBPFLookup(func(pid uint32) (string, uint64, bool) {
			if meta, ok := bpfCol.LookupPIDMetadata(pid); ok {
				var comm []byte
				for _, c := range meta.Comm {
					if c == 0 {
						break
					}
					comm = append(comm, byte(c))
				}
				return string(comm), meta.CgroupId, true
			}
			return "", 0, false
		})
	}

	// Start Unix Socket API server
	server := api.NewServer(store, daemon, *sockPath)
	if err := server.Start(); err != nil {
		return fmt.Errorf("start API server: %w", err)
	}
	defer server.Stop()
	fmt.Printf("✓ API server listening on %s\n", *sockPath)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)

	pollTicker := time.NewTicker(1 * time.Second)
	defer pollTicker.Stop()

	flushTicker := time.NewTicker(time.Duration(*flushSec) * time.Second)
	defer flushTicker.Stop()

	pruneTicker := time.NewTicker(24 * time.Hour)
	defer pruneTicker.Stop()
	if _, err := store.PruneOldHistory(14); err != nil {
		return fmt.Errorf("prune history: %w", err)
	}
	previousPoll := time.Now()
	fmt.Println("Collector running. Press Ctrl+C to stop.")
	for {
		select {
		case <-sig:
			fmt.Println("Received termination signal. Draining kernel counters and flushing...")
			if err := daemon.shutdown(previousPoll); err != nil {
				return err
			}
			fmt.Println("Collector cleanly stopped.")
			return nil
		case <-pollTicker.C:
			now := time.Now()
			if err := daemon.poll(now, now.Sub(previousPoll)); err != nil {
				fmt.Fprintf(os.Stderr, "Kernel snapshot failed; retaining counters: %v\n", err)
				continue
			}
			previousPoll = now
			if ifStats, err := util.ReadInterfaceStats(); err == nil {
				for _, stat := range ifStats {
					if err := store.RecordInterfaceStats(stat.Name, stat.RxBytes, stat.TxBytes); err != nil {
						fmt.Fprintf(os.Stderr, "Interface snapshot failed: %v\n", err)
					}
				}
			}
		case <-flushTicker.C:
			if err := daemon.flush(); err != nil {
				fmt.Fprintf(os.Stderr, "Usage flush failed; retaining %d records for retry: %v\n", len(daemon.pendingRecords), err)
			}
		case <-pruneTicker.C:
			if _, err := store.PruneOldHistory(14); err != nil {
				fmt.Fprintf(os.Stderr, "History pruning failed: %v\n", err)
			}
		}
	}
}

// poll is called serially by the event loop, including once after detachment.
func (d *collectorDaemon) poll(now time.Time, elapsed time.Duration) error {
	var deltas []bpf.FlowDelta
	if d.bpfCollector != nil {
		var err error
		deltas, err = d.bpfCollector.DrainDeltas()
		if err != nil {
			return err
		}
	}
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		seconds = 1
	}
	rates := make(map[string]*api.LiveAppRate)
	live := api.LiveStatus{Timestamp: now}
	for _, delta := range deltas {
		ident := d.resolver.ResolvePID(delta.PID)
		d.pendingRecords = append(d.pendingRecords, storage.IngestionRecord{
			Identity: ident, ObservedAt: now, Category: int(delta.Category),
			BytesIn: delta.RxBytes, BytesOut: delta.TxBytes,
			PacketsIn: delta.RxPackets, PacketsOut: delta.TxPackets,
		})
		rate := rates[ident.AppKey]
		if rate == nil {
			rate = &api.LiveAppRate{AppKey: ident.AppKey, DisplayName: ident.DisplayName, Category: ident.Category}
			rates[ident.AppKey] = rate
		}
		rate.RateIn += float64(delta.RxBytes) / seconds
		rate.RateOut += float64(delta.TxBytes) / seconds
		rate.TotalRate = rate.RateIn + rate.RateOut
		live.TotalRateIn += float64(delta.RxBytes) / seconds
		live.TotalRateOut += float64(delta.TxBytes) / seconds
	}
	for _, rate := range rates {
		live.AppRates = append(live.AppRates, *rate)
	}
	sort.Slice(live.AppRates, func(i, j int) bool { return live.AppRates[i].TotalRate > live.AppRates[j].TotalRate })
	live.TotalRate = live.TotalRateIn + live.TotalRateOut
	d.mu.Lock()
	d.liveStatus = live
	d.activeApps = len(rates)
	d.mu.Unlock()
	return nil
}

func (d *collectorDaemon) flush() error {
	if len(d.pendingRecords) == 0 {
		return nil
	}
	if err := d.store.RecordUsage(d.pendingRecords, time.Local); err != nil {
		return err
	}
	d.pendingRecords = nil
	d.mu.Lock()
	d.lastFlushTime = time.Now().UTC()
	d.mu.Unlock()
	return nil
}

// Always attempt persistence even if detachment or the final snapshot fails.
func (d *collectorDaemon) shutdown(previousPoll time.Time) error {
	var errs []error
	if d.bpfCollector != nil {
		if err := d.bpfCollector.StopAccounting(); err != nil {
			errs = append(errs, fmt.Errorf("detach accounting: %w", err))
		}
	}
	now := time.Now()
	if err := d.poll(now, now.Sub(previousPoll)); err != nil {
		errs = append(errs, fmt.Errorf("final snapshot: %w", err))
	}
	for attempt := 0; ; attempt++ {
		if err := d.flush(); err != nil {
			if attempt == 2 {
				errs = append(errs, fmt.Errorf("shutdown flush failed (%d records remain): %w", len(d.pendingRecords), err))
				break
			}
			fmt.Fprintf(os.Stderr, "Shutdown flush failed; retrying: %v\n", err)
			time.Sleep(time.Second)
			continue
		}
		break
	}
	return errors.Join(errs...)
}
