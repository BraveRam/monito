package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/BraveRam/monito/pkg/api"
	"github.com/BraveRam/monito/pkg/tui"
	"github.com/BraveRam/monito/pkg/util"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		// Launch interactive TUI by default
		runTUI(api.DefaultSocketPath())
		return
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "tui":
		fs := flag.NewFlagSet("tui", flag.ExitOnError)
		socket := fs.String("socket", api.DefaultSocketPath(), "Path to collector Unix domain socket")
		_ = fs.Parse(args)
		runTUI(*socket)

	case "today":
		fs := flag.NewFlagSet("today", flag.ExitOnError)
		socket := fs.String("socket", api.DefaultSocketPath(), "Path to collector socket")
		asJSON := fs.Bool("json", false, "Output results as JSON")
		_ = fs.Parse(args)
		runToday(*socket, *asJSON)

	case "apps":
		fs := flag.NewFlagSet("apps", flag.ExitOnError)
		socket := fs.String("socket", api.DefaultSocketPath(), "Path to collector socket")
		date := fs.String("date", time.Now().Format("2006-01-02"), "Date in YYYY-MM-DD")
		sort := fs.String("sort", "total", "Sort field: total, upload, download, rate, name")
		filter := fs.String("filter", "", "Filter apps by name or category")
		asJSON := fs.Bool("json", false, "Output results as JSON")
		_ = fs.Parse(args)
		runApps(*socket, *date, *sort, *filter, *asJSON)

	case "history":
		fs := flag.NewFlagSet("history", flag.ExitOnError)
		socket := fs.String("socket", api.DefaultSocketPath(), "Path to collector socket")
		app := fs.String("app", "", "Application key (required, e.g. 'exec:/usr/bin/curl')")
		days := fs.Int("days", 7, "Number of past days to query")
		asJSON := fs.Bool("json", false, "Output results as JSON")
		_ = fs.Parse(args)
		if *app == "" {
			fmt.Fprintln(os.Stderr, "Error: --app flag is required for history command.")
			fs.Usage()
			os.Exit(1)
		}
		runHistory(*socket, *app, *days, *asJSON)

	case "live":
		fs := flag.NewFlagSet("live", flag.ExitOnError)
		socket := fs.String("socket", api.DefaultSocketPath(), "Path to collector socket")
		asJSON := fs.Bool("json", false, "Output streaming rates as JSON lines")
		_ = fs.Parse(args)
		runLive(*socket, *asJSON)

	case "status":
		fs := flag.NewFlagSet("status", flag.ExitOnError)
		socket := fs.String("socket", api.DefaultSocketPath(), "Path to collector socket")
		asJSON := fs.Bool("json", false, "Output results as JSON")
		_ = fs.Parse(args)
		runStatus(*socket, *asJSON)

	case "doctor":
		fs := flag.NewFlagSet("doctor", flag.ExitOnError)
		socket := fs.String("socket", api.DefaultSocketPath(), "Path to collector socket")
		asJSON := fs.Bool("json", false, "Output results as JSON")
		_ = fs.Parse(args)
		runDoctor(*socket, *asJSON)

	case "version", "-v", "--version":
		fmt.Printf("monito version %s (Linux/x86_64 eBPF)\n", version)

	case "help", "-h", "--help":
		printUsage()

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`Monito - Linux Application Network Traffic Monitor (v%s)

Usage:
  monito [command] [flags]

Commands:
  (no args)                        Launch interactive Terminal User Interface (TUI)
  tui                              Launch interactive Terminal User Interface (TUI)
  today [--json]                   Show today's upload, download, and category totals
  apps [--sort=...] [--filter=...] List ranked applications for the given day
  history --app <key> [--days=7]   Show usage history for a specific application
  live [--json]                    Stream live upload and download rates
  status [--json]                  Show background collector health and diagnostics
  doctor [--json]                  Inspect system environment, eBPF, and capabilities
  version                          Show version information

Flags:
  --socket <path>                  Specify collector Unix domain socket
  --json                           Output in machine-readable JSON format

Examples:
  monito
  monito today
  monito apps --sort=rate
  monito apps --filter=firefox --json
  monito history --app=flatpak:org.mozilla.firefox --days=14
  monito live
  monito status
  monito doctor
`, version)
}

func runTUI(socketPath string) {
	client := api.NewClient(socketPath)
	model := tui.NewModel(client)
	p := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running TUI: %v\n", err)
		os.Exit(1)
	}
}

func runToday(socketPath string, asJSON bool) {
	client := api.NewClient(socketPath)
	today := time.Now().Format("2006-01-02")
	summary, err := client.GetSummary(today)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(summary)
		return
	}

	fmt.Printf("=== Monito Network Usage Summary for Today (%s) ===\n", today)
	fmt.Printf("Total Traffic:      %s\n", util.FormatBytes(summary.TotalBytes))
	fmt.Printf("  • Download (RX):  %s\n", util.FormatBytes(summary.TotalBytesIn))
	fmt.Printf("  • Upload (TX):    %s\n", util.FormatBytes(summary.TotalBytesOut))
	fmt.Println("\nTraffic by Category:")
	fmt.Printf("  • External:       %s\n", util.FormatBytes(summary.ExternalBytes))
	fmt.Printf("  • Private / LAN:  %s\n", util.FormatBytes(summary.PrivateBytes))
	fmt.Printf("  • Loopback:       %s\n", util.FormatBytes(summary.LoopbackBytes))
	if summary.UnknownBytes > 0 {
		fmt.Printf("  • Unattributed:   %s\n", util.FormatBytes(summary.UnknownBytes))
	}
	fmt.Printf("\nRecorded Applications: %d\n", summary.RecordedAppCount)
	if summary.TotalBytes > 0 {
		fmt.Printf("App Attribution: %.1f%% (%s unattributed)\n", float64(summary.TotalBytes-summary.UnattributedBytes)*100/float64(summary.TotalBytes), util.FormatBytes(summary.UnattributedBytes))
	}
}

func runApps(socketPath, date, sort, filter string, asJSON bool) {
	client := api.NewClient(socketPath)
	apps, err := client.GetApps(date, sort, filter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(apps)
		return
	}

	if len(apps) == 0 {
		fmt.Println("No network activity recorded for the given date/filter.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "APP NAME\tCATEGORY\tDOWNLOAD\tUPLOAD\tTOTAL\tLIVE RATE\n")
	for _, app := range apps {
		rateStr := "-"
		if app.RateIn+app.RateOut > 0 {
			rateStr = util.FormatRate(app.RateIn + app.RateOut)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			app.Identity.DisplayName,
			app.Identity.Category,
			util.FormatBytes(app.BytesIn),
			util.FormatBytes(app.BytesOut),
			util.FormatBytes(app.TotalBytes),
			rateStr,
		)
	}
	_ = w.Flush()
}

func runHistory(socketPath, appKey string, days int, asJSON bool) {
	client := api.NewClient(socketPath)
	pts, err := client.GetHistory(appKey, days)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(pts)
		return
	}

	fmt.Printf("=== Usage History for %s (Past %d Days) ===\n", appKey, days)
	if len(pts) == 0 {
		fmt.Println("No history records found for this application.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "DATE\tDOWNLOAD\tUPLOAD\tTOTAL\n")
	for _, pt := range pts {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			pt.Date,
			util.FormatBytes(pt.BytesIn),
			util.FormatBytes(pt.BytesOut),
			util.FormatBytes(pt.TotalBytes),
		)
	}
	_ = w.Flush()
}

func runLive(socketPath string, asJSON bool) {
	client := api.NewClient(socketPath)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	if !asJSON {
		fmt.Println("Streaming live bandwidth rates. Press Ctrl+C to stop...")
	}

	for {
		select {
		case <-sig:
			return
		case <-ticker.C:
			live, err := client.GetLive()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Collector error: %v\n", err)
				time.Sleep(1 * time.Second)
				continue
			}

			if asJSON {
				_ = json.NewEncoder(os.Stdout).Encode(live)
			} else {
				fmt.Printf("[%s] Total: %-10s (↓ %-10s  ↑ %-10s) | Top apps: ",
					live.Timestamp.Format("15:04:05"),
					util.FormatRate(live.TotalRate),
					util.FormatRate(live.TotalRateIn),
					util.FormatRate(live.TotalRateOut),
				)
				if len(live.AppRates) == 0 {
					fmt.Print("(idle)")
				} else {
					var top []string
					for i := 0; i < len(live.AppRates) && i < 3; i++ {
						ar := live.AppRates[i]
						top = append(top, fmt.Sprintf("%s: %s", ar.DisplayName, util.FormatRate(ar.TotalRate)))
					}
					fmt.Print(strings.Join(top, ", "))
				}
				fmt.Println()
			}
		}
	}
}

func runStatus(socketPath string, asJSON bool) {
	client := api.NewClient(socketPath)
	status, err := client.GetStatus()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(status)
		return
	}

	fmt.Println("=== Monito Collector Status ===")
	fmt.Printf("Version:               %s\n", status.Version)
	fmt.Printf("Uptime:                %s\n", time.Duration(status.UptimeSeconds)*time.Second)
	fmt.Printf("Started:               %s\n", status.StartTime.Format(time.RFC3339))
	fmt.Printf("Last DB Flush:         %s\n", status.LastFlushTime.Format(time.RFC3339))
	fmt.Printf("Active Applications:   %d\n", status.ActiveAppCount)
	fmt.Printf("Recovered Existing Sockets: %d\n", status.RecoveredSockets)
	fmt.Printf("Ownership Recovery Errors: %d\n", status.RecoveryErrors)
	fmt.Println("\nKernel eBPF Metrics:")
	fmt.Printf("  • Total Ingress:     %s packets\n", strconv.FormatUint(status.TotalIngressPackets, 10))
	fmt.Printf("  • Total Egress:      %s packets\n", strconv.FormatUint(status.TotalEgressPackets, 10))
	fmt.Printf("  • Tracked Sockets:   %s\n", strconv.FormatUint(status.SocketsRegistered, 10))
	fmt.Printf("  • Unattributed In:   %s\n", strconv.FormatUint(status.UnattributedIngress, 10))
	fmt.Printf("  • Unattributed Out:  %s\n", strconv.FormatUint(status.UnattributedEgress, 10))
	fmt.Printf("  • Map Drops/Errors:  %s\n", strconv.FormatUint(status.MapErrors, 10))
}

func runDoctor(socketPath string, asJSON bool) {
	client := api.NewClient(socketPath)
	doctor, err := client.GetDoctor()
	if err != nil {
		// Run standalone doctor checks if collector is not running
		doctor = &api.DoctorReport{
			SocketReachable: false,
			Warnings:        []string{fmt.Sprintf("Collector socket unreachable: %v", err)},
		}
		if kver, err := os.ReadFile("/proc/version"); err == nil {
			doctor.KernelVersion = strings.TrimSpace(string(kver))
		}
		if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
			doctor.CgroupV2Mounted = true
		}
		if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
			doctor.BTFAvailable = true
		}
	}

	if asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(doctor)
		return
	}

	fmt.Println("=== Monito Doctor Diagnostics ===")
	fmt.Printf("Kernel Version:        %s\n", doctor.KernelVersion)
	fmt.Printf("cgroup v2 Mounted:     %s\n", formatCheck(doctor.CgroupV2Mounted))
	fmt.Printf("BTF Support:           %s\n", formatCheck(doctor.BTFAvailable))
	fmt.Printf("Collector Socket:      %s\n", formatCheck(doctor.SocketReachable))

	if len(doctor.Warnings) > 0 {
		fmt.Println("\nWarnings / Notices:")
		for _, w := range doctor.Warnings {
			fmt.Printf("  ⚠️  %s\n", w)
		}
	} else {
		fmt.Println("\n✓ All core requirements satisfied.")
	}
}

func formatCheck(ok bool) string {
	if ok {
		return "✓ Yes"
	}
	return "✗ No"
}
