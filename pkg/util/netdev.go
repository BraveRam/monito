package util

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// InterfaceStat represents raw network device statistics
type InterfaceStat struct {
	Name    string
	RxBytes uint64
	TxBytes uint64
}

// ReadInterfaceStats reads raw byte counters from /proc/net/dev
func ReadInterfaceStats() ([]InterfaceStat, error) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var stats []InterfaceStat
	scanner := bufio.NewScanner(file)
	lineIdx := 0

	for scanner.Scan() {
		lineIdx++
		if lineIdx <= 2 {
			continue // Skip headers
		}

		line := strings.TrimSpace(scanner.Text())
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		ifname := strings.TrimSpace(parts[0])
		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}

		rxBytes, err1 := strconv.ParseUint(fields[0], 10, 64)
		txBytes, err2 := strconv.ParseUint(fields[8], 10, 64)
		if err1 == nil && err2 == nil {
			stats = append(stats, InterfaceStat{
				Name:    ifname,
				RxBytes: rxBytes,
				TxBytes: txBytes,
			})
		}
	}

	return stats, nil
}

// FormatBytes formats byte counts using decimal units (1 KB = 1000 bytes).
func FormatBytes(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	for n := b / unit; n >= unit && exp < len(units)-1; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %s", float64(b)/float64(div), units[exp])
}

// FormatRate formats bytes per second using decimal units (1 KB/s = 1000 B/s).
func FormatRate(bps float64) string {
	const unit = 1000.0
	if bps < unit {
		return fmt.Sprintf("%.0f B/s", bps)
	}
	div, exp := unit, 0
	units := []string{"KB/s", "MB/s", "GB/s"}
	for n := bps / unit; n >= unit && exp < len(units)-1; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %s", bps/div, units[exp])
}
