package util

import (
	"math"
	"testing"
)

func TestFormatBytesDecimal(t *testing.T) {
	for _, tt := range []struct {
		bytes int64
		want  string
	}{
		{0, "0 B"},
		{999, "999 B"},
		{1000, "1.00 KB"},
		{1024, "1.02 KB"},
		{1_000_000, "1.00 MB"},
		{1_000_000_000, "1.00 GB"},
		{1_449_551_462, "1.45 GB"},
		{math.MaxInt64, "9223.37 PB"},
	} {
		if got := FormatBytes(tt.bytes); got != tt.want {
			t.Errorf("FormatBytes(%d) = %q, want %q", tt.bytes, got, tt.want)
		}
	}
}

func TestFormatRateDecimal(t *testing.T) {
	for _, tt := range []struct {
		bps  float64
		want string
	}{
		{0, "0 B/s"},
		{999, "999 B/s"},
		{1000, "1.0 KB/s"},
		{1500, "1.5 KB/s"},
		{1_000_000, "1.0 MB/s"},
		{1_000_000_000, "1.0 GB/s"},
		{1_000_000_000_000, "1000.0 GB/s"},
	} {
		if got := FormatRate(tt.bps); got != tt.want {
			t.Errorf("FormatRate(%g) = %q, want %q", tt.bps, got, tt.want)
		}
	}
}
