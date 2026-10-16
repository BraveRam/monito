// Prototype prints raw PID/category deltas using the same collector as monitod.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BraveRam/monito/pkg/bpf"
)

func main() {
	collector, err := bpf.NewBPFCollector("/sys/fs/cgroup")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer collector.Close()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	printDeltas := func() {
		deltas, err := collector.DrainDeltas()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		for _, d := range deltas {
			fmt.Printf("pid=%d category=%s rx=%d tx=%d rx_packets=%d tx_packets=%d\n", d.PID, d.Category, d.RxBytes, d.TxBytes, d.RxPackets, d.TxPackets)
		}
	}
	for {
		select {
		case <-sig:
			if err := collector.StopAccounting(); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
			printDeltas()
			return
		case <-ticker.C:
			printDeltas()
		}
	}
}
