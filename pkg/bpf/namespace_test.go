package bpf

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// No Internet access: exercise socket traffic in a second network namespace,
// the inner half of the rootless-container/helper double-counting regression.
func TestKernelNetworkNamespaceScope(t *testing.T) {
	if os.Getenv("MONITO_EBPF_E2E") != "1" {
		t.Skip("requires privileged kernel test")
	}
	if os.Getenv("MONITO_NETNS_PROBE") == "1" {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		flags, err := unix.NewIfreq("lo")
		if err != nil {
			t.Fatal(err)
		}
		flags.SetUint16(unix.IFF_UP)
		if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, flags); err != nil {
			t.Fatal(err)
		}
		namespaceProbe(t)
		return
	}
	collector, err := NewBPFCollector("/sys/fs/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(exe, "-test.run=^TestKernelNetworkNamespaceScope$", "-test.v")
	child.Env = append(os.Environ(), "MONITO_NETNS_PROBE=1")
	child.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
	out, err := child.CombinedOutput()
	if errors.Is(err, syscall.EPERM) {
		// Service capabilities deliberately exclude CAP_SYS_ADMIN. The GA VM
		// runs this namespace-creation test; native sandbox tests still run.
		t.Skip("network namespace creation requires CAP_SYS_ADMIN; covered by kernel VM")
	}
	if err != nil {
		t.Fatalf("namespace probe: %v\n%s", err, out)
	}
	t.Logf("other namespace probe: %s", out)
	deltas, err := collector.DrainDeltas()
	if err != nil {
		t.Fatal(err)
	}
	for _, delta := range deltas {
		if delta.PID == uint32(child.ProcessState.Pid()) && delta.RxBytes+delta.TxBytes > 0 {
			t.Fatalf("counted inner-namespace traffic: %+v", delta)
		}
	}
	diag := collector.ReadCounters()
	if diag.ExcludedNamespacePackets == 0 || diag.NamespaceReadErrors != 0 {
		t.Fatalf("namespace boundary did not exclude packets cleanly: %+v", diag)
	}
	// The boundary must still count the outer host-side socket, independent
	// of executable name. Merely dropping all packets would fail this check.
	namespaceProbe(t)
	deltas, err = collector.DrainDeltas()
	if err != nil {
		t.Fatal(err)
	}
	var bytes uint64
	for _, delta := range deltas {
		if delta.PID == uint32(os.Getpid()) {
			bytes += delta.RxBytes + delta.TxBytes
		}
	}
	if bytes == 0 {
		t.Fatal("host namespace traffic disappeared")
	}
	if diag = collector.ReadCounters(); diag.NamespaceReadErrors != 0 {
		t.Fatalf("namespace read errors: %+v", diag)
	}
}

func namespaceProbe(t *testing.T) {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.ReadFromUDP(make([]byte, 8192)); err != nil {
		t.Fatal(err)
	}
}
