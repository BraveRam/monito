package bpf

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestCumulativeDeltasSurviveUpdatesAndRecreation(t *testing.T) {
	first := MonitoFlowMetrics{Generation: 10, RxBytes: 100, TxBytes: 200, RxPackets: 1, TxPackets: 2}
	second := MonitoFlowMetrics{Generation: 10, RxBytes: 130, TxBytes: 250, RxPackets: 2, TxPackets: 3}
	got := counterDelta(second, first)
	if got.RxBytes != 30 || got.TxBytes != 50 || got.RxPackets != 1 || got.TxPackets != 1 {
		t.Fatalf("delta = %+v", got)
	}
	// A new LRU entry may already exceed the old snapshot; generation, not a
	// counter-decrease heuristic, must identify recreation.
	recreated := MonitoFlowMetrics{Generation: 11, RxBytes: 300, TxBytes: 400}
	if got := counterDelta(recreated, second); got.RxBytes != 300 || got.TxBytes != 400 {
		t.Fatalf("recreated delta = %+v", got)
	}
	if got := counterDelta(second, second); got.RxBytes != 0 || got.TxBytes != 0 {
		t.Fatalf("unchanged snapshot counted twice: %+v", got)
	}
}

// TestKernelConcurrentSnapshots exercises the actual kernel programs while
// snapshots race with concurrent packet accounting. It needs no cgroup attach.
func TestKernelConcurrentSnapshots(t *testing.T) {
	if os.Getenv("MONITO_EBPF_E2E") != "1" {
		t.Skip("requires privileged kernel test")
	}
	var objs MonitoObjects
	if err := LoadMonitoObjects(&objs, nil); err != nil {
		t.Fatalf("load programs: %+v", err)
	}
	// BPF_PROG_TEST_RUN supplies no socket; disable only this test's boundary.
	if err := objs.AccountingScope.Update(uint32(0), NamespaceScope{}, 0); err != nil {
		t.Fatal(err)
	}
	c := &BPFCollector{objs: objs, previous: make(map[MonitoFlowKey]MonitoFlowMetrics)}
	defer c.Close()
	// Ethernet + a minimal IPv4/UDP packet. Program.Test injects a synthetic
	// skb with no owning socket, isolating this from real host traffic.
	packet := make([]byte, 14+20+8+32)
	packet[12], packet[13] = 0x08, 0x00
	packet[14], packet[16], packet[17], packet[22], packet[23] = 0x45, 0, 60, 64, 17
	copy(packet[26:30], []byte{10, 0, 0, 1})
	copy(packet[30:34], []byte{10, 0, 0, 2})
	if ret, _, err := c.objs.OnEgress.Test(packet); err != nil || ret != 1 {
		t.Fatalf("test packet: ret=%d err=%v", ret, err)
	}
	first, err := c.DrainDeltas()
	if err != nil || len(first) != 1 {
		t.Fatalf("initial delta=%+v err=%v", first, err)
	}
	bytesPerPacket := first[0].TxBytes
	const workers, packets = 16, 100
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < packets; j++ {
				if _, _, err := c.objs.OnEgress.Test(packet); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	var totalBytes, totalPackets uint64
	for {
		deltas, err := c.DrainDeltas()
		if err != nil {
			t.Fatal(err)
		}
		for _, delta := range deltas {
			totalBytes += delta.TxBytes
			totalPackets += delta.TxPackets
		}
		select {
		case <-done:
			last, err := c.DrainDeltas()
			if err != nil {
				t.Fatal(err)
			}
			for _, delta := range last {
				totalBytes += delta.TxBytes
				totalPackets += delta.TxPackets
			}
			if totalPackets != workers*packets || totalBytes != workers*packets*bytesPerPacket {
				t.Fatalf("lost or duplicated traffic: bytes=%d packets=%d; want bytes=%d packets=%d", totalBytes, totalPackets, workers*packets*bytesPerPacket, workers*packets)
			}
			return
		default:
			runtime.Gosched()
		}
	}
}

// Inspect the storage itself as well as packet counters so a failed integration
// test distinguishes listener registration from accepted-socket inheritance.
func TestKernelSocketOwnership(t *testing.T) {
	if os.Getenv("MONITO_EBPF_E2E") != "1" {
		t.Skip("requires privileged kernel test")
	}
	collector, err := NewBPFCollector("/sys/fs/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	t.Logf("storage flags=%#x", collector.objs.SockOwners.Flags())
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	checkOwner := func(name string, socket syscall.Conn) {
		raw, err := socket.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var owner MonitoProcInfo
		var lookupErr error
		if err := raw.Control(func(fd uintptr) { key := uint32(fd); lookupErr = collector.objs.SockOwners.Lookup(&key, &owner) }); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: owner=%+v lookup=%v counters=%+v", name, owner, lookupErr, collector.ReadCounters())
		if lookupErr != nil || owner.Pid != uint32(os.Getpid()) {
			t.Errorf("%s missing correct ownership", name)
		}
	}
	checkOwner("listener", l.(syscall.Conn))
	done := make(chan error, 1)
	go func() {
		c, err := net.DialTimeout("tcp4", l.Addr().String(), 3*time.Second)
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		_, err = fmt.Fprintln(c, "ownership probe")
		done <- err
	}()
	l.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
	accepted, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	checkOwner("accepted", accepted.(syscall.Conn))
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestKernelRecoverExistingSockets(t *testing.T) {
	if os.Getenv("MONITO_EBPF_E2E") != "1" {
		t.Skip("requires privileged kernel test")
	}
	// Establish these before any creation/listen hooks are attached.
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	type udpPair struct{ server, client *net.UDPConn }
	var pairs []udpPair
	for _, network := range []string{"udp4", "udp6"} {
		address := "127.0.0.1:0"
		if network == "udp6" {
			address = "[::1]:0"
		}
		a, err := net.ResolveUDPAddr(network, address)
		if err != nil {
			t.Fatal(err)
		}
		s, err := net.ListenUDP(network, a)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		c, err := net.DialUDP(network, nil, s.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		pairs = append(pairs, udpPair{s, c})
	}
	collector, err := NewBPFCollector("/sys/fs/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	check := func(socket syscall.Conn) {
		raw, err := socket.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var owner MonitoProcInfo
		var lookup error
		if err := raw.Control(func(fd uintptr) { key := uint32(fd); lookup = collector.objs.SockOwners.Lookup(&key, &owner) }); err != nil {
			t.Fatal(err)
		}
		if lookup != nil || owner.Pid != uint32(os.Getpid()) {
			t.Fatalf("existing socket owner=%+v error=%v", owner, lookup)
		}
	}
	client.SetDeadline(time.Now().Add(3 * time.Second))
	server.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	if _, err := server.Read(buf); err != nil {
		t.Fatal(err)
	}
	check(client.(syscall.Conn))
	check(server.(syscall.Conn))
	for _, pair := range pairs {
		pair.server.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := pair.client.Write([]byte("recover")); err != nil {
			t.Fatal(err)
		}
		if _, _, err := pair.server.ReadFromUDP(buf); err != nil {
			t.Fatal(err)
		}
		check(pair.server)
		check(pair.client)
	}
	status := collector.ReadCounters()
	if status.RecoveredSockets < 6 || status.RecoveryErrors != 0 {
		t.Fatalf("recovery counters=%+v", status)
	}
}
