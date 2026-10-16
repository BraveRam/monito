package bpf

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// TrafficCategory represents the traffic destination / type
type TrafficCategory uint8

const (
	CategoryLoopback TrafficCategory = 0
	CategoryPrivate  TrafficCategory = 1
	CategoryExternal TrafficCategory = 2
	CategoryUnknown  TrafficCategory = 3
)

func (c TrafficCategory) String() string {
	switch c {
	case CategoryLoopback:
		return "loopback"
	case CategoryPrivate:
		return "private"
	case CategoryExternal:
		return "external"
	default:
		return "unknown"
	}
}

// FlowDelta represents accumulated network delta for a PID and category
type FlowDelta struct {
	PID       uint32
	Category  TrafficCategory
	RxBytes   uint64
	TxBytes   uint64
	RxPackets uint64
	TxPackets uint64
}

// DiagnosticCounters represents kernel BPF health and capacity metrics
type DiagnosticCounters struct {
	TotalIngressPackets uint64
	TotalEgressPackets  uint64
	SocketsRegistered   uint64
	UnattributedIngress uint64
	UnattributedEgress  uint64
	MapErrors           uint64
}

// BPFCollector manages the eBPF programs, maps, and links
type BPFCollector struct {
	mu             sync.Mutex
	objs           MonitoObjects
	cgroupFile     *os.File
	sockCreateLink link.Link
	sockOpsLink    link.Link
	previous       map[MonitoFlowKey]MonitoFlowMetrics
	ingressLink    link.Link
	egressLink     link.Link
	cgroupPath     string
	closed         bool
}

// NewBPFCollector initializes, loads, and attaches BPF programs to root cgroup
func NewBPFCollector(cgroupPath string) (*BPFCollector, error) {
	if cgroupPath == "" {
		cgroupPath = "/sys/fs/cgroup"
	}

	// Try removing memlock limit (for older kernels; harmless on 5.11+)
	_ = rlimit.RemoveMemlock()

	col := &BPFCollector{
		cgroupPath: cgroupPath,
		previous:   make(map[MonitoFlowKey]MonitoFlowMetrics),
	}

	if err := LoadMonitoObjects(&col.objs, nil); err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			return nil, fmt.Errorf("load BPF objects: %+v", verifier)
		}
		return nil, fmt.Errorf("load BPF objects: %w (check CAP_BPF / CAP_NET_ADMIN)", err)
	}

	f, err := os.Open(cgroupPath)
	if err != nil {
		col.Close()
		return nil, fmt.Errorf("open cgroup %s: %w", cgroupPath, err)
	}
	col.cgroupFile = f

	// Attach cgroup/sock_create
	if col.objs.OnSockCreate != nil {
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  ebpf.AttachCGroupInetSockCreate,
			Program: col.objs.OnSockCreate,
		})
		if err != nil {
			col.Close()
			return nil, fmt.Errorf("attach sock_create: %w", err)
		}
		col.sockCreateLink = l
	}

	// TCP_LISTEN_CB is a syscall-context ownership refresh, not a handshake
	// PID sample. Treat attachment failure as fatal to avoid silent omissions.
	sockOps, err := link.AttachCgroup(link.CgroupOptions{
		Path: cgroupPath, Attach: ebpf.AttachCGroupSockOps, Program: col.objs.OnSockops,
	})
	if err != nil {
		col.Close()
		return nil, fmt.Errorf("attach sockops: %w", err)
	}
	col.sockOpsLink = sockOps

	// Attach cgroup_skb/ingress
	if col.objs.OnIngress != nil {
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  ebpf.AttachCGroupInetIngress,
			Program: col.objs.OnIngress,
		})
		if err != nil {
			col.Close()
			return nil, fmt.Errorf("attach ingress: %w", err)
		}
		col.ingressLink = l
	}

	// Attach cgroup_skb/egress
	if col.objs.OnEgress != nil {
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  ebpf.AttachCGroupInetEgress,
			Program: col.objs.OnEgress,
		})
		if err != nil {
			col.Close()
			return nil, fmt.Errorf("attach egress: %w", err)
		}
		col.egressLink = l
	}

	return col, nil
}

// DrainDeltas differences cumulative snapshots without deleting active counters.
func (c *BPFCollector) DrainDeltas() ([]FlowDelta, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, errors.New("collector closed")
	}

	var deltas []FlowDelta
	var key MonitoFlowKey
	var metrics MonitoFlowMetrics

	// Commit snapshots only after a complete iteration. Kernel counters remain
	// cumulative, so a failed read can be retried without dropping any bytes.
	next := make(map[MonitoFlowKey]MonitoFlowMetrics)
	iter := c.objs.FlowStats.Iterate()
	for iter.Next(&key, &metrics) {
		if _, seen := next[key]; seen {
			continue
		}
		next[key] = metrics
		delta := counterDelta(metrics, c.previous[key])
		if delta.RxBytes == 0 && delta.TxBytes == 0 {
			continue
		}
		deltas = append(deltas, FlowDelta{
			PID: key.Pid, Category: TrafficCategory(key.Category),
			RxBytes: delta.RxBytes, TxBytes: delta.TxBytes,
			RxPackets: delta.RxPackets, TxPackets: delta.TxPackets,
		})
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate flow_stats: %w", err)
	}
	// Concurrent insertions/LRU churn can make iteration miss an existing key.
	// Retain its prior baseline if the same generation is still present.
	for key, previous := range c.previous {
		if _, seen := next[key]; seen {
			continue
		}
		var current MonitoFlowMetrics
		err := c.objs.FlowStats.Lookup(&key, &current)
		if err == nil && current.Generation == previous.Generation {
			next[key] = previous
		}
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, fmt.Errorf("verify flow snapshot: %w", err)
		}
	}
	c.previous = next

	return deltas, nil
}

// counterDelta handles LRU eviction/recreation as a fresh cumulative counter.
func counterDelta(current, previous MonitoFlowMetrics) MonitoFlowMetrics {
	if current.Generation != previous.Generation {
		return current
	}
	current.RxBytes -= previous.RxBytes
	current.TxBytes -= previous.TxBytes
	current.RxPackets -= previous.RxPackets
	current.TxPackets -= previous.TxPackets
	return current
}

// StopAccounting detaches packet and creation hooks before the final snapshot.
// Map handles remain open until Close, allowing shutdown to persist that snapshot.
func (c *BPFCollector) StopAccounting() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var errs []error
	for _, hook := range []*link.Link{&c.ingressLink, &c.egressLink, &c.sockOpsLink, &c.sockCreateLink} {
		if *hook != nil {
			if err := (*hook).Close(); err != nil {
				errs = append(errs, err)
			} else {
				*hook = nil
			}
		}
	}
	return errors.Join(errs...)
}

// LookupPIDMetadata checks if a PID's metadata is stored in the kernel LRU map
func (c *BPFCollector) LookupPIDMetadata(pid uint32) (*MonitoProcInfo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed || c.objs.PidMetadata == nil {
		return nil, false
	}

	var info MonitoProcInfo
	if err := c.objs.PidMetadata.Lookup(&pid, &info); err == nil {
		return &info, true
	}
	return nil, false
}

// ReadCounters retrieves diagnostic and drop counters from BPF
func (c *BPFCollector) ReadCounters() DiagnosticCounters {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed || c.objs.Counters == nil {
		return DiagnosticCounters{}
	}

	var diag DiagnosticCounters
	var idx uint32

	idx = 0
	_ = c.objs.Counters.Lookup(&idx, &diag.TotalIngressPackets)
	idx = 1
	_ = c.objs.Counters.Lookup(&idx, &diag.TotalEgressPackets)
	idx = 2
	_ = c.objs.Counters.Lookup(&idx, &diag.SocketsRegistered)
	idx = 3
	_ = c.objs.Counters.Lookup(&idx, &diag.UnattributedIngress)
	idx = 4
	_ = c.objs.Counters.Lookup(&idx, &diag.UnattributedEgress)
	idx = 5
	_ = c.objs.Counters.Lookup(&idx, &diag.MapErrors)

	return diag
}

// Close detaches links and releases all BPF resources
func (c *BPFCollector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	var errs []error
	if c.sockCreateLink != nil {
		if err := c.sockCreateLink.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.sockOpsLink != nil {
		if err := c.sockOpsLink.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.ingressLink != nil {
		if err := c.ingressLink.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.egressLink != nil {
		if err := c.egressLink.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.cgroupFile != nil {
		_ = c.cgroupFile.Close()
	}

	if err := c.objs.Close(); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing BPF collector: %v", errs)
	}
	return nil
}
