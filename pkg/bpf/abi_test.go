package bpf

import (
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// Parse the committed Rust ELF without privileges. Catch ABI drift before a
// daemon can read misaligned counters or silently lose socket inheritance.
func TestEmbeddedCollectorABI(t *testing.T) {
	spec, err := LoadMonito()
	if err != nil {
		t.Fatal(err)
	}
	if spec.ByteOrder != binary.LittleEndian {
		t.Fatal("collector must target little-endian BPF")
	}
	for name, want := range map[string]struct {
		kind                        ebpf.MapType
		key, value, capacity, flags uint32
	}{
		"sock_owners":  {ebpf.SkStorage, 4, 32, 0, 0x201},
		"pid_metadata": {ebpf.LRUHash, 4, 32, 16384, 0},
		"flow_stats":   {ebpf.LRUHash, 8, 40, 16384, 0},
		"counters":     {ebpf.Array, 4, 8, 8, 0},
	} {
		m := spec.Maps[name]
		if m == nil {
			t.Fatalf("missing map %s", name)
		}
		if m.Type != want.kind || m.KeySize != want.key || m.ValueSize != want.value || m.MaxEntries != want.capacity || m.Flags != want.flags {
			t.Errorf("%s ABI changed: %+v", name, m)
		}
	}
	for _, check := range []struct {
		typ     btf.Type
		fields  []string
		offsets []btf.Bits
	}{
		{spec.Maps["flow_stats"].Key, []string{"pid", "category", "pad"}, []btf.Bits{0, 32, 40}},
		{spec.Maps["flow_stats"].Value, []string{"generation", "rx_bytes", "tx_bytes", "rx_packets", "tx_packets"}, []btf.Bits{0, 64, 128, 192, 256}},
		{spec.Maps["sock_owners"].Value, []string{"pid", "tgid", "cgroup_id", "comm"}, []btf.Bits{0, 32, 64, 128}},
	} {
		s, ok := btf.UnderlyingType(check.typ).(*btf.Struct)
		if !ok || len(s.Members) != len(check.fields) {
			t.Fatalf("unexpected BTF layout: %v", check.typ)
		}
		for i, field := range check.fields {
			if s.Members[i].Name != field || s.Members[i].Offset != check.offsets[i] {
				t.Errorf("wrong field layout: %+v", s.Members[i])
			}
		}
	}
	for name, want := range map[string]struct {
		kind   ebpf.ProgramType
		attach ebpf.AttachType
		target string
	}{
		"on_sock_create": {ebpf.CGroupSock, ebpf.AttachCGroupInetSockCreate, ""},
		"on_sockops":     {ebpf.SockOps, ebpf.AttachCGroupSockOps, ""},
		"on_socket_io":   {ebpf.Tracing, ebpf.AttachTraceFEntry, "tcp_sendmsg"},
		"on_ingress":     {ebpf.CGroupSKB, ebpf.AttachNone, ""},
		"on_egress":      {ebpf.CGroupSKB, ebpf.AttachCGroupInetEgress, ""},
	} {
		p := spec.Programs[name]
		if p == nil {
			t.Fatalf("missing program %s", name)
		}
		if p.Type != want.kind || p.AttachType != want.attach || p.AttachTo != want.target || p.License != "Dual MIT/GPL" {
			t.Errorf("wrong program metadata: %+v", p)
		}
		// All collector helpers are intentionally inlined. In particular, LLVM
		// must not emit global memcpy/memset functions: the kernel cannot
		// verify their pointer-returning signatures as global BPF functions.
		for _, instruction := range p.Instructions {
			if instruction.IsFunctionCall() {
				t.Errorf("%s contains an unexpected BPF subprogram call: %v", name, instruction)
			}
		}
		if name == "on_ingress" || name == "on_egress" {
			atomic := false
			for _, instruction := range p.Instructions {
				if instruction.OpCode.Mode() == asm.XAddMode {
					atomic = true
				}
				if instruction.IsBuiltinCall() && instruction.Constant == int64(asm.FnGetCurrentPidTgid) {
					t.Errorf("%s guesses packet owner from the current task", name)
				}
			}
			if !atomic {
				t.Errorf("%s lacks atomic accounting", name)
			}
		}
	}
}
