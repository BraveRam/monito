package bpf

import (
	"fmt"
	"math"
	"os"
	"syscall"

	"github.com/cilium/ebpf/btf"
)

// NamespaceScope is initialized before hooks attach. Offsets come from this
// kernel's BTF, not build-machine layouts (Ubuntu 6.8 and Fedora differ).
type NamespaceScope struct {
	SocketNetOffset uint32
	NetInumOffset   uint32
	Inum            uint32
	Pad             uint32
}

func namespaceScope() (NamespaceScope, error) {
	info, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return NamespaceScope{}, err
	}
	ino := info.Sys().(*syscall.Stat_t).Ino
	if ino == 0 || ino > math.MaxUint32 {
		return NamespaceScope{}, fmt.Errorf("invalid network namespace inode %d", ino)
	}
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return NamespaceScope{}, fmt.Errorf("read network namespace BTF: %w", err)
	}
	var socket, network *btf.Struct
	if err := spec.TypeByName("sock", &socket); err != nil {
		return NamespaceScope{}, err
	}
	if err := spec.TypeByName("net", &network); err != nil {
		return NamespaceScope{}, err
	}
	netOffset, netType, err := memberOffset(socket, "__sk_common", "skc_net", "net")
	if err != nil {
		return NamespaceScope{}, err
	}
	if _, ok := btf.UnderlyingType(netType).(*btf.Pointer); !ok {
		return NamespaceScope{}, fmt.Errorf("socket network namespace is not a pointer")
	}
	inumOffset, inumType, err := memberOffset(network, "ns", "inum")
	if err != nil {
		return NamespaceScope{}, err
	}
	if typ, ok := btf.UnderlyingType(inumType).(*btf.Int); !ok || typ.Size != 4 {
		return NamespaceScope{}, fmt.Errorf("network namespace inode is not a 32-bit integer")
	}
	return NamespaceScope{SocketNetOffset: netOffset, NetInumOffset: inumOffset, Inum: uint32(ino)}, nil
}

func memberOffset(typ btf.Type, path ...string) (uint32, btf.Type, error) {
	var offset uint32
	for _, name := range path {
		s, ok := btf.UnderlyingType(typ).(*btf.Struct)
		if !ok {
			return 0, nil, fmt.Errorf("BTF field %s has no containing struct", name)
		}
		found := false
		for _, member := range s.Members {
			if member.Name == name && member.BitfieldSize == 0 && member.Offset%8 == 0 {
				offset += uint32(member.Offset / 8)
				typ, found = member.Type, true
				break
			}
		}
		if !found {
			return 0, nil, fmt.Errorf("missing byte-aligned BTF field %s.%s", s.Name, name)
		}
	}
	return offset, typ, nil
}
