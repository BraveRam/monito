#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include "headers/bpf_helpers.h"
#include "headers/bpf_tracing.h"
#include "headers/bpf_endian.h"

struct sock;

char __license[] SEC("license") = "Dual MIT/GPL";

#define AF_INET 2
#define AF_INET6 10

#define CAT_LOOPBACK 0
#define CAT_PRIVATE  1
#define CAT_EXTERNAL 2
#define CAT_UNKNOWN  3

// Flow key for aggregated metrics
struct flow_key {
    __u32 pid;
    __u8 category;
    __u8 pad[3];
};

// Aggregated byte and packet counters
struct flow_metrics {
    __u64 generation;
    __u64 rx_bytes;
    __u64 tx_bytes;
    __u64 rx_packets;
    __u64 tx_packets;
};

// Process metadata captured at socket creation
struct proc_info {
    __u32 pid;
    __u32 tgid;
    __u64 cgroup_id;
    char comm[16];
};

// Socket-local ownership is copied from a listening socket to its accepted
// children by the kernel. Never infer an owner from handshake softirq context.
struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_CLONE);
    __type(key, int);
    __type(value, struct proc_info);
} sock_owners SEC(".maps");

// Map: pid -> proc_info for short-lived process metadata retention (LRU hash)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct proc_info);
} pid_metadata SEC(".maps");

// Map: flow_key -> flow_metrics (Kernel-side aggregation map)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct flow_key);
    __type(value, struct flow_metrics);
} flow_stats SEC(".maps");

// Map: system diagnostic and capacity counters
// 0: Total ingress packets
// 1: Total egress packets
// 2: Total sockets registered
// 3: Unattributed ingress packets
// 4: Unattributed egress packets
// 5: Map insertion / capacity errors
// 6: Existing sockets recovered at application IO
// 7: Ownership recovery allocation failures
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

static __always_inline void bump_counter(__u32 idx) {
    __u64 *cnt = bpf_map_lookup_elem(&counters, &idx);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    }
}

// Hook 1: Socket creation (cgroup/sock_create)
SEC("cgroup/sock_create")
int on_sock_create(struct bpf_sock *sk) {
    struct proc_info proc = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    proc.pid = (__u32)(pid_tgid >> 32);
    proc.tgid = proc.pid;
    proc.cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&proc.comm, sizeof(proc.comm));

    if (!bpf_sk_storage_get(&sock_owners, sk, &proc, BPF_SK_STORAGE_GET_F_CREATE))
        bump_counter(5);
    if (proc.pid > 0) {
        bpf_map_update_elem(&pid_metadata, &proc.pid, &proc, BPF_ANY);
    }

    bump_counter(2); // Sockets registered
    return 1;
}

// listen() runs in the application context. Refresh listener ownership here
// before the kernel clones it for incoming connections; never use the current
// PID from PASSIVE_ESTABLISHED_CB (which runs on the receive path).
SEC("sockops")
int on_sockops(struct bpf_sock_ops *ctx) {
    if (ctx->op != BPF_SOCK_OPS_TCP_LISTEN_CB) return 1;
    struct bpf_sock *sk = ctx->sk;
    if (!sk) return 1;
    struct proc_info proc = {};
    proc.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    proc.tgid = proc.pid;
    proc.cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&proc.comm, sizeof(proc.comm));
    struct proc_info *owner = bpf_sk_storage_get(&sock_owners, sk, &proc, BPF_SK_STORAGE_GET_F_CREATE);
    if (owner) *owner = proc;
    else bump_counter(5);
    if (proc.pid) bpf_map_update_elem(&pid_metadata, &proc.pid, &proc, BPF_ANY);
    return 1;
}

// tcp/udp sendmsg and recvmsg run in the application's syscall context.
// This recovers pre-existing sockets without reading or duplicating another
// process's file descriptors, and never changes a known socket owner.
SEC("fentry/tcp_sendmsg")
int BPF_PROG(on_socket_io, struct sock *sk) {
    if (!sk) return 0;
    if (bpf_sk_storage_get(&sock_owners, sk, 0, 0)) return 0;
    struct proc_info proc = {};
    proc.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (!proc.pid) return 0;
    proc.tgid = proc.pid;
    proc.cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&proc.comm, sizeof(proc.comm));
    struct proc_info *owner = bpf_sk_storage_get(&sock_owners, sk, &proc, BPF_SK_STORAGE_GET_F_CREATE);
    if (owner) {
        bpf_map_update_elem(&pid_metadata, &proc.pid, &proc, BPF_ANY);
        bump_counter(6);
    } else bump_counter(7);
    return 0;
}

// Cumulative counters are never reset by userspace. A generation distinguishes
// a newly allocated LRU entry from an older snapshot of the same PID/category.
static __always_inline void account(struct flow_key *key, __u32 bytes, int ingress) {
    struct flow_metrics *metrics = bpf_map_lookup_elem(&flow_stats, key);
    if (!metrics) {
        struct flow_metrics init = { .generation = bpf_ktime_get_ns() };
        int err = bpf_map_update_elem(&flow_stats, key, &init, BPF_NOEXIST);
        if (err && err != -17 /* EEXIST: another CPU created the entry */) {
            bump_counter(5);
            return;
        }
        metrics = bpf_map_lookup_elem(&flow_stats, key);
        if (!metrics) {
            bump_counter(5);
            return;
        }
    }
    if (ingress) {
        __sync_fetch_and_add(&metrics->rx_bytes, bytes);
        __sync_fetch_and_add(&metrics->rx_packets, 1);
    } else {
        __sync_fetch_and_add(&metrics->tx_bytes, bytes);
        __sync_fetch_and_add(&metrics->tx_packets, 1);
    }
}

static __always_inline __u32 socket_pid(struct __sk_buff *skb, __u32 unattributed) {
    struct bpf_sock *sk = skb->sk;
    if (sk) {
        sk = bpf_sk_fullsock(sk);
        if (sk) {
            struct proc_info *proc = bpf_sk_storage_get(&sock_owners, sk, 0, 0);
            if (proc) return proc->pid;
        }
    }
    bump_counter(unattributed);
    return 0;
}

static __always_inline __u8 classify_ipv4(__u32 net_ip) {
    __u32 host_ip = bpf_ntohl(net_ip);

    // Loopback: 127.0.0.0/8
    if ((host_ip >> 24) == 127) {
        return CAT_LOOPBACK;
    }

    // RFC1918 Private ranges:
    // 10.0.0.0/8
    if ((host_ip >> 24) == 10) {
        return CAT_PRIVATE;
    }
    // 172.16.0.0/12
    if ((host_ip >> 20) == ((172 << 4) | 1)) {
        return CAT_PRIVATE;
    }
    // 192.168.0.0/16
    if ((host_ip >> 16) == ((192 << 8) | 168)) {
        return CAT_PRIVATE;
    }

    // Link-local: 169.254.0.0/16
    if ((host_ip >> 16) == ((169 << 8) | 254)) {
        return CAT_PRIVATE;
    }

    // Multicast: 224.0.0.0/4
    if ((host_ip >> 28) == 14) {
        return CAT_PRIVATE;
    }

    // Broadcast: 255.255.255.255
    if (host_ip == 0xFFFFFFFF) {
        return CAT_PRIVATE;
    }

    // CGNAT / Tailscale: 100.64.0.0/10
    if ((host_ip >> 22) == ((100 << 2) | 1)) {
        return CAT_PRIVATE;
    }

    return CAT_EXTERNAL;
}

static __always_inline __u8 classify_ipv6(const struct in6_addr *addr) {
    // Loopback: ::1
    if (addr->in6_u.u6_addr32[0] == 0 &&
        addr->in6_u.u6_addr32[1] == 0 &&
        addr->in6_u.u6_addr32[2] == 0 &&
        addr->in6_u.u6_addr32[3] == bpf_htonl(1)) {
        return CAT_LOOPBACK;
    }

    __u16 first_word = bpf_ntohs(addr->in6_u.u6_addr16[0]);

    // Link-local: fe80::/10
    if ((first_word & 0xffc0) == 0xfe80) {
        return CAT_PRIVATE;
    }

    // Unique Local Address (ULA): fc00::/7
    if ((first_word & 0xfe00) == 0xfc00) {
        return CAT_PRIVATE;
    }

    // Multicast: ff00::/8
    if ((first_word & 0xff00) == 0xff00) {
        return CAT_PRIVATE;
    }

    return CAT_EXTERNAL;
}

// Hook 3: Ingress packet accounting (cgroup_skb/ingress)
SEC("cgroup_skb/ingress")
int on_ingress(struct __sk_buff *skb) {
    __u32 bytes = skb->len;
    __u32 pid = socket_pid(skb, 3);

    __u8 cat = CAT_UNKNOWN;
    if (skb->ingress_ifindex == 1) {
        cat = CAT_LOOPBACK;
    } else {
        void *data = (void *)(long)skb->data;
        void *data_end = (void *)(long)skb->data_end;

        if (skb->family == AF_INET) {
            if (data + sizeof(struct iphdr) <= data_end) {
                struct iphdr *iph = data;
                cat = classify_ipv4(iph->saddr);
            }
        } else if (skb->family == AF_INET6) {
            if (data + sizeof(struct ipv6hdr) <= data_end) {
                struct ipv6hdr *ip6h = data;
                cat = classify_ipv6(&ip6h->saddr);
            }
        }
    }

    struct flow_key key = {
        .pid = pid,
        .category = cat,
        .pad = {0, 0, 0},
    };

    account(&key, bytes, 1);

    bump_counter(0);
    return 1;
}

// Hook 4: Egress packet accounting (cgroup_skb/egress)
SEC("cgroup_skb/egress")
int on_egress(struct __sk_buff *skb) {
    __u32 bytes = skb->len;
    __u32 pid = socket_pid(skb, 4);

    __u8 cat = CAT_UNKNOWN;
    if (skb->ifindex == 1) {
        cat = CAT_LOOPBACK;
    } else {
        void *data = (void *)(long)skb->data;
        void *data_end = (void *)(long)skb->data_end;

        if (skb->family == AF_INET) {
            if (data + sizeof(struct iphdr) <= data_end) {
                struct iphdr *iph = data;
                cat = classify_ipv4(iph->daddr);
            }
        } else if (skb->family == AF_INET6) {
            if (data + sizeof(struct ipv6hdr) <= data_end) {
                struct ipv6hdr *ip6h = data;
                cat = classify_ipv6(&ip6h->daddr);
            }
        }
    }

    struct flow_key key = {
        .pid = pid,
        .category = cat,
        .pad = {0, 0, 0},
    };

    account(&key, bytes, 0);

    bump_counter(1);
    return 1;
}
