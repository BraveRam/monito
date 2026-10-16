#include <linux/bpf.h>
#include "headers/bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct flow_key {
    __u32 pid;
    __u8 category;
    __u8 pad[3];
};

struct flow_metrics {
    __u64 rx_bytes;
    __u64 tx_bytes;
    __u64 rx_packets;
    __u64 tx_packets;
};

struct proc_info {
    __u32 pid;
    __u32 tgid;
    __u64 cgroup_id;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64); // socket cookie
    __type(value, struct proc_info);
} sock_owners SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct flow_key);
    __type(value, struct flow_metrics);
} flow_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

SEC("cgroup/sock_create")
int on_sock_create(struct bpf_sock *sk) {
    __u64 cookie = bpf_get_socket_cookie(sk);
    if (!cookie) return 1;

    struct proc_info proc = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    proc.pid = (__u32)(pid_tgid >> 32);
    proc.tgid = (__u32)pid_tgid;
    proc.cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&proc.comm, sizeof(proc.comm));

    bpf_map_update_elem(&sock_owners, &cookie, &proc, BPF_ANY);

    __u32 idx = 1; // Sockets created
    __u64 *cnt = bpf_map_lookup_elem(&counters, &idx);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    }
    return 1;
}

SEC("cgroup_skb/ingress")
int on_ingress(struct __sk_buff *skb) {
    __u32 bytes = skb->len;
    __u64 cookie = bpf_get_socket_cookie(skb);

    __u32 pid = 0;
    if (cookie) {
        struct proc_info *proc = bpf_map_lookup_elem(&sock_owners, &cookie);
        if (proc) {
            pid = proc->pid;
        }
    }

    __u8 cat = 3; // Unknown
    if (skb->ingress_ifindex == 1) {
        cat = 0; // Loopback
    } else {
        cat = 2; // External
    }

    struct flow_key key = {
        .pid = pid,
        .category = cat,
        .pad = {0, 0, 0},
    };

    struct flow_metrics *metrics = bpf_map_lookup_elem(&flow_stats, &key);
    if (metrics) {
        __sync_fetch_and_add(&metrics->rx_bytes, bytes);
        __sync_fetch_and_add(&metrics->rx_packets, 1);
    } else {
        struct flow_metrics init = {
            .rx_bytes = bytes,
            .rx_packets = 1,
        };
        bpf_map_update_elem(&flow_stats, &key, &init, BPF_NOEXIST);
    }

    __u32 total_idx = 0;
    __u64 *total = bpf_map_lookup_elem(&counters, &total_idx);
    if (total) {
        __sync_fetch_and_add(total, 1);
    }

    return 1;
}

SEC("cgroup_skb/egress")
int on_egress(struct __sk_buff *skb) {
    __u32 bytes = skb->len;
    __u64 cookie = bpf_get_socket_cookie(skb);

    __u32 pid = 0;
    if (cookie) {
        struct proc_info *proc = bpf_map_lookup_elem(&sock_owners, &cookie);
        if (proc) {
            pid = proc->pid;
        }
    }

    __u8 cat = 3; // Unknown
    if (skb->ifindex == 1) {
        cat = 0; // Loopback
    } else {
        cat = 2; // External
    }

    struct flow_key key = {
        .pid = pid,
        .category = cat,
        .pad = {0, 0, 0},
    };

    struct flow_metrics *metrics = bpf_map_lookup_elem(&flow_stats, &key);
    if (metrics) {
        __sync_fetch_and_add(&metrics->tx_bytes, bytes);
        __sync_fetch_and_add(&metrics->tx_packets, 1);
    } else {
        struct flow_metrics init = {
            .tx_bytes = bytes,
            .tx_packets = 1,
        };
        bpf_map_update_elem(&flow_stats, &key, &init, BPF_NOEXIST);
    }

    __u32 total_idx = 0;
    __u64 *total = bpf_map_lookup_elem(&counters, &total_idx);
    if (total) {
        __sync_fetch_and_add(total, 1);
    }

    return 1;
}
