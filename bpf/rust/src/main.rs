#![no_std]
#![no_main]
#![feature(core_intrinsics)]
#![allow(internal_features)]
#![allow(non_upper_case_globals)] // Map symbols are part of the Go loader ABI.

use aya_ebpf::{
    bindings::{
        __sk_buff, BPF_ANY, BPF_F_CLONE, BPF_F_NO_PREALLOC, BPF_NOEXIST,
        BPF_SK_STORAGE_GET_F_CREATE,
    },
    btf_maps::{Array, LruHashMap},
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_ktime_get_ns,
        bpf_probe_read_kernel, bpf_sk_fullsock, bpf_sk_storage_get,
        generated::bpf_get_current_comm,
    },
    macros::{btf_map, cgroup_skb, cgroup_sock, fentry},
    programs::{FEntryContext, SkBuffContext, SockContext},
};
use core::{
    ffi::c_void,
    intrinsics::{AtomicOrdering, atomic_xadd},
    mem::MaybeUninit,
    ptr,
};
use monito_ebpf::{
    FlowKey, FlowMetrics, LOOPBACK, ProcInfo, UNKNOWN, classify_ipv4, classify_ipv6,
};

#[unsafe(no_mangle)]
#[unsafe(link_section = "license")]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

// Aya's SkStorage does not expose BPF_F_CLONE. Use the same BTF map
// declaration as the C collector so accepted TCP sockets inherit ownership.
#[repr(C)]
struct SocketStorage {
    r#type: *const [i32; 24], // BPF_MAP_TYPE_SK_STORAGE
    map_flags: *const [i32; (BPF_F_NO_PREALLOC | BPF_F_CLONE) as usize],
    key: *const i32,
    value: *const ProcInfo,
}
// The loader replaces this immutable definition with a kernel map reference.
unsafe impl Sync for SocketStorage {}

#[unsafe(no_mangle)]
#[unsafe(link_section = ".maps")]
static sock_owners: SocketStorage = SocketStorage {
    r#type: ptr::null(),
    map_flags: ptr::null(),
    key: ptr::null(),
    value: ptr::null(),
};

#[btf_map]
static pid_metadata: LruHashMap<u32, ProcInfo, 16384> = LruHashMap::new();
#[btf_map]
static flow_stats: LruHashMap<FlowKey, FlowMetrics, 16384> = LruHashMap::new();
#[btf_map]
static counters: Array<u64, 10> = Array::new();

#[repr(C)]
struct NamespaceScope {
    socket_net_offset: u32,
    net_inum_offset: u32,
    inum: u32,
    pad: u32,
}

#[btf_map]
static accounting_scope: Array<NamespaceScope, 1> = Array::new();

#[inline(always)]
unsafe fn in_accounting_namespace(skb: *mut __sk_buff) -> bool {
    let Some(scope) = accounting_scope.get(0) else {
        bump(9);
        return false;
    };
    // Only synthetic, socketless BPF_PROG_TEST_RUN accounting tests disable
    // the boundary. The production loader always supplies a nonzero inode.
    if scope.inum == 0 {
        return true;
    }
    let socket = unsafe { (*skb).__bindgen_anon_2.sk };
    if socket.is_null() {
        bump(9);
        return false;
    }
    // get_netns_cookie is not available to cgroup_skb on Linux 6.8. Read
    // the socket's own namespace using offsets validated against live BTF.
    // Never use the current task: packet processing can run in softirq context.
    // sock_common verifier pointers forbid pointer arithmetic. Read the raw
    // address from a stack slot before applying the live-BTF offset; both
    // kernel dereferences remain fault-safe probe reads.
    let socket_address = socket as usize;
    let Ok(socket_address) = (unsafe { bpf_probe_read_kernel(&socket_address) }) else {
        bump(9);
        return false;
    };
    let net = unsafe {
        bpf_probe_read_kernel((socket_address + scope.socket_net_offset as usize) as *const usize)
    };
    let Ok(net) = net else {
        bump(9);
        return false;
    };
    if net == 0 {
        bump(9);
        return false;
    }
    let inum = unsafe {
        bpf_probe_read_kernel(
            (net as *const u8)
                .add(scope.net_inum_offset as usize)
                .cast::<u32>(),
        )
    };
    let Ok(inum) = inum else {
        bump(9);
        return false;
    };
    if inum != scope.inum {
        bump(8);
        return false;
    }
    true
}

#[inline(always)]
unsafe fn add(value: *mut u64, delta: u64) {
    // Rust's BPF target does not expose AtomicU64::fetch_add.
    // Use the intrinsic to emit the supported XADD instruction.
    // Values are 8-byte aligned by the kernel. Shared counters must use atomic
    // updates because different CPUs can account for the same socket/process.
    unsafe {
        atomic_xadd::<_, _, { AtomicOrdering::Relaxed }>(value, delta);
    }
}

#[inline(always)]
fn bump(index: u32) {
    if let Some(counter) = counters.get_ptr_mut(index) {
        unsafe {
            add(counter, 1);
        }
    }
}

#[inline(always)]
unsafe fn current_process(proc: *mut ProcInfo) {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    // Explicit volatile stores prevent LLVM from outlining small structure
    // initialization/copies into libc memory calls rejected by the verifier.
    // ProcInfo has no padding, and its comm field is aligned to eight bytes.
    unsafe {
        ptr::write_volatile(ptr::addr_of_mut!((*proc).pid), pid);
        ptr::write_volatile(ptr::addr_of_mut!((*proc).tgid), pid);
        ptr::write_volatile(
            ptr::addr_of_mut!((*proc).cgroup_id),
            bpf_get_current_cgroup_id(),
        );
        let comm = ptr::addr_of_mut!((*proc).comm).cast::<u64>();
        ptr::write_volatile(comm, 0);
        ptr::write_volatile(comm.add(1), 0);
        bpf_get_current_comm(comm.cast(), 16);
    }
}

#[inline(always)]
unsafe fn owner(socket: *mut c_void, initial: *mut ProcInfo, flags: u64) -> *mut ProcInfo {
    unsafe {
        bpf_sk_storage_get(
            ptr::addr_of!(sock_owners).cast_mut().cast(),
            socket,
            initial.cast(),
            flags,
        )
    }
    .cast()
}

#[inline(always)]
fn remember(proc: &ProcInfo) {
    if proc.pid != 0 {
        let _ = pid_metadata.insert(&proc.pid, proc, BPF_ANY as u64);
    }
}

#[cgroup_sock(sock_create)]
pub fn on_sock_create(ctx: SockContext) -> i32 {
    let mut proc = MaybeUninit::<ProcInfo>::uninit();
    unsafe {
        current_process(proc.as_mut_ptr());
    }
    if unsafe {
        owner(
            ctx.sock.cast(),
            proc.as_mut_ptr(),
            BPF_SK_STORAGE_GET_F_CREATE as u64,
        )
    }
    .is_null()
    {
        bump(5);
    }
    remember(unsafe { proc.assume_init_ref() });
    bump(2);
    1
}

// Trace listen in process context: Linux 6.8 sock_ops programs cannot call
// get_current_pid_tgid/get_current_comm. Refresh before accepted sockets clone
// listener storage, including when a child listens on an inherited socket.
#[fentry(function = "inet_csk_listen_start")]
pub fn on_socket_listen(ctx: FEntryContext) -> u32 {
    let socket: *mut c_void = ctx.arg(0);
    if socket.is_null() {
        return 0;
    }
    let mut proc = MaybeUninit::<ProcInfo>::uninit();
    unsafe {
        current_process(proc.as_mut_ptr());
    }
    let stored = unsafe {
        owner(
            socket.cast(),
            proc.as_mut_ptr(),
            BPF_SK_STORAGE_GET_F_CREATE as u64,
        )
    };
    if stored.is_null() {
        bump(5);
    } else {
        unsafe {
            // Fixed-width stores keep the listener refresh free of memmove.
            let src = proc.as_ptr().cast::<u64>();
            let dst = stored.cast::<u64>();
            ptr::write_volatile(dst, ptr::read_volatile(src));
            ptr::write_volatile(dst.add(1), ptr::read_volatile(src.add(1)));
            ptr::write_volatile(dst.add(2), ptr::read_volatile(src.add(2)));
            ptr::write_volatile(dst.add(3), ptr::read_volatile(src.add(3)));
        }
    }
    remember(unsafe { proc.assume_init_ref() });
    0
}

#[fentry(function = "tcp_sendmsg")]
pub fn on_socket_io(ctx: FEntryContext) -> u32 {
    let socket: *mut c_void = ctx.arg(0);
    if socket.is_null() || !unsafe { owner(socket, ptr::null_mut(), 0) }.is_null() {
        return 0;
    }
    let mut proc = MaybeUninit::<ProcInfo>::uninit();
    unsafe {
        current_process(proc.as_mut_ptr());
    }
    if unsafe { proc.assume_init_ref().pid } == 0 {
        return 0;
    }
    if unsafe {
        owner(
            socket,
            proc.as_mut_ptr(),
            BPF_SK_STORAGE_GET_F_CREATE as u64,
        )
    }
    .is_null()
    {
        bump(7);
    } else {
        remember(unsafe { proc.assume_init_ref() });
        bump(6);
    }
    0
}

#[inline(always)]
unsafe fn socket_pid(skb: *mut __sk_buff, unattributed: u32) -> u32 {
    let socket = unsafe { (*skb).__bindgen_anon_2.sk };
    if !socket.is_null() {
        let full = unsafe { bpf_sk_fullsock(socket) };
        if !full.is_null() {
            let proc = unsafe { owner(full.cast(), ptr::null_mut(), 0) };
            if !proc.is_null() {
                return unsafe { (*proc).pid };
            }
        }
    }
    bump(unattributed);
    0
}

#[inline(always)]
fn account(key: &FlowKey, bytes: u32, ingress: bool) {
    let mut metrics = flow_stats.get_ptr_mut(key);
    if metrics.is_none() {
        let mut initial = MaybeUninit::<FlowMetrics>::uninit();
        let words = initial.as_mut_ptr().cast::<u64>();
        unsafe {
            ptr::write_volatile(words, bpf_ktime_get_ns());
            ptr::write_volatile(words.add(1), 0);
            ptr::write_volatile(words.add(2), 0);
            ptr::write_volatile(words.add(3), 0);
            ptr::write_volatile(words.add(4), 0);
        }
        if let Err(error) = flow_stats.insert(
            key,
            unsafe { initial.assume_init_ref() },
            BPF_NOEXIST as u64,
        ) {
            if error != -17 {
                bump(5);
                return;
            } // Another CPU may have won insertion.
        }
        metrics = flow_stats.get_ptr_mut(key);
    }
    let Some(metrics) = metrics else {
        bump(5);
        return;
    };
    unsafe {
        if ingress {
            add(ptr::addr_of_mut!((*metrics).rx_bytes), bytes as u64);
            add(ptr::addr_of_mut!((*metrics).rx_packets), 1);
        } else {
            add(ptr::addr_of_mut!((*metrics).tx_bytes), bytes as u64);
            add(ptr::addr_of_mut!((*metrics).tx_packets), 1);
        }
    }
}

#[inline(always)]
unsafe fn category(skb: *mut __sk_buff, ingress: bool) -> u8 {
    let interface = unsafe {
        if ingress {
            (*skb).ingress_ifindex
        } else {
            (*skb).ifindex
        }
    };
    if interface == 1 {
        return LOOPBACK;
    }
    let data = unsafe { (*skb).data as usize };
    let end = unsafe { (*skb).data_end as usize };
    let family = unsafe { (*skb).family };
    if family == 2 && data + 20 <= end {
        let offset = if ingress { 12 } else { 16 };
        let ip = unsafe { ptr::read_unaligned((data + offset) as *const u32) };
        classify_ipv4(u32::from_be(ip))
    } else if family == 10 && data + 40 <= end {
        let offset = if ingress { 8 } else { 24 };
        let ip = unsafe { ptr::read_unaligned((data + offset) as *const [u8; 16]) };
        classify_ipv6(ip)
    } else {
        UNKNOWN
    }
}

#[repr(C, align(8))]
struct AlignedKey(MaybeUninit<FlowKey>);

#[inline(always)]
fn packet(ctx: SkBuffContext, ingress: bool) -> i32 {
    if !unsafe { in_accounting_namespace(ctx.skb.skb) } {
        return 1;
    }
    // Packet hooks only consult socket-local ownership; the current task may
    // be unrelated softirq context and must never be used as the packet owner.
    let pid = unsafe { socket_pid(ctx.skb.skb, if ingress { 3 } else { 4 }) };
    let category = unsafe { category(ctx.skb.skb, ingress) };
    let mut key = AlignedKey(MaybeUninit::<FlowKey>::uninit());
    // The embedded object targets little-endian BPF: this initializes pid,
    // category, and all three padding bytes with a single aligned store.
    unsafe {
        ptr::write_volatile(
            key.0.as_mut_ptr().cast::<u64>(),
            pid as u64 | ((category as u64) << 32),
        );
        account(key.0.assume_init_ref(), ctx.len(), ingress);
    }
    bump(if ingress { 0 } else { 1 });
    1
}

#[cgroup_skb(ingress)]
pub fn on_ingress(ctx: SkBuffContext) -> i32 {
    packet(ctx, true)
}

#[cgroup_skb(egress)]
pub fn on_egress(ctx: SkBuffContext) -> i32 {
    packet(ctx, false)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
