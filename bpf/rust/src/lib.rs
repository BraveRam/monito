#![no_std]

pub const LOOPBACK: u8 = 0;
pub const PRIVATE: u8 = 1;
pub const EXTERNAL: u8 = 2;
pub const UNKNOWN: u8 = 3;

// These layouts are the ABI consumed by pkg/bpf in the Go daemon.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowKey {
    pub pid: u32,
    pub category: u8,
    pub pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FlowMetrics {
    pub generation: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ProcInfo {
    pub pid: u32,
    pub tgid: u32,
    pub cgroup_id: u64,
    pub comm: [u8; 16],
}

#[inline(always)]
pub fn classify_ipv4(ip: u32) -> u8 {
    if ip >> 24 == 127 {
        LOOPBACK
    } else if ip >> 24 == 10
        || ip >> 20 == (172 << 4 | 1)
        || ip >> 16 == (192 << 8 | 168)
        || ip >> 16 == (169 << 8 | 254)
        || ip >> 28 == 14
        || ip == u32::MAX
        || ip >> 22 == (100 << 2 | 1)
    {
        PRIVATE
    } else {
        EXTERNAL
    }
}

#[inline(always)]
pub fn classify_ipv6(ip: [u8; 16]) -> u8 {
    if ip == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] {
        LOOPBACK
    } else if (ip[0] == 0xfe && ip[1] & 0xc0 == 0x80) || ip[0] & 0xfe == 0xfc || ip[0] == 0xff {
        PRIVATE
    } else {
        EXTERNAL
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn go_map_abi() {
        assert_eq!(size_of::<FlowKey>(), 8);
        assert_eq!(offset_of!(FlowKey, category), 4);
        assert_eq!(size_of::<FlowMetrics>(), 40);
        assert_eq!(align_of::<FlowMetrics>(), 8);
        assert_eq!(offset_of!(FlowMetrics, tx_packets), 32);
        assert_eq!(size_of::<ProcInfo>(), 32);
        assert_eq!(offset_of!(ProcInfo, cgroup_id), 8);
        assert_eq!(offset_of!(ProcInfo, comm), 16);
    }

    #[test]
    fn ipv4_categories_and_range_boundaries() {
        for (ip, category) in [
            ([127, 0, 0, 1], LOOPBACK),
            ([127, 255, 255, 255], LOOPBACK),
            ([10, 0, 0, 1], PRIVATE),
            ([172, 16, 0, 0], PRIVATE),
            ([172, 31, 255, 255], PRIVATE),
            ([172, 15, 255, 255], EXTERNAL),
            ([172, 32, 0, 0], EXTERNAL),
            ([192, 168, 1, 1], PRIVATE),
            ([169, 254, 0, 1], PRIVATE),
            ([224, 0, 0, 1], PRIVATE),
            ([239, 255, 255, 255], PRIVATE),
            ([240, 0, 0, 0], EXTERNAL),
            ([255, 255, 255, 255], PRIVATE),
            ([100, 64, 0, 0], PRIVATE),
            ([100, 127, 255, 255], PRIVATE),
            ([100, 63, 255, 255], EXTERNAL),
            ([100, 128, 0, 0], EXTERNAL),
            ([8, 8, 8, 8], EXTERNAL),
        ] {
            assert_eq!(classify_ipv4(u32::from_be_bytes(ip)), category, "{ip:?}");
        }
    }

    #[test]
    fn ipv6_categories_and_range_boundaries() {
        assert_eq!(classify_ipv6([0; 16]), EXTERNAL);
        let mut ip = [0; 16];
        ip[15] = 1;
        assert_eq!(classify_ipv6(ip), LOOPBACK);
        ip[15] = 2;
        assert_eq!(classify_ipv6(ip), EXTERNAL);
        for (first, second, expected) in [
            (0xfe, 0x80, PRIVATE),
            (0xfe, 0xbf, PRIVATE),
            (0xfe, 0x7f, EXTERNAL),
            (0xfe, 0xc0, EXTERNAL),
            (0xfc, 0, PRIVATE),
            (0xfd, 0xff, PRIVATE),
            (0xfb, 0, EXTERNAL),
            (0xff, 0x02, PRIVATE),
            (0x20, 0x01, EXTERNAL),
        ] {
            ip[0] = first;
            ip[1] = second;
            assert_eq!(classify_ipv6(ip), expected, "{first:x}:{second:x}");
        }
    }
}
