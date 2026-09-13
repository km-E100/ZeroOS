#![no_std]
extern crate alloc;

use alloc::{collections::VecDeque, vec, vec::Vec};
use core::sync::atomic::{AtomicU32, Ordering};
use zero_abi::channels::{NET_REQ, NET_RESP};
use zero_abi::ipc::Message;
use zero_abi::protocol::net as np;
use zero_abi::syscall::SysError;

pub const ETH_MTU: usize = 1500;
const ETH_HDR: usize = 14;
const ETH_ARP: u16 = 0x0806;
const ETH_IPV4: u16 = 0x0800;
const IP_ICMP: u8 = 1;
const IP_TCP: u8 = 6;
const IP_UDP: u8 = 17;
const DHCP_CLIENT: u16 = 68;
const DHCP_SERVER: u16 = 67;
const ARP_CACHE_MAX: usize = 16;
const PENDING_MAX: usize = 16;
const SOCKET_MAX: usize = 32;
const TCP_RX_CAP: usize = 64 * 1024;
const TCP_SYN_RETRY_MS: u64 = 750;
const TCP_SYN_RETRY_LIMIT: u8 = 5;
const TCP_EPHEMERAL_BASE: u16 = 49152;
const TCP_EPHEMERAL_SPAN: u32 = 16384;
// TEMP Parallels bring-up endpoint. Removed after TCP receive diagnosis.
const TCP_DIAG_UDP_PORT: u16 = 31337;

// TCP bring-up counters exposed read-only through NET::TCP_DIAG. They never
// perform syscalls from the packet path, so enabling diagnostics does not alter
// TCP_CONNECT timing or scheduler behaviour.
static TCP_SYN_SENT: AtomicU32 = AtomicU32::new(0);
static TCP_RX_SEGMENTS: AtomicU32 = AtomicU32::new(0);
static TCP_LOCAL_PORT_MATCH: AtomicU32 = AtomicU32::new(0);
static TCP_REMOTE_IP_MATCH: AtomicU32 = AtomicU32::new(0);
static TCP_REMOTE_PORT_MATCH: AtomicU32 = AtomicU32::new(0);
static TCP_FULL_TUPLE_MATCH: AtomicU32 = AtomicU32::new(0);
static TCP_SYNACK_SEEN: AtomicU32 = AtomicU32::new(0);
static TCP_SYNACK_BAD_ACK: AtomicU32 = AtomicU32::new(0);
static TCP_RST_SEEN: AtomicU32 = AtomicU32::new(0);
static TCP_ESTABLISHED: AtomicU32 = AtomicU32::new(0);
static TCP_LAST_FLAGS: AtomicU32 = AtomicU32::new(0);
static TCP_LAST_SEQ: AtomicU32 = AtomicU32::new(0);
static TCP_LAST_ACK: AtomicU32 = AtomicU32::new(0);
static TCP_LAST_EXPECTED_ACK: AtomicU32 = AtomicU32::new(0);
static TCP_LAST_HEADER_LEN: AtomicU32 = AtomicU32::new(0);
static TCP_LAST_PAYLOAD_LEN: AtomicU32 = AtomicU32::new(0);

fn tcp_diag_values() -> [u32; 16] {
    [
        TCP_SYN_SENT.load(Ordering::Relaxed),
        TCP_RX_SEGMENTS.load(Ordering::Relaxed),
        TCP_LOCAL_PORT_MATCH.load(Ordering::Relaxed),
        TCP_REMOTE_IP_MATCH.load(Ordering::Relaxed),
        TCP_REMOTE_PORT_MATCH.load(Ordering::Relaxed),
        TCP_FULL_TUPLE_MATCH.load(Ordering::Relaxed),
        TCP_SYNACK_SEEN.load(Ordering::Relaxed),
        TCP_SYNACK_BAD_ACK.load(Ordering::Relaxed),
        TCP_RST_SEEN.load(Ordering::Relaxed),
        TCP_ESTABLISHED.load(Ordering::Relaxed),
        TCP_LAST_FLAGS.load(Ordering::Relaxed),
        TCP_LAST_SEQ.load(Ordering::Relaxed),
        TCP_LAST_ACK.load(Ordering::Relaxed),
        TCP_LAST_EXPECTED_ACK.load(Ordering::Relaxed),
        TCP_LAST_HEADER_LEN.load(Ordering::Relaxed),
        TCP_LAST_PAYLOAD_LEN.load(Ordering::Relaxed),
    ]
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Ipv4(pub [u8; 4]);
impl Ipv4 {
    pub const ZERO: Self = Self([0; 4]);
    pub const BCAST: Self = Self([255; 4]);
    pub fn is_zero(self) -> bool {
        self == Self::ZERO
    }
    pub fn to_u32(self) -> u32 {
        u32::from_be_bytes(self.0)
    }
}
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Mac(pub [u8; 6]);
impl Mac {
    const BCAST: Self = Self([0xff; 6]);
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct NetConfig {
    pub ip: Ipv4,
    pub mask: Ipv4,
    pub gateway: Ipv4,
    pub dns: Ipv4,
    pub lease_seconds: u32,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Dhcp {
    Init,
    Selecting {
        xid: u32,
        last_ms: u64,
    },
    Requesting {
        xid: u32,
        offer: Ipv4,
        server: Ipv4,
        last_ms: u64,
    },
    Bound,
}
#[derive(Copy, Clone, Debug)]
struct Arp {
    ip: Ipv4,
    mac: Mac,
    last_ms: u64,
}
#[derive(Clone, Debug)]
struct Datagram {
    src: Ipv4,
    port: u16,
    data: Vec<u8>,
}
#[derive(Clone, Debug)]
struct UdpSocket {
    handle: u32,
    owner: u64,
    port: u16,
    rx: VecDeque<Datagram>,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TcpState {
    SynSent = 1,
    Established = 2,
    Closed = 3,
}
#[derive(Clone, Debug)]
struct TcpSocket {
    handle: u32,
    owner: u64,
    local: u16,
    remote: Ipv4,
    remote_port: u16,
    state: TcpState,
    snd_nxt: u32,
    rcv_nxt: u32,
    syn_last_ms: u64,
    syn_retries: u8,
    rx: VecDeque<u8>,
}

pub struct NetStack {
    mac: Mac,
    cfg: NetConfig,
    dhcp: Dhcp,
    arp: Vec<Arp>,
    pending: Vec<(Ipv4, Vec<u8>)>,
    out: VecDeque<Vec<u8>>,
    udp: Vec<UdpSocket>,
    tcp: Vec<TcpSocket>,
    next_handle: u32,
    ping_reply: Option<(Ipv4, u16, u16)>,
    ip_id: u16,
}
impl NetStack {
    pub fn new(mac: Mac) -> Self {
        Self {
            mac,
            cfg: NetConfig::default(),
            dhcp: Dhcp::Init,
            arp: Vec::new(),
            pending: Vec::new(),
            out: VecDeque::new(),
            udp: Vec::new(),
            tcp: Vec::new(),
            next_handle: 1,
            ping_reply: None,
            ip_id: 1,
        }
    }
    pub fn config(&self) -> NetConfig {
        self.cfg
    }
    pub fn bound(&self) -> bool {
        matches!(self.dhcp, Dhcp::Bound) && !self.cfg.ip.is_zero()
    }
    pub fn pop_frame(&mut self) -> Option<Vec<u8>> {
        self.out.pop_front()
    }
    pub fn tick(&mut self, now_ms: u64) {
        match self.dhcp {
            Dhcp::Init => self.send_discover(now_ms),
            Dhcp::Selecting { last_ms, .. } if now_ms.saturating_sub(last_ms) >= 2000 => {
                self.send_discover(now_ms)
            }
            Dhcp::Requesting {
                xid,
                offer,
                server,
                last_ms,
            } if now_ms.saturating_sub(last_ms) >= 2000 => {
                self.send_request(xid, offer, server, now_ms)
            }
            _ => {}
        }

        // A real network may lose the first SYN (and stale packets from a
        // recently reused four-tuple may arrive first). QEMU/slirp is unusually
        // forgiving here, so keep a bounded SYN retransmit timer in the stack
        // rather than making TCP_CONNECT a one-shot best effort.
        let mut retries = Vec::new();
        for (i, socket) in self.tcp.iter_mut().enumerate() {
            if socket.state == TcpState::SynSent
                && socket.syn_retries < TCP_SYN_RETRY_LIMIT
                && now_ms.saturating_sub(socket.syn_last_ms) >= TCP_SYN_RETRY_MS
            {
                socket.syn_last_ms = now_ms;
                socket.syn_retries = socket.syn_retries.saturating_add(1);
                retries.push(i);
            }
        }
        for i in retries {
            let seq = self.tcp[i].snd_nxt.wrapping_sub(1);
            self.send_tcp_raw(i, seq, 0, 0x02, &[]);
            TCP_SYN_SENT.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn send_discover(&mut self, now: u64) {
        let xid = (now as u32) ^ 0x5a45_524f;
        let payload = dhcp_packet(1, xid, self.mac, Ipv4::ZERO, Ipv4::ZERO);
        self.send_udp_direct(
            Ipv4::ZERO,
            Ipv4::BCAST,
            DHCP_CLIENT,
            DHCP_SERVER,
            &payload,
            Mac::BCAST,
        );
        self.dhcp = Dhcp::Selecting { xid, last_ms: now };
    }
    fn send_request(&mut self, xid: u32, offer: Ipv4, server: Ipv4, now: u64) {
        let payload = dhcp_packet(3, xid, self.mac, offer, server);
        self.send_udp_direct(
            Ipv4::ZERO,
            Ipv4::BCAST,
            DHCP_CLIENT,
            DHCP_SERVER,
            &payload,
            Mac::BCAST,
        );
        self.dhcp = Dhcp::Requesting {
            xid,
            offer,
            server,
            last_ms: now,
        };
    }
    pub fn ingest(&mut self, frame: &[u8], now_ms: u64) {
        if frame.len() < ETH_HDR {
            return;
        }
        let dst = Mac(frame[0..6].try_into().unwrap());
        let src = Mac(frame[6..12].try_into().unwrap());
        let et = u16::from_be_bytes([frame[12], frame[13]]);
        if dst != self.mac && dst != Mac::BCAST {
            return;
        }
        match et {
            ETH_ARP => self.ingest_arp(src, &frame[ETH_HDR..], now_ms),
            ETH_IPV4 => self.ingest_ipv4(src, &frame[ETH_HDR..], now_ms),
            _ => {}
        }
    }
    fn ingest_arp(&mut self, _eth_src: Mac, p: &[u8], now: u64) {
        if p.len() < 28 {
            return;
        }
        if &p[0..6] != [0, 1, 8, 0, 6, 4] {
            return;
        }
        let op = u16::from_be_bytes([p[6], p[7]]);
        let sha = Mac(p[8..14].try_into().unwrap());
        let spa = Ipv4(p[14..18].try_into().unwrap());
        let tpa = Ipv4(p[24..28].try_into().unwrap());
        if op == 2 {
            self.learn_arp(spa, sha, now);
            self.flush_pending(spa)
        } else if op == 1 && tpa == self.cfg.ip {
            self.queue_arp_reply(sha, spa)
        }
    }
    fn ingest_ipv4(&mut self, eth_src: Mac, p: &[u8], now: u64) {
        if p.len() < 20 || p[0] >> 4 != 4 {
            return;
        }
        let ihl = ((p[0] & 0xf) as usize) * 4;
        if ihl < 20 || p.len() < ihl {
            return;
        }
        let total = u16::from_be_bytes([p[2], p[3]]) as usize;
        if total < ihl || total > p.len() {
            return;
        }
        if checksum(&p[..ihl]) != 0 {
            return;
        }
        let src = Ipv4(p[12..16].try_into().unwrap());
        let dst = Ipv4(p[16..20].try_into().unwrap());
        if self.bound() && dst != self.cfg.ip && dst != Ipv4::BCAST {
            return;
        }
        self.learn_arp(src, eth_src, now);
        let body = &p[ihl..total];
        match p[9] {
            IP_ICMP => self.ingest_icmp(src, body),
            IP_UDP => self.ingest_udp(src, dst, body, now),
            IP_TCP => self.ingest_tcp(src, body),
            _ => {}
        }
    }
    fn ingest_icmp(&mut self, src: Ipv4, b: &[u8]) {
        if b.len() < 8 || checksum(b) != 0 {
            return;
        }
        let typ = b[0];
        let id = u16::from_be_bytes([b[4], b[5]]);
        let seq = u16::from_be_bytes([b[6], b[7]]);
        if typ == 0 {
            self.ping_reply = Some((src, id, seq))
        } else if typ == 8 && self.bound() {
            let mut out = b.to_vec();
            out[0] = 0;
            out[2] = 0;
            out[3] = 0;
            let c = checksum(&out).to_be_bytes();
            out[2..4].copy_from_slice(&c);
            self.send_ip(src, IP_ICMP, &out)
        }
    }
    fn ingest_udp(&mut self, src: Ipv4, _dst: Ipv4, b: &[u8], now: u64) {
        if b.len() < 8 {
            return;
        }
        let sport = u16::from_be_bytes([b[0], b[1]]);
        let dport = u16::from_be_bytes([b[2], b[3]]);
        let len = u16::from_be_bytes([b[4], b[5]]) as usize;
        if len < 8 || len > b.len() {
            return;
        }
        let data = &b[8..len];
        if dport == TCP_DIAG_UDP_PORT && data == b"tcpdiag" && self.bound() {
            let values = tcp_diag_values();
            let mut payload = Vec::with_capacity(values.len() * 4);
            for value in values {
                payload.extend_from_slice(&value.to_le_bytes());
            }
            let udp = build_udp(TCP_DIAG_UDP_PORT, sport, &payload);
            self.send_ip(src, IP_UDP, &udp);
            return;
        }
        if sport == DHCP_SERVER && dport == DHCP_CLIENT {
            self.ingest_dhcp(data, now);
            return;
        }
        if let Some(s) = self.udp.iter_mut().find(|s| s.port == dport) {
            if s.rx.len() < 16 {
                s.rx.push_back(Datagram {
                    src,
                    port: sport,
                    data: data[..data.len().min(1024)].to_vec(),
                })
            }
        }
    }
    fn ingest_dhcp(&mut self, b: &[u8], now: u64) {
        let Some(parsed) = parse_dhcp(b, self.mac) else {
            return;
        };
        match (self.dhcp, parsed.msg_type) {
            (Dhcp::Selecting { xid, .. }, 2) if xid == parsed.xid => {
                let server = parsed.server.unwrap_or(parsed.siaddr);
                self.send_request(xid, parsed.yiaddr, server, now)
            }
            (Dhcp::Requesting { xid, offer, .. }, 5)
                if xid == parsed.xid && parsed.yiaddr == offer =>
            {
                self.cfg = NetConfig {
                    ip: parsed.yiaddr,
                    mask: parsed.mask.unwrap_or(Ipv4([255, 255, 255, 0])),
                    gateway: parsed.router.unwrap_or(Ipv4::ZERO),
                    dns: parsed.dns.unwrap_or(Ipv4::ZERO),
                    lease_seconds: parsed.lease.unwrap_or(0),
                };
                self.dhcp = Dhcp::Bound;
            }
            _ => {}
        }
    }
    fn ingest_tcp(&mut self, src: Ipv4, b: &[u8]) {
        if b.len() < 20 {
            return;
        }
        let sport = u16::from_be_bytes([b[0], b[1]]);
        let dport = u16::from_be_bytes([b[2], b[3]]);
        let seq = u32::from_be_bytes(b[4..8].try_into().unwrap());
        let ack = u32::from_be_bytes(b[8..12].try_into().unwrap());
        let off = ((b[12] >> 4) as usize) * 4;
        if off < 20 || off > b.len() {
            return;
        }
        let flags = b[13];
        TCP_RX_SEGMENTS.fetch_add(1, Ordering::Relaxed);
        if self.tcp.iter().any(|s| s.local == dport) {
            TCP_LOCAL_PORT_MATCH.fetch_add(1, Ordering::Relaxed);
        }
        if self.tcp.iter().any(|s| s.remote == src) {
            TCP_REMOTE_IP_MATCH.fetch_add(1, Ordering::Relaxed);
        }
        if self.tcp.iter().any(|s| s.remote_port == sport) {
            TCP_REMOTE_PORT_MATCH.fetch_add(1, Ordering::Relaxed);
        }
        let Some(i) = self
            .tcp
            .iter()
            .position(|s| s.local == dport && s.remote == src && s.remote_port == sport)
        else {
            return;
        };
        TCP_FULL_TUPLE_MATCH.fetch_add(1, Ordering::Relaxed);
        TCP_LAST_FLAGS.store(flags as u32, Ordering::Relaxed);
        TCP_LAST_SEQ.store(seq, Ordering::Relaxed);
        TCP_LAST_ACK.store(ack, Ordering::Relaxed);
        TCP_LAST_HEADER_LEN.store(off as u32, Ordering::Relaxed);
        TCP_LAST_PAYLOAD_LEN.store(b.len().saturating_sub(off) as u32, Ordering::Relaxed);
        let mut send_ack = false;
        {
            let s = &mut self.tcp[i];
            TCP_LAST_EXPECTED_ACK.store(s.snd_nxt, Ordering::Relaxed);
            match s.state {
                TcpState::SynSent => {
                    if flags & 0x04 != 0 {
                        TCP_RST_SEEN.fetch_add(1, Ordering::Relaxed);
                    }
                    if flags & 0x12 == 0x12 {
                        TCP_SYNACK_SEEN.fetch_add(1, Ordering::Relaxed);
                        if ack == s.snd_nxt {
                            s.rcv_nxt = seq.wrapping_add(1);
                            s.state = TcpState::Established;
                            send_ack = true;
                            TCP_ESTABLISHED.fetch_add(1, Ordering::Relaxed);
                        } else {
                            TCP_SYNACK_BAD_ACK.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                TcpState::Established => {
                    let data = &b[off..];
                    let mut data_fully_accepted = data.is_empty();
                    if !data.is_empty() && seq == s.rcv_nxt {
                        let room = TCP_RX_CAP.saturating_sub(s.rx.len());
                        let accepted = data.len().min(room);
                        for &v in &data[..accepted] {
                            s.rx.push_back(v);
                        }
                        // Advance ACK only over bytes actually retained. If the
                        // receive queue is full, the peer sees a zero/small
                        // window and retransmits the unaccepted suffix instead
                        // of us silently acknowledging dropped package data.
                        s.rcv_nxt = s.rcv_nxt.wrapping_add(accepted as u32);
                        data_fully_accepted = accepted == data.len();
                        send_ack = true;
                    }
                    // FIN occupies one sequence number and is only consumed
                    // after all payload in the same segment was accepted.
                    if flags & 0x01 != 0
                        && data_fully_accepted
                        && seq.wrapping_add(data.len() as u32) == s.rcv_nxt
                    {
                        s.rcv_nxt = s.rcv_nxt.wrapping_add(1);
                        s.state = TcpState::Closed;
                        send_ack = true
                    }
                }
                _ => {}
            }
        }
        if send_ack {
            self.send_tcp_index(i, 0x10, &[])
        }
    }
    fn learn_arp(&mut self, ip: Ipv4, mac: Mac, now: u64) {
        if ip.is_zero() {
            return;
        }
        if let Some(e) = self.arp.iter_mut().find(|e| e.ip == ip) {
            e.mac = mac;
            e.last_ms = now;
            return;
        }
        if self.arp.len() >= ARP_CACHE_MAX {
            self.arp.remove(0);
        }
        self.arp.push(Arp {
            ip,
            mac,
            last_ms: now,
        })
    }
    fn route(&self, dst: Ipv4) -> Ipv4 {
        let ip = self.cfg.ip.to_u32();
        let mask = self.cfg.mask.to_u32();
        if (dst.to_u32() & mask) == (ip & mask) {
            dst
        } else {
            self.cfg.gateway
        }
    }
    fn send_ip(&mut self, dst: Ipv4, proto: u8, payload: &[u8]) {
        if !self.bound() {
            return;
        }
        let next = self.route(dst);
        if let Some(mac) = self.arp.iter().find(|e| e.ip == next).map(|e| e.mac) {
            let ip = build_ipv4(self.cfg.ip, dst, proto, payload, self.ip_id);
            self.ip_id = self.ip_id.wrapping_add(1);
            self.out.push_back(build_eth(mac, self.mac, ETH_IPV4, &ip))
        } else {
            if self.pending.len() < PENDING_MAX {
                let ip = build_ipv4(self.cfg.ip, dst, proto, payload, self.ip_id);
                self.ip_id = self.ip_id.wrapping_add(1);
                self.pending.push((next, ip));
            }
            self.queue_arp_request(next)
        }
    }
    fn flush_pending(&mut self, ip: Ipv4) {
        let Some(mac) = self.arp.iter().find(|e| e.ip == ip).map(|e| e.mac) else {
            return;
        };
        let mut i = 0;
        while i < self.pending.len() {
            if self.pending[i].0 == ip {
                let (_, pkt) = self.pending.remove(i);
                self.out.push_back(build_eth(mac, self.mac, ETH_IPV4, &pkt))
            } else {
                i += 1
            }
        }
    }
    fn queue_arp_request(&mut self, target: Ipv4) {
        if !self.bound() {
            return;
        }
        let mut p = vec![0u8; 28];
        p[0..8].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
        p[8..14].copy_from_slice(&self.mac.0);
        p[14..18].copy_from_slice(&self.cfg.ip.0);
        p[24..28].copy_from_slice(&target.0);
        self.out
            .push_back(build_eth(Mac::BCAST, self.mac, ETH_ARP, &p))
    }
    fn queue_arp_reply(&mut self, dst_mac: Mac, dst_ip: Ipv4) {
        let mut p = vec![0u8; 28];
        p[0..8].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 2]);
        p[8..14].copy_from_slice(&self.mac.0);
        p[14..18].copy_from_slice(&self.cfg.ip.0);
        p[18..24].copy_from_slice(&dst_mac.0);
        p[24..28].copy_from_slice(&dst_ip.0);
        self.out
            .push_back(build_eth(dst_mac, self.mac, ETH_ARP, &p))
    }
    fn send_udp_direct(
        &mut self,
        src: Ipv4,
        dst: Ipv4,
        sport: u16,
        dport: u16,
        data: &[u8],
        mac: Mac,
    ) {
        let udp = build_udp(sport, dport, data);
        let ip = build_ipv4(src, dst, IP_UDP, &udp, self.ip_id);
        self.ip_id = self.ip_id.wrapping_add(1);
        self.out.push_back(build_eth(mac, self.mac, ETH_IPV4, &ip))
    }
    pub fn ping(&mut self, dst: Ipv4, id: u16, seq: u16) -> bool {
        if self.ping_reply == Some((dst, id, seq)) {
            return true;
        }
        let mut p = vec![0u8; 8];
        p[0] = 8;
        p[4..6].copy_from_slice(&id.to_be_bytes());
        p[6..8].copy_from_slice(&seq.to_be_bytes());
        let c = checksum(&p).to_be_bytes();
        p[2..4].copy_from_slice(&c);
        self.send_ip(dst, IP_ICMP, &p);
        false
    }
    pub fn udp_open(&mut self, owner: u64, port: u16) -> Option<u32> {
        if self.udp.len() + self.tcp.len() >= SOCKET_MAX
            || port == 0
            || self.udp.iter().any(|s| s.port == port)
        {
            return None;
        }
        let h = self.alloc_handle();
        self.udp.push(UdpSocket {
            handle: h,
            owner,
            port,
            rx: VecDeque::new(),
        });
        Some(h)
    }
    pub fn udp_send(&mut self, owner: u64, h: u32, dst: Ipv4, port: u16, data: &[u8]) -> bool {
        let Some(s) = self.udp.iter().find(|s| s.handle == h && s.owner == owner) else {
            return false;
        };
        let udp = build_udp(s.port, port, data);
        self.send_ip(dst, IP_UDP, &udp);
        true
    }
    fn udp_recv(&mut self, owner: u64, h: u32) -> Option<Datagram> {
        self.udp
            .iter_mut()
            .find(|s| s.handle == h && s.owner == owner)?
            .rx
            .pop_front()
    }
    pub fn tcp_connect(&mut self, owner: u64, dst: Ipv4, port: u16) -> Option<u32> {
        if !self.bound() || self.tcp.len() + self.udp.len() >= SOCKET_MAX {
            return None;
        }
        let h = self.alloc_handle();
        let now_ns = userlib::monotonic_ns().unwrap_or(1);
        let seed = (now_ns as u32)
            ^ ((now_ns >> 32) as u32).rotate_left(7)
            ^ h.rotate_left(13)
            ^ self.cfg.ip.to_u32().rotate_left(17);
        let mut local = None;
        for probe in 0..TCP_EPHEMERAL_SPAN {
            let port =
                (TCP_EPHEMERAL_BASE as u32 + seed.wrapping_add(probe) % TCP_EPHEMERAL_SPAN) as u16;
            if !self.tcp.iter().any(|socket| socket.local == port) {
                local = Some(port);
                break;
            }
        }
        let local = local?;
        let iss = seed.rotate_left(11) ^ (now_ns as u32).rotate_right(3);
        self.tcp.push(TcpSocket {
            handle: h,
            owner,
            local,
            remote: dst,
            remote_port: port,
            state: TcpState::SynSent,
            snd_nxt: iss.wrapping_add(1),
            rcv_nxt: 0,
            syn_last_ms: now_ns / 1_000_000,
            syn_retries: 0,
            rx: VecDeque::new(),
        });
        let i = self.tcp.len() - 1;
        self.send_tcp_raw(i, iss, 0, 0x02, &[]);
        TCP_SYN_SENT.fetch_add(1, Ordering::Relaxed);
        Some(h)
    }
    pub fn tcp_state(&self, owner: u64, h: u32) -> Option<TcpState> {
        self.tcp
            .iter()
            .find(|s| s.handle == h && s.owner == owner)
            .map(|s| s.state)
    }
    pub fn tcp_send(&mut self, owner: u64, h: u32, data: &[u8]) -> bool {
        let Some(i) = self
            .tcp
            .iter()
            .position(|s| s.handle == h && s.owner == owner && s.state == TcpState::Established)
        else {
            return false;
        };
        let n = data.len().min(536);
        self.send_tcp_index(i, 0x18, &data[..n]);
        self.tcp[i].snd_nxt = self.tcp[i].snd_nxt.wrapping_add(n as u32);
        true
    }
    pub fn tcp_recv(&mut self, owner: u64, h: u32, max: usize) -> Option<Vec<u8>> {
        let i = self
            .tcp
            .iter()
            .position(|s| s.handle == h && s.owner == owner)?;
        let n = max.min(self.tcp[i].rx.len());
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            if let Some(b) = self.tcp[i].rx.pop_front() {
                out.push(b)
            }
        }
        // Draining receive data re-opens the advertised window. Send a pure
        // ACK immediately so a peer paused on a zero/small window can resume
        // without waiting for unrelated outbound traffic.
        if n != 0 && self.tcp[i].state == TcpState::Established {
            self.send_tcp_index(i, 0x10, &[]);
        }
        Some(out)
    }
    fn send_tcp_index(&mut self, i: usize, flags: u8, data: &[u8]) {
        let seq = self.tcp[i].snd_nxt;
        let ack = self.tcp[i].rcv_nxt;
        self.send_tcp_raw(i, seq, ack, flags, data)
    }
    fn send_tcp_raw(&mut self, i: usize, seq: u32, ack: u32, flags: u8, data: &[u8]) {
        let s = &self.tcp[i];
        let window = TCP_RX_CAP.saturating_sub(s.rx.len()).min(u16::MAX as usize) as u16;
        let seg = build_tcp(
            self.cfg.ip,
            s.remote,
            s.local,
            s.remote_port,
            seq,
            ack,
            flags,
            window,
            data,
        );
        let dst = s.remote;
        self.send_ip(dst, IP_TCP, &seg)
    }
    fn alloc_handle(&mut self) -> u32 {
        let h = self.next_handle;
        self.next_handle = self.next_handle.wrapping_add(1).max(1);
        h
    }
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum = sum.wrapping_add(u16::from_be_bytes([c[0], c[1]]) as u32)
    }
    if let Some(&b) = chunks.remainder().first() {
        sum = sum.wrapping_add((b as u32) << 8)
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16)
    }
    !(sum as u16)
}
fn build_eth(dst: Mac, src: Mac, kind: u16, p: &[u8]) -> Vec<u8> {
    // Ethernet II requires at least 60 bytes on the wire before the NIC adds
    // the 4-byte FCS. Real hardware/hypervisors may drop shorter runt frames;
    // QEMU/slirp is more permissive, which previously hid this for 54-byte TCP
    // SYN/ACK frames. Pad only at L2: IPv4 total-length/checksums remain unchanged.
    const ETH_MIN_FRAME_NO_FCS: usize = 60;
    let frame_len = (14 + p.len()).max(ETH_MIN_FRAME_NO_FCS);
    let mut f = Vec::with_capacity(frame_len);
    f.extend_from_slice(&dst.0);
    f.extend_from_slice(&src.0);
    f.extend_from_slice(&kind.to_be_bytes());
    f.extend_from_slice(p);
    f.resize(frame_len, 0);
    f
}
fn build_ipv4(src: Ipv4, dst: Ipv4, proto: u8, p: &[u8], id: u16) -> Vec<u8> {
    let len = 20 + p.len();
    let mut b = vec![0u8; len];
    b[0] = 0x45;
    b[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    b[4..6].copy_from_slice(&id.to_be_bytes());
    b[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    b[8] = 64;
    b[9] = proto;
    b[12..16].copy_from_slice(&src.0);
    b[16..20].copy_from_slice(&dst.0);
    let c = checksum(&b[..20]).to_be_bytes();
    b[10..12].copy_from_slice(&c);
    b[20..].copy_from_slice(p);
    b
}
fn build_udp(sport: u16, dport: u16, p: &[u8]) -> Vec<u8> {
    let len = 8 + p.len();
    let mut b = vec![0u8; len];
    b[0..2].copy_from_slice(&sport.to_be_bytes());
    b[2..4].copy_from_slice(&dport.to_be_bytes());
    b[4..6].copy_from_slice(&(len as u16).to_be_bytes());
    b[8..].copy_from_slice(p);
    b
}
fn pseudo_checksum(src: Ipv4, dst: Ipv4, proto: u8, segment: &[u8]) -> u16 {
    let mut b = Vec::with_capacity(12 + segment.len());
    b.extend_from_slice(&src.0);
    b.extend_from_slice(&dst.0);
    b.push(0);
    b.push(proto);
    b.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    b.extend_from_slice(segment);
    checksum(&b)
}
fn build_tcp(
    src: Ipv4,
    dst: Ipv4,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    p: &[u8],
) -> Vec<u8> {
    let mut b = vec![0u8; 20 + p.len()];
    b[0..2].copy_from_slice(&sport.to_be_bytes());
    b[2..4].copy_from_slice(&dport.to_be_bytes());
    b[4..8].copy_from_slice(&seq.to_be_bytes());
    b[8..12].copy_from_slice(&ack.to_be_bytes());
    b[12] = 5 << 4;
    b[13] = flags;
    b[14..16].copy_from_slice(&window.to_be_bytes());
    b[20..].copy_from_slice(p);
    let c = pseudo_checksum(src, dst, IP_TCP, &b).to_be_bytes();
    b[16..18].copy_from_slice(&c);
    b
}

struct DhcpParsed {
    xid: u32,
    yiaddr: Ipv4,
    siaddr: Ipv4,
    msg_type: u8,
    server: Option<Ipv4>,
    mask: Option<Ipv4>,
    router: Option<Ipv4>,
    dns: Option<Ipv4>,
    lease: Option<u32>,
}
fn dhcp_packet(msg: u8, xid: u32, mac: Mac, request: Ipv4, server: Ipv4) -> Vec<u8> {
    let mut b = vec![0u8; 240];
    b[0] = 1;
    b[1] = 1;
    b[2] = 6;
    b[4..8].copy_from_slice(&xid.to_be_bytes());
    b[10..12].copy_from_slice(&0x8000u16.to_be_bytes());
    b[28..34].copy_from_slice(&mac.0);
    b[236..240].copy_from_slice(&[99, 130, 83, 99]);
    b.extend_from_slice(&[53, 1, msg]);
    if msg == 3 && !request.is_zero() {
        b.extend_from_slice(&[50, 4]);
        b.extend_from_slice(&request.0);
        if !server.is_zero() {
            b.extend_from_slice(&[54, 4]);
            b.extend_from_slice(&server.0)
        }
    }
    b.extend_from_slice(&[55, 4, 1, 3, 6, 51, 255]);
    b
}
fn parse_dhcp(b: &[u8], mac: Mac) -> Option<DhcpParsed> {
    if b.len() < 240
        || b[0] != 2
        || b[1] != 1
        || b[2] != 6
        || b[28..34] != mac.0
        || b[236..240] != [99, 130, 83, 99]
    {
        return None;
    }
    let xid = u32::from_be_bytes(b[4..8].try_into().ok()?);
    let yiaddr = Ipv4(b[16..20].try_into().ok()?);
    let siaddr = Ipv4(b[20..24].try_into().ok()?);
    let (mut typ, mut server, mut mask, mut router, mut dns, mut lease) =
        (0, None, None, None, None, None);
    let mut i = 240;
    while i < b.len() {
        let k = b[i];
        i += 1;
        if k == 255 {
            break;
        }
        if k == 0 {
            continue;
        }
        if i >= b.len() {
            break;
        }
        let n = b[i] as usize;
        i += 1;
        if i + n > b.len() {
            break;
        }
        let v = &b[i..i + n];
        match (k, n) {
            (53, 1) => typ = v[0],
            (54, 4) => server = Some(Ipv4(v.try_into().ok()?)),
            (1, 4) => mask = Some(Ipv4(v.try_into().ok()?)),
            (3, n) if n >= 4 => router = Some(Ipv4(v[0..4].try_into().ok()?)),
            (6, n) if n >= 4 => dns = Some(Ipv4(v[0..4].try_into().ok()?)),
            (51, 4) => lease = Some(u32::from_be_bytes(v.try_into().ok()?)),
            _ => {}
        }
        i += n
    }
    Some(DhcpParsed {
        xid,
        yiaddr,
        siaddr,
        msg_type: typ,
        server,
        mask,
        router,
        dns,
        lease,
    })
}

fn rd_u32(p: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(
        p.get(o..o + 4)
            .and_then(|s| s.try_into().ok())
            .unwrap_or([0; 4]),
    )
}
fn rd_u16(p: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(
        p.get(o..o + 2)
            .and_then(|s| s.try_into().ok())
            .unwrap_or([0; 2]),
    )
}
fn ip_at(p: &[u8], o: usize) -> Ipv4 {
    Ipv4(
        p.get(o..o + 4)
            .and_then(|s| s.try_into().ok())
            .unwrap_or([0; 4]),
    )
}
fn response(target: u64, req: u32, code: u32, payload: &[u8]) {
    let mut m = Message::empty();
    m.code = code;
    m.payload[..4].copy_from_slice(&req.to_le_bytes());
    let n = payload.len().min(m.payload.len() - 4);
    m.payload[4..4 + n].copy_from_slice(&payload[..n]);
    let _ = userlib::ipc_send_to(NET_RESP, target, &m);
}

pub extern "C" fn server_main() -> ! {
    let _ = userlib::console_write(b"Zero OS netd starting\r\n");
    let mut waiting_for_device_logged = false;
    let mac = loop {
        match userlib::net_get_mac() {
            Ok(v) => break Mac(v),
            Err(SysError::DeviceError) => {
                if !waiting_for_device_logged {
                    let _ = userlib::console_write(
                        b"netd: no network backend yet; retrying at low frequency\r\n",
                    );
                    waiting_for_device_logged = true;
                }
                // Device discovery is complete before launchd starts netd on the
                // normal boot path. A missing backend therefore must not turn
                // into a cooperative-yield busy loop that consumes an entire PE.
                // Keep a low-frequency retry for future hotplug/recovery.
                let _ = userlib::sleep_ticks(50);
            }
            Err(_) => {
                let _ = userlib::sleep_ticks(50);
            }
        }
    };
    let mut stack = NetStack::new(mac);
    let mut last_bound = false;
    let mut rx = [0u8; 1536];
    loop {
        let now = userlib::monotonic_ns().unwrap_or(0) / 1_000_000;
        stack.tick(now);
        let mut did = false;
        loop {
            match userlib::net_recv_frame(&mut rx) {
                Ok(n) => {
                    did = true;
                    stack.ingest(&rx[..n], now)
                }
                Err(SysError::WouldBlock) => break,
                Err(_) => break,
            }
        }
        while let Some(f) = stack.pop_frame() {
            match userlib::net_send_frame(&f) {
                Ok(()) => did = true,
                Err(SysError::Busy) => {
                    stack.out.push_front(f);
                    break;
                }
                Err(_) => break,
            }
        }
        if stack.bound() && !last_bound {
            last_bound = true;
            let _ = userlib::console_write(b"netd: DHCP bound\r\n");
        }
        let mut req = Message::empty();
        if let Ok(sender) = userlib::ipc_try_receive_from(NET_REQ, &mut req) {
            did = true;
            handle_req(&mut stack, sender, &req)
        }
        if !did {
            let _ = userlib::sleep_ticks(1);
        }
    }
}
fn handle_req(s: &mut NetStack, owner: u64, m: &Message) {
    let req = rd_u32(&m.payload, 0);
    match m.code {
        np::STATUS => {
            let c = s.config();
            let mut p = [0u8; 20];
            p[0..4].copy_from_slice(&c.ip.0);
            p[4..8].copy_from_slice(&c.mask.0);
            p[8..12].copy_from_slice(&c.gateway.0);
            p[12..16].copy_from_slice(&c.dns.0);
            p[16..20].copy_from_slice(&c.lease_seconds.to_le_bytes());
            response(owner, req, if s.bound() { np::OK } else { np::AGAIN }, &p)
        }
        np::PING => {
            let ip = ip_at(&m.payload, 4);
            let id = (owner as u16) ^ 0x5a5a;
            let seq = rd_u16(&m.payload, 8);
            response(
                owner,
                req,
                if s.ping(ip, id, seq) {
                    np::OK
                } else {
                    np::AGAIN
                },
                &[],
            )
        }
        np::UDP_OPEN => {
            let port = rd_u16(&m.payload, 4);
            let h = s.udp_open(owner, port).unwrap_or(0);
            response(
                owner,
                req,
                if h != 0 { np::OK } else { np::ERR },
                &h.to_le_bytes(),
            )
        }
        np::UDP_SEND => {
            let h = rd_u32(&m.payload, 4);
            let ip = ip_at(&m.payload, 8);
            let port = rd_u16(&m.payload, 12);
            let n = rd_u16(&m.payload, 14) as usize;
            let end = (16 + n).min(m.payload.len());
            response(
                owner,
                req,
                if s.udp_send(owner, h, ip, port, &m.payload[16..end]) {
                    np::OK
                } else {
                    np::ERR
                },
                &[],
            )
        }
        np::UDP_RECV => {
            let h = rd_u32(&m.payload, 4);
            if let Some(d) = s.udp_recv(owner, h) {
                let mut p = [0u8; 124];
                p[..4].copy_from_slice(&d.src.0);
                p[4..6].copy_from_slice(&d.port.to_le_bytes());
                let n = d.data.len().min(116);
                p[6..8].copy_from_slice(&(n as u16).to_le_bytes());
                p[8..8 + n].copy_from_slice(&d.data[..n]);
                response(owner, req, np::OK, &p[..8 + n])
            } else {
                response(owner, req, np::AGAIN, &[])
            }
        }
        np::TCP_CONNECT => {
            let h = s
                .tcp_connect(owner, ip_at(&m.payload, 4), rd_u16(&m.payload, 8))
                .unwrap_or(0);
            response(
                owner,
                req,
                if h != 0 { np::OK } else { np::AGAIN },
                &h.to_le_bytes(),
            )
        }
        np::TCP_STATE => {
            let h = rd_u32(&m.payload, 4);
            let st = s.tcp_state(owner, h).map(|v| v as u32).unwrap_or(0);
            response(
                owner,
                req,
                if st != 0 { np::OK } else { np::ERR },
                &st.to_le_bytes(),
            )
        }
        np::TCP_SEND => {
            let h = rd_u32(&m.payload, 4);
            let n = rd_u16(&m.payload, 8) as usize;
            let end = (10 + n).min(m.payload.len());
            response(
                owner,
                req,
                if s.tcp_send(owner, h, &m.payload[10..end]) {
                    np::OK
                } else {
                    np::AGAIN
                },
                &[],
            )
        }
        np::TCP_RECV => {
            let h = rd_u32(&m.payload, 4);
            let max = rd_u16(&m.payload, 8) as usize;
            if let Some(d) = s.tcp_recv(owner, h, max.min(122)) {
                if d.is_empty() {
                    response(owner, req, np::AGAIN, &[])
                } else {
                    let mut p = [0u8; 124];
                    let n = d.len().min(122);
                    p[..2].copy_from_slice(&(n as u16).to_le_bytes());
                    p[2..2 + n].copy_from_slice(&d[..n]);
                    response(owner, req, np::OK, &p[..2 + n])
                }
            } else {
                response(owner, req, np::ERR, &[])
            }
        }
        np::TCP_RECV_SHM => {
            let h = rd_u32(&m.payload, 4);
            let shm = rd_u32(&m.payload, 8);
            let requested = rd_u32(&m.payload, 12) as usize;
            let result = (|| -> Result<Option<usize>, ()> {
                let cap = userlib::shm_len(shm).map_err(|_| ())?;
                let ptr = userlib::shm_map(shm).map_err(|_| ())?;
                let max = requested.min(cap).min(64 * 1024);
                let Some(d) = s.tcp_recv(owner, h, max) else {
                    return Err(());
                };
                if d.is_empty() {
                    return Ok(None);
                }
                unsafe {
                    core::ptr::copy_nonoverlapping(d.as_ptr(), ptr, d.len());
                }
                Ok(Some(d.len()))
            })();
            // The client grants exactly one holder for this RPC. Drop it before
            // replying so completed HTTPS connections cannot leak SHM regions.
            let _ = userlib::shm_release(shm);
            match result {
                Ok(Some(n)) => response(owner, req, np::OK, &(n as u32).to_le_bytes()),
                Ok(None) => response(owner, req, np::AGAIN, &[]),
                Err(()) => response(owner, req, np::ERR, &[]),
            }
        }
        np::TCP_DIAG => {
            let values = tcp_diag_values();
            let mut p = [0u8; 64];
            for (i, v) in values.iter().copied().enumerate() {
                p[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
            }
            response(owner, req, np::OK, &p)
        }
        _ => response(owner, req, np::ERR, &[]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checksum_ipv4_roundtrip() {
        let p = build_ipv4(Ipv4([1, 2, 3, 4]), Ipv4([5, 6, 7, 8]), 17, &[1, 2, 3], 7);
        assert_eq!(checksum(&p[..20]), 0);
        assert_eq!(p.len(), 23)
    }

    #[test]
    fn ethernet_pads_short_tcp_frames_to_wire_minimum() {
        let tcp = build_tcp(
            Ipv4([10, 0, 0, 1]),
            Ipv4([10, 0, 0, 2]),
            40000,
            443,
            1,
            0,
            0x02,
            u16::MAX,
            &[],
        );
        let ip = build_ipv4(Ipv4([10, 0, 0, 1]), Ipv4([10, 0, 0, 2]), IP_TCP, &tcp, 1);
        assert_eq!(14 + ip.len(), 54, "bare SYN geometry should stay 54 bytes");
        let frame = build_eth(Mac([0; 6]), Mac([2, 0, 0, 0, 0, 1]), ETH_IPV4, &ip);
        assert_eq!(frame.len(), 60);
        assert_eq!(&frame[14..14 + ip.len()], ip.as_slice());
        assert!(frame[14 + ip.len()..].iter().all(|b| *b == 0));
    }
    #[test]
    fn arp_request_layout() {
        let mut s = NetStack::new(Mac([2, 0, 0, 0, 0, 1]));
        s.cfg = NetConfig {
            ip: Ipv4([10, 0, 2, 15]),
            mask: Ipv4([255, 255, 255, 0]),
            gateway: Ipv4([10, 0, 2, 2]),
            dns: Ipv4::ZERO,
            lease_seconds: 1,
        };
        s.dhcp = Dhcp::Bound;
        s.queue_arp_request(Ipv4([10, 0, 2, 2]));
        let f = s.pop_frame().unwrap();
        assert_eq!(&f[0..6], &[0xff; 6]);
        assert_eq!(u16::from_be_bytes([f[12], f[13]]), ETH_ARP)
    }
    #[test]
    fn dhcp_offer_parser() {
        let mac = Mac([2, 3, 4, 5, 6, 7]);
        let xid: u32 = 0x12345678;
        let mut b = vec![0u8; 240];
        b[0] = 2;
        b[1] = 1;
        b[2] = 6;
        b[4..8].copy_from_slice(&xid.to_be_bytes());
        b[16..20].copy_from_slice(&[10, 0, 2, 15]);
        b[20..24].copy_from_slice(&[10, 0, 2, 2]);
        b[28..34].copy_from_slice(&mac.0);
        b[236..240].copy_from_slice(&[99, 130, 83, 99]);
        b.extend_from_slice(&[
            53, 1, 2, 1, 4, 255, 255, 255, 0, 3, 4, 10, 0, 2, 2, 6, 4, 10, 0, 2, 3, 54, 4, 10, 0,
            2, 2, 51, 4, 0, 0, 3, 0, 255,
        ]);
        let p = parse_dhcp(&b, mac).unwrap();
        assert_eq!(p.xid, xid);
        assert_eq!(p.msg_type, 2);
        assert_eq!(p.router, Some(Ipv4([10, 0, 2, 2])));
        assert_eq!(p.dns, Some(Ipv4([10, 0, 2, 3])))
    }
    #[test]
    fn tcp_checksum_nonzero_and_socket_ownership() {
        let seg = build_tcp(
            Ipv4([10, 0, 0, 1]),
            Ipv4([10, 0, 0, 2]),
            123,
            80,
            1,
            0,
            2,
            u16::MAX,
            &[],
        );
        assert_eq!(
            pseudo_checksum(Ipv4([10, 0, 0, 1]), Ipv4([10, 0, 0, 2]), 6, &seg),
            0
        );
        let mut s = NetStack::new(Mac([2, 0, 0, 0, 0, 1]));
        let h = s.udp_open(7, 1234).unwrap();
        assert!(s.udp_send(8, h, Ipv4([1, 1, 1, 1]), 53, b"x") == false)
    }
}
