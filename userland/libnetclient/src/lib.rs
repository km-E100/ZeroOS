#![no_std]
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use zero_abi::channels::{NET_REQ, NET_RESP};
use zero_abi::ipc::Message;
use zero_abi::protocol::net as np;
use zero_abi::syscall::SysError;
static NEXT: AtomicU32 = AtomicU32::new(1);
static NETD_PID: AtomicU64 = AtomicU64::new(0);
const BULK_SIZE: usize = 16 * 1024;
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct NetStatus {
    pub ip: [u8; 4],
    pub mask: [u8; 4],
    pub gateway: [u8; 4],
    pub dns: [u8; 4],
    pub lease_seconds: u32,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TcpDiag {
    pub syn_sent: u32,
    pub rx_segments: u32,
    pub local_port_match: u32,
    pub remote_ip_match: u32,
    pub remote_port_match: u32,
    pub full_tuple_match: u32,
    pub synack_seen: u32,
    pub synack_bad_ack: u32,
    pub rst_seen: u32,
    pub established: u32,
    pub last_flags: u32,
    pub last_seq: u32,
    pub last_ack: u32,
    pub last_expected_ack: u32,
    pub last_header_len: u32,
    pub last_payload_len: u32,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Sys(SysError),
    Again,
    Remote,
    Protocol,
}
fn rpc(code: u32, payload: &[u8]) -> Result<Message, Error> {
    let id = NEXT.fetch_add(1, Ordering::Relaxed).max(1);
    let mut q = Message::empty();
    q.code = code;
    q.payload[..4].copy_from_slice(&id.to_le_bytes());
    let n = payload.len().min(124);
    q.payload[4..4 + n].copy_from_slice(&payload[..n]);
    userlib::ipc_send(NET_REQ, &q).map_err(Error::Sys)?;
    loop {
        let mut r = Message::empty();
        match userlib::ipc_receive_from(NET_RESP, &mut r) {
            Ok(sender) => {
                NETD_PID.store(sender, Ordering::Release);
                if u32::from_le_bytes(r.payload[..4].try_into().unwrap_or([0; 4])) != id {
                    continue;
                }
                return match r.code {
                    np::OK => Ok(r),
                    np::AGAIN => Err(Error::Again),
                    _ => Err(Error::Remote),
                };
            }
            Err(SysError::WouldBlock) => userlib::yield_now(),
            Err(e) => return Err(Error::Sys(e)),
        }
    }
}
pub fn status() -> Result<NetStatus, Error> {
    let r = rpc(np::STATUS, &[])?;
    Ok(NetStatus {
        ip: r.payload[4..8].try_into().map_err(|_| Error::Protocol)?,
        mask: r.payload[8..12].try_into().map_err(|_| Error::Protocol)?,
        gateway: r.payload[12..16].try_into().map_err(|_| Error::Protocol)?,
        dns: r.payload[16..20].try_into().map_err(|_| Error::Protocol)?,
        lease_seconds: u32::from_le_bytes(
            r.payload[20..24].try_into().map_err(|_| Error::Protocol)?,
        ),
    })
}

pub fn tcp_diag() -> Result<TcpDiag, Error> {
    let r = rpc(np::TCP_DIAG, &[])?;
    let rd = |off: usize| -> Result<u32, Error> {
        Ok(u32::from_le_bytes(
            r.payload[off..off + 4]
                .try_into()
                .map_err(|_| Error::Protocol)?,
        ))
    };
    Ok(TcpDiag {
        syn_sent: rd(4)?,
        rx_segments: rd(8)?,
        local_port_match: rd(12)?,
        remote_ip_match: rd(16)?,
        remote_port_match: rd(20)?,
        full_tuple_match: rd(24)?,
        synack_seen: rd(28)?,
        synack_bad_ack: rd(32)?,
        rst_seen: rd(36)?,
        established: rd(40)?,
        last_flags: rd(44)?,
        last_seq: rd(48)?,
        last_ack: rd(52)?,
        last_expected_ack: rd(56)?,
        last_header_len: rd(60)?,
        last_payload_len: rd(64)?,
    })
}
pub fn ping(ip: [u8; 4], seq: u16) -> Result<(), Error> {
    let mut p = [0u8; 6];
    p[..4].copy_from_slice(&ip);
    p[4..6].copy_from_slice(&seq.to_le_bytes());
    rpc(np::PING, &p).map(|_| ())
}
pub fn udp_open(port: u16) -> Result<u32, Error> {
    let r = rpc(np::UDP_OPEN, &port.to_le_bytes())?;
    Ok(u32::from_le_bytes(
        r.payload[4..8].try_into().map_err(|_| Error::Protocol)?,
    ))
}
pub fn udp_send(h: u32, ip: [u8; 4], port: u16, data: &[u8]) -> Result<(), Error> {
    if data.len() > 108 {
        return Err(Error::Protocol);
    }
    let mut p = [0u8; 124];
    p[..4].copy_from_slice(&h.to_le_bytes());
    p[4..8].copy_from_slice(&ip);
    p[8..10].copy_from_slice(&port.to_le_bytes());
    p[10..12].copy_from_slice(&(data.len() as u16).to_le_bytes());
    p[12..12 + data.len()].copy_from_slice(data);
    rpc(np::UDP_SEND, &p[..12 + data.len()]).map(|_| ())
}
pub fn udp_recv(h: u32, out: &mut [u8]) -> Result<Option<([u8; 4], u16, usize)>, Error> {
    let r = match rpc(np::UDP_RECV, &h.to_le_bytes()) {
        Ok(r) => r,
        Err(Error::Again) => return Ok(None),
        Err(e) => return Err(e),
    };
    let ip = r.payload[4..8].try_into().map_err(|_| Error::Protocol)?;
    let port = u16::from_le_bytes(r.payload[8..10].try_into().map_err(|_| Error::Protocol)?);
    let n = u16::from_le_bytes(r.payload[10..12].try_into().map_err(|_| Error::Protocol)?) as usize;
    let n = n.min(out.len()).min(116);
    out[..n].copy_from_slice(&r.payload[12..12 + n]);
    Ok(Some((ip, port, n)))
}
pub fn tcp_connect(ip: [u8; 4], port: u16) -> Result<u32, Error> {
    let mut p = [0u8; 6];
    p[..4].copy_from_slice(&ip);
    p[4..6].copy_from_slice(&port.to_le_bytes());
    let r = rpc(np::TCP_CONNECT, &p)?;
    Ok(u32::from_le_bytes(
        r.payload[4..8].try_into().map_err(|_| Error::Protocol)?,
    ))
}
pub fn tcp_state(h: u32) -> Result<u32, Error> {
    let r = rpc(np::TCP_STATE, &h.to_le_bytes())?;
    Ok(u32::from_le_bytes(
        r.payload[4..8].try_into().map_err(|_| Error::Protocol)?,
    ))
}
pub fn tcp_send(h: u32, data: &[u8]) -> Result<(), Error> {
    if data.len() > 114 {
        return Err(Error::Protocol);
    }
    let mut p = [0u8; 124];
    p[..4].copy_from_slice(&h.to_le_bytes());
    p[4..6].copy_from_slice(&(data.len() as u16).to_le_bytes());
    p[6..6 + data.len()].copy_from_slice(data);
    rpc(np::TCP_SEND, &p[..6 + data.len()]).map(|_| ())
}
pub fn tcp_recv(h: u32, out: &mut [u8]) -> Result<Option<usize>, Error> {
    let mut p = [0u8; 6];
    p[..4].copy_from_slice(&h.to_le_bytes());
    p[4..6].copy_from_slice(&(out.len().min(122) as u16).to_le_bytes());
    let r = match rpc(np::TCP_RECV, &p) {
        Ok(r) => r,
        Err(Error::Again) => return Ok(None),
        Err(e) => return Err(e),
    };
    let actual =
        u16::from_le_bytes(r.payload[4..6].try_into().map_err(|_| Error::Protocol)?) as usize;
    if actual > 122 || actual > out.len() {
        return Err(Error::Protocol);
    }
    out[..actual].copy_from_slice(&r.payload[6..6 + actual]);
    Ok(Some(actual))
}

pub struct BulkBuffer {
    shm: userlib::SharedMemory,
}
impl BulkBuffer {
    pub fn new() -> Result<Self, Error> {
        if NETD_PID.load(Ordering::Acquire) == 0 {
            return Err(Error::Protocol);
        }
        let shm = userlib::shm_create(BULK_SIZE).map_err(Error::Sys)?;
        Ok(Self { shm })
    }
    pub fn capacity(&self) -> usize {
        self.shm.len
    }
    pub fn handle(&self) -> u32 {
        self.shm.handle
    }
}
impl Drop for BulkBuffer {
    fn drop(&mut self) {
        let _ = userlib::shm_release(self.shm.handle);
    }
}

pub fn tcp_recv_bulk(
    h: u32,
    bulk: &mut BulkBuffer,
    out: &mut [u8],
) -> Result<Option<usize>, Error> {
    let max = out.len().min(bulk.shm.len).min(u32::MAX as usize);
    if max == 0 {
        return Ok(Some(0));
    }
    let pid = NETD_PID.load(Ordering::Acquire);
    if pid == 0 {
        return Err(Error::Protocol);
    }
    userlib::shm_grant(bulk.shm.handle, pid).map_err(Error::Sys)?;
    let mut p = [0u8; 12];
    p[0..4].copy_from_slice(&h.to_le_bytes());
    p[4..8].copy_from_slice(&bulk.shm.handle.to_le_bytes());
    p[8..12].copy_from_slice(&(max as u32).to_le_bytes());
    let r = match rpc(np::TCP_RECV_SHM, &p) {
        Ok(r) => r,
        Err(Error::Again) => return Ok(None),
        Err(e) => return Err(e),
    };
    let actual =
        u32::from_le_bytes(r.payload[4..8].try_into().map_err(|_| Error::Protocol)?) as usize;
    if actual > max {
        return Err(Error::Protocol);
    }
    unsafe {
        core::ptr::copy_nonoverlapping(bulk.shm.ptr, out.as_mut_ptr(), actual);
    }
    Ok(Some(actual))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn status_layout() {
        assert_eq!(core::mem::size_of::<NetStatus>(), 20)
    }
    #[test]
    fn payload_limits() {
        assert!(matches!(
            udp_send(1, [1; 4], 1, &[0; 109]),
            Err(Error::Protocol)
        ));
        assert!(matches!(tcp_send(1, &[0; 115]), Err(Error::Protocol)))
    }
}
