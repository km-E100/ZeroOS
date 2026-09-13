#![no_std]
extern crate alloc;

use alloc::{string::String, vec, vec::Vec};
use core::{fmt, num::NonZeroU32};
use embedded_io::{ErrorKind, ErrorType, Read, Write};
use embedded_tls::{
    blocking::TlsConnection, pki::CertVerifier as RustPkiCertVerifier, Aes128GcmSha256,
    Certificate, CertificateEntryRef, CertificateRef, CertificateVerifyRef, CryptoProvider,
    TlsClock, TlsConfig, TlsContext, TlsError, TlsVerifier,
};
use p256::ecdsa::DerSignature;
use rand_core::{CryptoRng, Error as RandError, RngCore};

const ROOT_CA_DER: &[u8] = include_bytes!("../../../libs/certs/isrgrootx1.der");
const DNS_TIMEOUT_TICKS: u64 = 500;
const TCP_TIMEOUT_TICKS: u64 = 800;
const MAX_HTTP_RESPONSE: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Network,
    Timeout,
    Dns,
    Protocol,
    Tls,
    TooLarge,
    Entropy,
}

impl Error {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Timeout => "timeout",
            Self::Dns => "dns",
            Self::Protocol => "protocol",
            Self::Tls => "tls",
            Self::TooLarge => "too-large",
            Self::Entropy => "entropy",
        }
    }
}

#[derive(Debug)]
pub struct NetIoError;
impl fmt::Display for NetIoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Zero OS TCP I/O error")
    }
}
impl core::error::Error for NetIoError {}
impl embedded_io::Error for NetIoError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::Other
    }
}

pub struct TcpStream {
    handle: u32,
    bulk: Option<libnetclient::BulkBuffer>,
}
impl TcpStream {
    pub fn connect(ip: [u8; 4], port: u16) -> Result<Self, Error> {
        let h = loop {
            match libnetclient::tcp_connect(ip, port) {
                Ok(h) => break h,
                Err(libnetclient::Error::Again) => {
                    let _ = userlib::sleep_ticks(1);
                }
                Err(_) => return Err(Error::Network),
            }
        };
        for _ in 0..TCP_TIMEOUT_TICKS {
            match libnetclient::tcp_state(h) {
                Ok(2) => {
                    return Ok(Self {
                        handle: h,
                        bulk: libnetclient::BulkBuffer::new().ok(),
                    })
                }
                Ok(3) => return Err(Error::Network),
                Ok(_) | Err(libnetclient::Error::Again) => {
                    let _ = userlib::sleep_ticks(1);
                }
                Err(_) => return Err(Error::Network),
            }
        }
        Err(Error::Timeout)
    }
}
impl ErrorType for TcpStream {
    type Error = NetIoError;
}
impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let got = if let Some(bulk) = self.bulk.as_mut() {
                libnetclient::tcp_recv_bulk(self.handle, bulk, buf)
            } else {
                libnetclient::tcp_recv(self.handle, buf)
            };
            match got {
                Ok(Some(n)) if n > 0 => return Ok(n),
                Ok(_) | Err(libnetclient::Error::Again) => {
                    if matches!(libnetclient::tcp_state(self.handle), Ok(3)) {
                        return Ok(0);
                    }
                    let _ = userlib::sleep_ticks(1);
                }
                Err(_) => return Err(NetIoError),
            }
        }
    }
}
impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut off = 0usize;
        while off < buf.len() {
            let end = (off + 114).min(buf.len());
            loop {
                match libnetclient::tcp_send(self.handle, &buf[off..end]) {
                    Ok(()) => break,
                    Err(libnetclient::Error::Again) => {
                        let _ = userlib::sleep_ticks(1);
                    }
                    Err(_) => return Err(NetIoError),
                }
            }
            off = end;
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct ZeroRng;
impl RngCore for ZeroRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest)
            .expect("Zero OS entropy source unavailable")
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        userlib::getrandom(dest).map_err(|_| RandError::from(NonZeroU32::new(1).unwrap()))
    }
}
impl CryptoRng for ZeroRng {}

struct ZeroClock;
impl TlsClock for ZeroClock {
    fn now() -> Option<u64> {
        userlib::realtime_ns().ok().map(|v| v / 1_000_000_000)
    }
}

struct VerifiedProvider<'a> {
    rng: ZeroRng,
    verifier: RustPkiCertVerifier<'a, Aes128GcmSha256, ZeroClock, 8192>,
}
impl CryptoProvider for VerifiedProvider<'_> {
    type CipherSuite = Aes128GcmSha256;
    type Signature = DerSignature;
    fn rng(&mut self) -> impl embedded_tls::CryptoRngCore {
        &mut self.rng
    }
    fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Aes128GcmSha256>, TlsError> {
        Ok(&mut self.verifier)
    }
}

struct IpVerifiedProvider<'a> {
    rng: ZeroRng,
    verifier: IpSanVerifier<'a>,
}
impl CryptoProvider for IpVerifiedProvider<'_> {
    type CipherSuite = Aes128GcmSha256;
    type Signature = DerSignature;
    fn rng(&mut self) -> impl embedded_tls::CryptoRngCore {
        &mut self.rng
    }
    fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Aes128GcmSha256>, TlsError> {
        Ok(&mut self.verifier)
    }
}

/// `embedded-tls` rustpki 0.19 only exposes dNSName SANs. Keep its proven
/// chain/time/CertificateVerify logic, but add the missing RFC 5280 iPAddress
/// SAN gate for IP-literal repositories before delegating to it.
struct IpSanVerifier<'a> {
    expected: [u8; 4],
    inner: RustPkiCertVerifier<'a, Aes128GcmSha256, ZeroClock, 8192>,
}
impl<'a> IpSanVerifier<'a> {
    fn new(expected: [u8; 4], ca: &'a [u8]) -> Self {
        Self {
            expected,
            inner: RustPkiCertVerifier::new(Certificate::X509(ca)),
        }
    }
}
impl TlsVerifier<Aes128GcmSha256> for IpSanVerifier<'_> {
    fn set_hostname_verification(&mut self, hostname: &str) -> Result<(), TlsError> {
        if parse_ipv4_literal(hostname) != Some(self.expected) {
            return Err(TlsError::InvalidCertificate);
        }
        // The inner verifier still checks CN as a compatibility backstop; the
        // authoritative identity check is `certificate_has_ipv4_san` below.
        self.inner.set_hostname_verification(hostname)
    }
    fn verify_certificate(
        &mut self,
        transcript: &<Aes128GcmSha256 as embedded_tls::TlsCipherSuite>::Hash,
        cert: CertificateRef,
    ) -> Result<(), TlsError> {
        let leaf = match cert.entries.first() {
            Some(CertificateEntryRef::X509(der)) => *der,
            _ => return Err(TlsError::InvalidCertificate),
        };
        if !certificate_has_ipv4_san(leaf, self.expected) {
            return Err(TlsError::InvalidCertificate);
        }
        self.inner.verify_certificate(transcript, cert)
    }
    fn verify_signature(&mut self, verify: CertificateVerifyRef) -> Result<(), TlsError> {
        self.inner.verify_signature(verify)
    }
}

fn der_len(bytes: &[u8], off: &mut usize) -> Option<usize> {
    let first = *bytes.get(*off)?;
    *off += 1;
    if first & 0x80 == 0 {
        return Some(first as usize);
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > core::mem::size_of::<usize>() {
        return None;
    }
    let mut len = 0usize;
    for _ in 0..n {
        len = len
            .checked_mul(256)?
            .checked_add(*bytes.get(*off)? as usize)?;
        *off += 1;
    }
    Some(len)
}
fn der_tlv<'a>(bytes: &'a [u8], off: &mut usize) -> Option<(u8, &'a [u8])> {
    let tag = *bytes.get(*off)?;
    *off += 1;
    let len = der_len(bytes, off)?;
    let end = off.checked_add(len)?;
    let content = bytes.get(*off..end)?;
    *off = end;
    Some((tag, content))
}
fn general_names_has_ipv4(bytes: &[u8], expected: [u8; 4]) -> bool {
    let mut o = 0;
    let Some((0x30, seq)) = der_tlv(bytes, &mut o) else {
        return false;
    };
    let mut i = 0;
    while i < seq.len() {
        let Some((tag, c)) = der_tlv(seq, &mut i) else {
            return false;
        };
        if tag == 0x87 && c == expected {
            return true;
        } // [7] iPAddress, raw network bytes
    }
    false
}
fn scan_for_san(bytes: &[u8], expected: [u8; 4], depth: u8) -> bool {
    if depth > 16 {
        return false;
    }
    let mut o = 0;
    while o < bytes.len() {
        let before = o;
        let Some((tag, c)) = der_tlv(bytes, &mut o) else {
            return false;
        };
        if tag == 0x30 {
            // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL,
            //                          extnValue OCTET STRING }
            let mut e = 0;
            if let Some((0x06, oid)) = der_tlv(c, &mut e) {
                if oid == [0x55, 0x1d, 0x11] {
                    // 2.5.29.17 subjectAltName
                    if let Some((0x01, _)) = peek_tlv(c, e) {
                        let _ = der_tlv(c, &mut e);
                    }
                    if let Some((0x04, octets)) = der_tlv(c, &mut e) {
                        if general_names_has_ipv4(octets, expected) {
                            return true;
                        }
                    }
                }
            }
        }
        if tag & 0x20 != 0 && scan_for_san(c, expected, depth + 1) {
            return true;
        }
        if o <= before {
            return false;
        }
    }
    false
}
fn peek_tlv<'a>(bytes: &'a [u8], mut off: usize) -> Option<(u8, &'a [u8])> {
    der_tlv(bytes, &mut off)
}
fn certificate_has_ipv4_san(der: &[u8], expected: [u8; 4]) -> bool {
    scan_for_san(der, expected, 0)
}

static DNS_ID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0x5a00);

fn parse_ipv4_literal(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut i = 0usize;
    for part in s.split('.') {
        if i >= 4 {
            return None;
        };
        out[i] = part.parse::<u8>().ok()?;
        i += 1;
    }
    (i == 4).then_some(out)
}

pub fn resolve_a(host: &str) -> Result<[u8; 4], Error> {
    validate_hostname(host)?;
    if let Some(ip) = parse_ipv4_literal(host) {
        return Ok(ip);
    }
    let status = loop {
        match libnetclient::status() {
            Ok(s) => break s,
            Err(libnetclient::Error::Again) => {
                let _ = userlib::sleep_ticks(1);
            }
            Err(_) => return Err(Error::Network),
        }
    };
    if status.dns == [0; 4] {
        return Err(Error::Dns);
    }
    let id = DNS_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed) as u16;
    let query = build_dns_query(id, host)?;
    let port = 53000u16.wrapping_add(id % 1000);
    let sock = libnetclient::udp_open(port).map_err(|_| Error::Network)?;
    libnetclient::udp_send(sock, status.dns, 53, &query).map_err(|_| Error::Network)?;
    let mut buf = [0u8; 116];
    for _ in 0..DNS_TIMEOUT_TICKS {
        match libnetclient::udp_recv(sock, &mut buf) {
            Ok(Some((src, 53, n))) if src == status.dns => {
                return parse_dns_a(id, &buf[..n]).ok_or(Error::Dns);
            }
            Ok(_) | Err(libnetclient::Error::Again) => {
                let _ = userlib::sleep_ticks(1);
            }
            Err(_) => return Err(Error::Network),
        }
    }
    Err(Error::Timeout)
}

fn validate_hostname(host: &str) -> Result<(), Error> {
    if host.is_empty()
        || host.len() > 253
        || host
            .bytes()
            .any(|b| !(b.is_ascii_alphanumeric() || b == b'.' || b == b'-'))
    {
        Err(Error::Dns)
    } else {
        Ok(())
    }
}
fn build_dns_query(id: u16, host: &str) -> Result<Vec<u8>, Error> {
    let mut b = Vec::with_capacity(12 + host.len() + 6);
    b.extend_from_slice(&id.to_be_bytes());
    b.extend_from_slice(&0x0100u16.to_be_bytes());
    b.extend_from_slice(&1u16.to_be_bytes());
    b.extend_from_slice(&0u16.to_be_bytes());
    b.extend_from_slice(&0u16.to_be_bytes());
    b.extend_from_slice(&0u16.to_be_bytes());
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(Error::Dns);
        }
        b.push(label.len() as u8);
        b.extend_from_slice(label.as_bytes());
    }
    b.push(0);
    b.extend_from_slice(&1u16.to_be_bytes());
    b.extend_from_slice(&1u16.to_be_bytes());
    Ok(b)
}
fn skip_name(b: &[u8], mut i: usize) -> Option<usize> {
    for _ in 0..128 {
        let n = *b.get(i)?;
        if n & 0xc0 == 0xc0 {
            return i.checked_add(2).filter(|v| *v <= b.len());
        }
        if n == 0 {
            return Some(i + 1);
        };
        if n & 0xc0 != 0 {
            return None;
        };
        i = i.checked_add(1 + n as usize)?;
        if i > b.len() {
            return None;
        }
    }
    None
}
fn parse_dns_a(id: u16, b: &[u8]) -> Option<[u8; 4]> {
    if b.len() < 12
        || u16::from_be_bytes([b[0], b[1]]) != id
        || b[2] & 0x80 == 0
        || b[3] & 0x0f != 0
    {
        return None;
    }
    let qd = u16::from_be_bytes([b[4], b[5]]) as usize;
    let an = u16::from_be_bytes([b[6], b[7]]) as usize;
    let mut i = 12;
    for _ in 0..qd {
        i = skip_name(b, i)?;
        i = i.checked_add(4)?;
        if i > b.len() {
            return None;
        }
    }
    for _ in 0..an {
        i = skip_name(b, i)?;
        if i + 10 > b.len() {
            return None;
        };
        let typ = u16::from_be_bytes([b[i], b[i + 1]]);
        let cls = u16::from_be_bytes([b[i + 2], b[i + 3]]);
        let n = u16::from_be_bytes([b[i + 8], b[i + 9]]) as usize;
        i += 10;
        if i + n > b.len() {
            return None;
        };
        if typ == 1 && cls == 1 && n == 4 {
            return b[i..i + 4].try_into().ok();
        }
        i += n
    }
    None
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

pub fn http_get(host: &str, path: &str) -> Result<HttpResponse, Error> {
    let ip = resolve_a(host)?;
    let mut tcp = TcpStream::connect(ip, 80)?;
    let req = request(host, path);
    tcp.write_all(req.as_bytes()).map_err(|_| Error::Network)?;
    read_http(&mut tcp)
}

pub fn https_get(host: &str, path: &str) -> Result<HttpResponse, Error> {
    https_get_with_ca(host, 443, path, ROOT_CA_DER)
}

pub fn https_get_with_ca(
    host: &str,
    port: u16,
    path: &str,
    ca_der: &[u8],
) -> Result<HttpResponse, Error> {
    let ip = resolve_a(host)?;
    let tcp = TcpStream::connect(ip, port)?;
    let mut rb = vec![0u8; 16640];
    let mut wb = vec![0u8; 4096];
    let cfg = TlsConfig::new()
        .with_server_name(host)
        .enable_rsa_signatures();
    let req = request(host, path);
    if parse_ipv4_literal(host).is_some() {
        // rustpki in embedded-tls 0.19 only extracts dNSName SANs. For an
        // IP-literal repository use the webpki verifier, which validates an
        // actual iPAddress SAN and still checks CA, validity and CertificateVerify.
        let provider = IpVerifiedProvider {
            rng: ZeroRng,
            verifier: IpSanVerifier::new(ip, ca_der),
        };
        let mut tls: TlsConnection<'_, _, Aes128GcmSha256> =
            TlsConnection::new(tcp, &mut rb, &mut wb);
        tls.open(TlsContext::new(&cfg, provider))
            .map_err(|_| Error::Tls)?;
        tls.write_all(req.as_bytes()).map_err(|_| Error::Tls)?;
        tls.flush().map_err(|_| Error::Tls)?;
        let result = read_http_tls(&mut tls);
        result
    } else {
        let provider = VerifiedProvider {
            rng: ZeroRng,
            verifier: RustPkiCertVerifier::new(Certificate::X509(ca_der)),
        };
        let mut tls: TlsConnection<'_, _, Aes128GcmSha256> =
            TlsConnection::new(tcp, &mut rb, &mut wb);
        tls.open(TlsContext::new(&cfg, provider))
            .map_err(|_| Error::Tls)?;
        tls.write_all(req.as_bytes()).map_err(|_| Error::Tls)?;
        tls.flush().map_err(|_| Error::Tls)?;
        read_http_tls(&mut tls)
    }
}

fn request(host: &str, path: &str) -> String {
    let mut s = String::new();
    use core::fmt::Write as _;
    let _=write!(s,"GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: ZeroOS/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n",if path.is_empty(){"/"}else{path},host);
    s
}
fn read_http_tls<R>(r: &mut R) -> Result<HttpResponse, Error>
where
    R: Read<Error = TlsError>,
{
    let mut raw = Vec::new();
    let mut tmp = [0u8; 16 * 1024];
    loop {
        if http_message_complete(&raw)? {
            return parse_http(&raw);
        }
        match r.read(&mut tmp) {
            Ok(0) | Err(TlsError::ConnectionClosed) => break,
            Ok(n) => {
                if raw.len() + n > MAX_HTTP_RESPONSE {
                    return Err(Error::TooLarge);
                }
                raw.extend_from_slice(&tmp[..n]);
            }
            Err(_) => return Err(Error::Network),
        }
    }
    // HTTP/1.0 and HTTP/1.1 `Connection: close` responses legitimately use
    // transport close as message framing. embedded-tls reports close_notify (and
    // an underlying EOF) as ConnectionClosed; at that point the bytes already
    // authenticated by TLS are the complete close-delimited response.
    parse_http(&raw)
}

fn read_http<R: Read>(r: &mut R) -> Result<HttpResponse, Error> {
    let mut raw = Vec::new();
    let mut tmp = [0u8; 16 * 1024];
    loop {
        // Do not make HTTP correctness depend on transport EOF. Once framing
        // proves the response complete (Content-Length or terminal chunk),
        // return immediately; TLS peers are allowed to keep the connection or
        // close it without giving this layer a special EOF signal.
        if http_message_complete(&raw)? {
            return parse_http(&raw);
        }
        let n = r.read(&mut tmp).map_err(|_| Error::Network)?;
        if n == 0 {
            break;
        }
        if raw.len() + n > MAX_HTTP_RESPONSE {
            return Err(Error::TooLarge);
        }
        raw.extend_from_slice(&tmp[..n]);
    }
    parse_http(&raw)
}

fn http_message_complete(raw: &[u8]) -> Result<bool, Error> {
    let Some(sep) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Ok(false);
    };
    let head = &raw[..sep];
    let body = &raw[sep + 4..];
    let mut content_len = None;
    let mut chunked = false;
    for line in head.split(|b| *b == b'\n') {
        let line = core::str::from_utf8(line)
            .map_err(|_| Error::Protocol)?
            .trim();
        if let Some(v) = line
            .strip_prefix("Content-Length:")
            .or_else(|| line.strip_prefix("content-length:"))
        {
            content_len = Some(v.trim().parse::<usize>().map_err(|_| Error::Protocol)?);
        }
        if line.eq_ignore_ascii_case("Transfer-Encoding: chunked") {
            chunked = true;
        }
    }
    if chunked {
        return Ok(chunked_complete(body));
    }
    if let Some(n) = content_len {
        return Ok(body.len() >= n);
    }
    // No explicit framing: caller must use connection close.
    Ok(false)
}

fn chunked_complete(mut b: &[u8]) -> bool {
    loop {
        let Some(e) = b.windows(2).position(|w| w == b"\r\n") else {
            return false;
        };
        let Ok(line) = core::str::from_utf8(&b[..e]) else {
            return false;
        };
        let Ok(n) = usize::from_str_radix(line.split(';').next().unwrap_or(""), 16) else {
            return false;
        };
        b = &b[e + 2..];
        if n == 0 {
            // RFC 9112 allows trailers terminated by an empty line. Accept the
            // common no-trailer form and any complete trailer block.
            return b.starts_with(b"\r\n") || b.windows(4).any(|w| w == b"\r\n\r\n");
        }
        if b.len() < n + 2 || &b[n..n + 2] != b"\r\n" {
            return false;
        }
        b = &b[n + 2..];
    }
}

fn parse_http(raw: &[u8]) -> Result<HttpResponse, Error> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(Error::Protocol)?;
    let head = &raw[..sep];
    let line_end = head
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(head.len());
    let line = core::str::from_utf8(&head[..line_end]).map_err(|_| Error::Protocol)?;
    let mut parts = line.split_whitespace();
    if !parts.next().unwrap_or("").starts_with("HTTP/") {
        return Err(Error::Protocol);
    }
    let status = parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or(Error::Protocol)?;
    let body = &raw[sep + 4..];
    let chunked = head.split(|b| *b == b'\n').any(|l| {
        core::str::from_utf8(l)
            .ok()
            .map(|s| s.trim().eq_ignore_ascii_case("transfer-encoding: chunked"))
            .unwrap_or(false)
    });
    let body = if chunked {
        decode_chunked(body)?
    } else {
        body.to_vec()
    };
    Ok(HttpResponse { status, body })
}
fn decode_chunked(mut b: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    loop {
        let e = b
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or(Error::Protocol)?;
        let line = core::str::from_utf8(&b[..e]).map_err(|_| Error::Protocol)?;
        let n = usize::from_str_radix(line.split(';').next().unwrap_or(""), 16)
            .map_err(|_| Error::Protocol)?;
        b = &b[e + 2..];
        if n == 0 {
            return Ok(out);
        }
        if b.len() < n + 2 || &b[n..n + 2] != b"\r\n" {
            return Err(Error::Protocol);
        }
        out.extend_from_slice(&b[..n]);
        b = &b[n + 2..];
        if out.len() > MAX_HTTP_RESPONSE {
            return Err(Error::TooLarge);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_query_and_compressed_answer() {
        let q = build_dns_query(7, "a.test").unwrap();
        assert_eq!(&q[..2], &[0, 7]);
        let mut r = q.clone();
        r[2] = 0x81;
        r[3] = 0x80;
        r[6] = 0;
        r[7] = 1;
        r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4]);
        assert_eq!(parse_dns_a(7, &r), Some([1, 2, 3, 4]));
    }
    #[test]
    fn parses_real_qemu_slirp_dns_answer() {
        let b: &[u8] = &[
            0x5a, 0x00, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10, b'v',
            b'a', b'l', b'i', b'd', b'-', b'i', b's', b'r', b'g', b'r', b'o', b'o', b't', b'x',
            b'1', 0x0b, b'l', b'e', b't', b's', b'e', b'n', b'c', b'r', b'y', b'p', b't', 0x03,
            b'o', b'r', b'g', 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0xc6, 0x12, 0x01, 0x9e,
        ];
        assert_eq!(parse_dns_a(0x5a00, b), Some([198, 18, 1, 158]));
    }
    #[test]
    fn strict_ip_san_matches_real_dev_certificate() {
        let cert = include_bytes!("../../../tools/testkeys/zeropkg-repo-server.cert.der");
        assert!(certificate_has_ipv4_san(cert, [10, 0, 2, 2]));
        assert!(!certificate_has_ipv4_san(cert, [10, 0, 2, 3]));
    }
    #[test]
    fn http_plain_and_chunked() {
        let r = parse_http(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(&r.body, b"ok");
        let r =
            parse_http(b"HTTP/1.0 200 ok\r\nContent-type: text/plain\r\n\r\nclose-body").unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(&r.body, b"close-body");
        let r = parse_http(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(&r.body, b"ok");
        assert!(http_message_complete(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap());
        assert!(!http_message_complete(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok").unwrap());
        assert!(http_message_complete(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"
        )
        .unwrap());
    }
}
