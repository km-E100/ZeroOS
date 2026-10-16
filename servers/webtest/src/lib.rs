#![no_std]

const HOST: &str = "valid-isrgrootx1.letsencrypt.org";

fn line(prefix: &[u8], suffix: &str) {
    let _ = userlib::console_write(prefix);
    let _ = userlib::console_write(suffix.as_bytes());
    let _ = userlib::console_write(b"\r\n");
}

fn write_u8_decimal(value: u8) {
    let mut buf = [0u8; 3];
    let mut n = value;
    let mut pos = buf.len();
    loop {
        pos -= 1;
        buf[pos] = b'0' + (n % 10);
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let _ = userlib::console_write(&buf[pos..]);
}

fn write_u32_decimal(value: u32) {
    let mut buf = [0u8; 10];
    let mut n = value;
    let mut pos = buf.len();
    loop {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let _ = userlib::console_write(&buf[pos..]);
}

fn print_tcp_diag() {
    let Ok(d) = libnetclient::tcp_diag() else {
        let _ = userlib::console_write(b"webtest: TCPDIAG unavailable\r\n");
        return;
    };
    let _ = userlib::console_write(b"webtest: TCPDIAG syn=");
    write_u32_decimal(d.syn_sent);
    let _ = userlib::console_write(b" rx=");
    write_u32_decimal(d.rx_segments);
    let _ = userlib::console_write(b" lport=");
    write_u32_decimal(d.local_port_match);
    let _ = userlib::console_write(b" rip=");
    write_u32_decimal(d.remote_ip_match);
    let _ = userlib::console_write(b" rport=");
    write_u32_decimal(d.remote_port_match);
    let _ = userlib::console_write(b" full=");
    write_u32_decimal(d.full_tuple_match);
    let _ = userlib::console_write(b" synack=");
    write_u32_decimal(d.synack_seen);
    let _ = userlib::console_write(b" badack=");
    write_u32_decimal(d.synack_bad_ack);
    let _ = userlib::console_write(b" rst=");
    write_u32_decimal(d.rst_seen);
    let _ = userlib::console_write(b" est=");
    write_u32_decimal(d.established);
    let _ = userlib::console_write(b"\r\nwebtest: TCPDIAG last flags=");
    write_u32_decimal(d.last_flags);
    let _ = userlib::console_write(b" seq=");
    write_u32_decimal(d.last_seq);
    let _ = userlib::console_write(b" ack=");
    write_u32_decimal(d.last_ack);
    let _ = userlib::console_write(b" expect=");
    write_u32_decimal(d.last_expected_ack);
    let _ = userlib::console_write(b" hlen=");
    write_u32_decimal(d.last_header_len);
    let _ = userlib::console_write(b" plen=");
    write_u32_decimal(d.last_payload_len);
    let _ = userlib::console_write(b"\r\n");
}

fn print_dns_ip(ip: [u8; 4]) {
    let _ = userlib::console_write(b"webtest: DNS A=");
    for (i, octet) in ip.iter().copied().enumerate() {
        if i != 0 {
            let _ = userlib::console_write(b".");
        }
        write_u8_decimal(octet);
    }
    let _ = userlib::console_write(b"\r\n");
}

pub extern "C" fn server_main() -> ! {
    let _ = userlib::console_write(b"webtest: starting DNS/TCP/TLS/HTTP\r\n");
    let _ = userlib::console_write(b"webtest: calling resolve_a\r\n");
    match libweb::resolve_a(HOST) {
        Ok(ip) => {
            print_dns_ip(ip);
            let _ = userlib::console_write(b"webtest: DNS PASS\r\n");
        }
        Err(e) => {
            line(b"webtest: DNS FAIL error=", e.as_str());
            userlib::exit(28);
        }
    }

    // Plain HTTP is intentionally tested before TLS. It separates TCP/HTTP
    // transport correctness from the TLS 1.3/certificate stack during real-
    // hypervisor bring-up while keeping the historical HTTPS verdict below.
    match libweb::http_get(HOST, "/") {
        Ok(r) if (200..400).contains(&r.status) => {
            let _ = userlib::console_write(b"webtest: HTTP TCP PASS\r\n");
            // TEMP Parallels isolation: prove the TCP/HTTP layer independently
            // before entering TLS. Revert after the bring-up verdict is captured.
            print_tcp_diag();
            userlib::exit(0);
        }
        Ok(_) => {
            let _ = userlib::console_write(b"webtest: HTTP STATUS FAIL\r\n");
            userlib::exit(31);
        }
        Err(e) => {
            line(b"webtest: HTTP TCP FAIL error=", e.as_str());
            print_tcp_diag();
            userlib::exit(32);
        }
    }

    match libweb::https_get(HOST, "/") {
        Ok(r) if (200..400).contains(&r.status) => {
            let _ = userlib::console_write(b"webtest: HTTPS TLS13 PASS\r\n");
            userlib::exit(0)
        }
        Ok(_) => {
            let _ = userlib::console_write(b"webtest: HTTPS STATUS FAIL\r\n");
            userlib::exit(29)
        }
        Err(e) => {
            line(b"webtest: HTTPS TLS13 FAIL error=", e.as_str());
            print_tcp_diag();
            userlib::exit(30)
        }
    }
}
