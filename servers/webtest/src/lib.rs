#![no_std]

pub extern "C" fn server_main() -> ! {
    let _ = userlib::console_write(b"webtest: starting DNS/TLS/HTTP\r\n");
    let _ = userlib::console_write(b"webtest: calling resolve_a\r\n");
    match libweb::resolve_a("valid-isrgrootx1.letsencrypt.org") {
        Ok(_) => {
            let _ = userlib::console_write(b"webtest: DNS PASS\r\n");
        }
        Err(_) => {
            let _ = userlib::console_write(b"webtest: DNS FAIL\r\n");
            userlib::exit(28);
        }
    }
    match libweb::https_get("valid-isrgrootx1.letsencrypt.org", "/") {
        Ok(r) if (200..400).contains(&r.status) => {
            let _ = userlib::console_write(b"webtest: HTTPS TLS13 PASS\r\n");
            userlib::exit(0)
        }
        Ok(_) => {
            let _ = userlib::console_write(b"webtest: HTTPS STATUS FAIL\r\n");
            userlib::exit(29)
        }
        Err(_) => {
            let _ = userlib::console_write(b"webtest: HTTPS TLS13 FAIL\r\n");
            userlib::exit(30)
        }
    }
}
