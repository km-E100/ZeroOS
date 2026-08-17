use core::fmt::{self, Write};
use core::panic::PanicInfo;

use super::serial;

struct SerialSink;

impl Write for SerialSink {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        serial::write_str(s);
        Ok(())
    }
}

pub fn log(args: fmt::Arguments<'_>) {
    let mut sink = SerialSink;
    let _ = sink.write_fmt(args);
    let _ = sink.write_str("\n");
}

#[allow(deprecated)]
pub fn log_panic(info: &PanicInfo) {
    let mut sink = SerialSink;
    let location = info.location();
    let (slot, pid) = current_process_info();
    let _ = sink.write_str("panic");
    if let Some(loc) = location {
        let _ = write!(sink, " at {}:{}", loc.file(), loc.line());
    }
    if let Some(slot) = slot {
        let pid_text = pid.map(|p| p as i64).unwrap_or(-1);
        let _ = write!(sink, " (slot={} pid={})", slot, pid_text);
    }
    let _ = sink.write_str(": ");
    let msg = info.message();
    if let Some(s) = msg.as_str() {
        let _ = sink.write_str(s);
    } else {
        let _ = sink.write_str("<non-string panic payload>");
    }
    let _ = sink.write_str("\n");
}

fn current_process_info() -> (Option<usize>, Option<u64>) {
    let slot = crate::scheduler::current_slot_opt();
    let pid = slot.and_then(|slot| crate::process::pid_at_slot(slot).map(|pid| pid.raw()));
    (slot, pid)
}
