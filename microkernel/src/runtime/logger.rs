use core::fmt::{self, Write};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU8, Ordering};

use super::serial;

/// 日志级别。数值越小越严重；`log_at` 仅在 `level <= 当前阈值` 时输出。
///
/// 默认阈值是 `Info`：保留启动横幅与关键事件（进程退出、异常终止、
/// 服务拉起），屏蔽 trap/调度等高频路径的噪音。
/// 调试内核时调用 `logger::set_level(Level::Debug)` 打开全量输出。
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

static LOG_LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

pub fn set_level(level: Level) {
    LOG_LEVEL.store(level as u8, Ordering::Relaxed);
}

pub fn level() -> Level {
    match LOG_LEVEL.load(Ordering::Relaxed) {
        0 => Level::Error,
        1 => Level::Warn,
        3 => Level::Debug,
        _ => Level::Info,
    }
}

fn should_log(level: Level) -> bool {
    (level as u8) <= LOG_LEVEL.load(Ordering::Relaxed)
}

struct SerialSink;

impl Write for SerialSink {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        serial::write_str(s);
        Ok(())
    }
}

/// info 级输出（lib.rs 的 `info!` 宏走这里；语义 = Info 级别，受阈值控制）。
pub fn log(args: fmt::Arguments<'_>) {
    log_at(Level::Info, args);
}

/// 分级输出：低于阈值的调用被静默丢弃。
/// 日志直写 PL011 无缓冲，阈值过滤同时省下串口写。
pub fn log_at(level: Level, args: fmt::Arguments<'_>) {
    if !should_log(level) {
        return;
    }
    let mut sink = SerialSink;
    let _ = sink.write_fmt(args);
    let _ = sink.write_str("\n");
}

/// 错误级：内核故障、无法恢复的不变量破坏。正常运行期不应出现。
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {{
        $crate::runtime::logger::log_at(
            $crate::runtime::logger::Level::Error,
            ::core::format_args!($($arg)*),
        );
    }};
}

/// 警告级：进程退出/终止等审计事件、资源耗尽前的边界情况。
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {{
        $crate::runtime::logger::log_at(
            $crate::runtime::logger::Level::Warn,
            ::core::format_args!($($arg)*),
        );
    }};
}

/// 调试级：每次 trap/IRQ/tick、逐页映射等高频路径。默认关闭。
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {{
        $crate::runtime::logger::log_at(
            $crate::runtime::logger::Level::Debug,
            ::core::format_args!($($arg)*),
        );
    }};
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