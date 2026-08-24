use core::fmt::{self, Write};
use core::ptr::NonNull;
use spin::Mutex;
use uefi::prelude::*;
use uefi::proto::console::text::{Color, Output};

static CONSOLE: Mutex<Option<Console>> = Mutex::new(None);

pub fn init(st: &mut SystemTable<Boot>) {
    let stdout = st.stdout();
    let mut stdout_ptr = NonNull::from(stdout);
    *CONSOLE.lock() = Some(Console { output: stdout_ptr });
    unsafe {
        let output = stdout_ptr.as_mut();
        output.reset(false).ok();
        output.clear().ok();
    }
}

struct Console {
    output: NonNull<Output>,
}

unsafe impl Send for Console {}
unsafe impl Sync for Console {}

impl Console {
    fn write_line(&mut self, level: LogLevel, args: fmt::Arguments<'_>) {
        unsafe {
            let output = self.output.as_mut();
            let _ = output.set_color(Color::LightGray, Color::Black);
            let _ = output.write_str("[");
            let _ = output.set_color(level.color(), Color::Black);
            let _ = output.write_str(level.label());
            let _ = output.set_color(Color::LightGray, Color::Black);
            let _ = output.write_str("] ");
            let _ = output.write_fmt(args);
            let _ = output.write_str("\r\n");
        }
    }
}

fn with_console<F>(mut f: F)
where
    F: FnMut(&mut Console),
{
    if let Some(console) = CONSOLE.lock().as_mut() {
        f(console);
    }
}

#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Critical,
}

impl LogLevel {
    fn label(self) -> &'static str {
        match self {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Critical => "CRIT",
        }
    }

    fn color(self) -> Color {
        match self {
            LogLevel::Debug => Color::LightGray,
            LogLevel::Info => Color::LightGreen,
            LogLevel::Warn => Color::Yellow,
            LogLevel::Error => Color::LightRed,
            LogLevel::Critical => Color::Red,
        }
    }
}

pub fn log_args(level: LogLevel, args: fmt::Arguments<'_>) {
    with_console(|console| {
        console.write_line(level, args);
    });
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        $crate::console::log_args($crate::console::LogLevel::Debug, format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        $crate::console::log_args($crate::console::LogLevel::Info, format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        $crate::console::log_args($crate::console::LogLevel::Warn, format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        $crate::console::log_args($crate::console::LogLevel::Error, format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! log_critical {
    ($($arg:tt)*) => {
        $crate::console::log_args($crate::console::LogLevel::Critical, format_args!($($arg)*));
    };
}
