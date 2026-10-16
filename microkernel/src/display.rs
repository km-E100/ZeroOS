//! Display Foundation：UEFI GOP framebuffer + 软件 2D + UTF-8 图形控制台。
//!
//! 串口仍是权威诊断出口；图形 sink 是可选镜像。GOP 不存在/格式不支持时
//! 全部 API 静默 no-op，不影响 headless acceptance。

use core::fmt::{self, Write};
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::display_font::{ASCII, CJK, GLYPH_HEIGHT};

extern "C" {
    static __zero_fb_base: u64;
    static __zero_fb_size: u64;
    static __zero_fb_width: u64;
    static __zero_fb_height: u64;
    static __zero_fb_stride: u64;
    static __zero_fb_format: u64;
}

const FG: Rgb = Rgb {
    r: 0xea,
    g: 0xea,
    b: 0xe7,
};
const BG: Rgb = Rgb {
    r: 0x18,
    g: 0x19,
    b: 0x1b,
};
const MARGIN: usize = 8;
const CELL_ADVANCE: usize = 9;
const CELL_CLEAR_WIDTH: usize = 16;
const CSI_MAX_PARAMS: usize = 4;
const MAX_CONSOLE_CELLS: usize = 8192;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct Rect {
    pub x: usize,
    pub y: usize,
    pub w: usize,
    pub h: usize,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Format {
    Rgbx,
    Bgrx,
}

#[derive(Copy, Clone)]
struct Framebuffer {
    base: usize,
    size: usize,
    width: usize,
    height: usize,
    stride: usize,
    format: Format,
    /// GOP is firmware/device memory and requires volatile accesses; VirtIO-GPU
    /// backing is ordinary coherent RAM and can use bulk copies.
    volatile: bool,
    /// Some scanout backends expose their first memory row at the visual
    /// bottom. Keep the console in normal top-left coordinates and flip only
    /// the physical row calculation for those backends.
    flip_y: bool,
}

impl Framebuffer {
    fn from_boot() -> Option<Self> {
        let base = unsafe { core::ptr::addr_of!(__zero_fb_base).read_volatile() as usize };
        let size = unsafe { core::ptr::addr_of!(__zero_fb_size).read_volatile() as usize };
        let width = unsafe { core::ptr::addr_of!(__zero_fb_width).read_volatile() as usize };
        let height = unsafe { core::ptr::addr_of!(__zero_fb_height).read_volatile() as usize };
        let stride = unsafe { core::ptr::addr_of!(__zero_fb_stride).read_volatile() as usize };
        let format = match unsafe { core::ptr::addr_of!(__zero_fb_format).read_volatile() } {
            1 => Format::Rgbx,
            2 => Format::Bgrx,
            _ => return None,
        };
        if base == 0
            || width == 0
            || height == 0
            || stride < width
            || width > 16384
            || height > 16384
        {
            return None;
        }
        let required = stride.checked_mul(height)?.checked_mul(4)?;
        if size < required {
            return None;
        }
        Some(Self {
            base,
            size,
            width,
            height,
            stride,
            format,
            volatile: true,
            flip_y: crate::bootinfo::platform_kind() == crate::bootinfo::PLATFORM_PARALLELS_ARM,
        })
    }

    #[inline]
    fn offset(&self, x: usize, y: usize) -> Option<usize> {
        if x >= self.width || y >= self.height {
            return None;
        }
        let physical_y = if self.flip_y {
            self.height.checked_sub(1)?.checked_sub(y)?
        } else {
            y
        };
        let off = (physical_y.checked_mul(self.stride)?.checked_add(x)?).checked_mul(4)?;
        (off + 4 <= self.size).then_some(off)
    }

    fn pixel(&self, x: usize, y: usize) -> Option<Rgb> {
        let off = self.offset(x, y)?;
        let ptr = (self.base + off) as *const u32;
        let raw = unsafe {
            if self.volatile {
                read_volatile(ptr)
            } else {
                ptr.read()
            }
        };
        let v = raw.to_le_bytes();
        Some(match self.format {
            Format::Rgbx => Rgb {
                r: v[0],
                g: v[1],
                b: v[2],
            },
            Format::Bgrx => Rgb {
                r: v[2],
                g: v[1],
                b: v[0],
            },
        })
    }

    fn put(&self, x: usize, y: usize, c: Rgb) {
        let Some(off) = self.offset(x, y) else { return };
        let bytes = match self.format {
            Format::Rgbx => [c.r, c.g, c.b, 0],
            Format::Bgrx => [c.b, c.g, c.r, 0],
        };
        let ptr = (self.base + off) as *mut u32;
        let value = u32::from_le_bytes(bytes);
        unsafe {
            if self.volatile {
                write_volatile(ptr, value)
            } else {
                ptr.write(value)
            }
        };
    }
}

#[derive(Copy, Clone, Debug, Default)]
struct ConsoleCell {
    x: u16,
    y: u16,
    codepoint: u32,
    width: u8,
}

struct Console {
    fb: Framebuffer,
    x: usize,
    y: usize,
    dirty: Option<Rect>,
    /// Sparse terminal cells used to replay Console glyphs after a userland
    /// compositor presents a new surface into the same framebuffer.
    console_cells: Option<alloc::boxed::Box<[ConsoleCell]>>,
    /// Incremental decoder for raw userland ConsoleWrite byte streams. Kernel
    /// logger strings bypass this field because fmt::Arguments are already UTF-8.
    decoder: Utf8Decoder,
    /// Small ANSI/VT input state. The Console deliberately implements only the
    /// cursor/erase subset emitted by the built-in shell.
    escape: u8,
    csi_params: [u16; CSI_MAX_PARAMS],
    csi_len: u8,
    csi_current: u16,
    csi_has_current: bool,
    last_advance: usize,
}

static CONSOLE: Mutex<Option<Console>> = Mutex::new(None);
/// Once the interactive shell is ready, graphical output belongs to it. Kernel
/// logs and service diagnostics remain available on serial but must not
/// asynchronously overwrite the shell surface.
static SHELL_FOREGROUND: AtomicBool = AtomicBool::new(false);

/// Raw bootloader GOP aperture for early paging attribute classification.
pub fn boot_framebuffer_range() -> Option<(usize, usize)> {
    let fb = Framebuffer::from_boot()?;
    Some((fb.base, fb.size))
}

fn boot_console() -> Option<Console> {
    let fb = Framebuffer::from_boot()?;
    let mut c = Console {
        fb,
        x: MARGIN,
        y: MARGIN,
        dirty: None,
        console_cells: None,
        decoder: Utf8Decoder::new(),
        escape: 0,
        csi_params: [0; CSI_MAX_PARAMS],
        csi_len: 0,
        csi_current: 0,
        csi_has_current: false,
        last_advance: 0,
    };
    c.fill_rect(
        Rect {
            x: 0,
            y: 0,
            w: fb.width,
            h: fb.height,
        },
        BG,
    );
    Some(c)
}

/// Attach the bootloader-provided GOP framebuffer before MM/ACPI/platform init.
/// This is intentionally allocation-free: early bring-up on an unfamiliar ARM64
/// platform must have a diagnostic sink even when no UART is known yet. Physical
/// reservation is deferred to [`init`] after the allocator exists.
pub fn early_init() {
    let mut guard = CONSOLE.lock();
    if guard.is_some() {
        return;
    }
    *guard = boot_console();
}

/// Finalize GOP ownership once physical memory management is online. If early
/// init already installed the console, preserve its contents/cursor and only
/// reserve the underlying physical range.
pub fn init() {
    if CONSOLE.lock().is_none() {
        early_init();
    }
    let fb = { CONSOLE.lock().as_ref().map(|c| c.fb) };
    let Some(fb) = fb else {
        return;
    };
    let reserved = crate::mm::phys::reserve_physical_range(fb.base, fb.size);
    crate::info!(
        "display: GOP framebuffer {}x{} stride={} base={:#x} reserved_pages={}",
        fb.width,
        fb.height,
        fb.stride,
        fb.base,
        reserved
    );
}

pub fn available() -> bool {
    CONSOLE.lock().is_some()
}

pub fn framebuffer_size() -> Option<(usize, usize)> {
    CONSOLE.lock().as_ref().map(|c| (c.fb.width, c.fb.height))
}

/// VirtIO GPU 建立 host-backed 2D resource 后把 backing 交给同一软件 2D/
/// 文本层。对上层而言 GOP 与 GPU 都只是 XRGB8888 framebuffer backend。
pub fn install_virtio_gpu_framebuffer(
    base: usize,
    size: usize,
    width: usize,
    height: usize,
    stride: usize,
) {
    if base == 0 || width == 0 || height == 0 || stride < width {
        return;
    }
    let Some(required) = stride.checked_mul(height).and_then(|n| n.checked_mul(4)) else {
        return;
    };
    if size < required {
        return;
    }
    let fb = Framebuffer {
        base,
        size,
        width,
        height,
        stride,
        format: Format::Bgrx,
        volatile: false,
        flip_y: false,
    };
    let mut c = Console {
        fb,
        x: MARGIN,
        y: MARGIN,
        dirty: None,
        console_cells: Some(
            alloc::vec![ConsoleCell::default(); console_cell_capacity(width, height)]
                .into_boxed_slice(),
        ),
        decoder: Utf8Decoder::new(),
        escape: 0,
        csi_params: [0; CSI_MAX_PARAMS],
        csi_len: 0,
        csi_current: 0,
        csi_has_current: false,
        last_advance: 0,
    };
    c.fill_rect(
        Rect {
            x: 0,
            y: 0,
            w: width,
            h: height,
        },
        BG,
    );
    *CONSOLE.lock() = Some(c);
}

pub fn clear(color: Rgb) {
    let changed = if let Some(c) = CONSOLE.lock().as_mut() {
        c.fill_rect(
            Rect {
                x: 0,
                y: 0,
                w: c.fb.width,
                h: c.fb.height,
            },
            color,
        );
        c.remove_cells_in_rect(Rect {
            x: 0,
            y: 0,
            w: c.fb.width,
            h: c.fb.height,
        });
        c.x = MARGIN;
        c.y = MARGIN;
        true
    } else {
        false
    };
    if changed {
        repaint_console();
        crate::drivers::virtio::gpu::flush_all();
    }
}

/// Clear the boot log and switch the graphical console to the interactive
/// shell. This is called before the shell is queued, so no user process can
/// race the transition.
pub fn begin_shell_session() {
    clear(BG);
    SHELL_FOREGROUND.store(true, Ordering::Release);
}

pub fn fill_rect(rect: Rect, color: Rgb) {
    if let Some(c) = CONSOLE.lock().as_mut() {
        c.fill_rect(rect, color);
    }
}

pub fn alpha_blit(x: usize, y: usize, width: usize, height: usize, alpha: &[u8], color: Rgb) {
    if alpha.len() < width.saturating_mul(height) {
        return;
    }
    let mut guard = CONSOLE.lock();
    let Some(c) = guard.as_mut() else { return };
    for yy in 0..height {
        for xx in 0..width {
            let a = alpha[yy * width + xx];
            if a == 0 {
                continue;
            }
            let dst = c.fb.pixel(x + xx, y + yy).unwrap_or(BG);
            let mix = |s: u8, d: u8| -> u8 {
                ((s as u16 * a as u16 + d as u16 * (255 - a) as u16 + 127) / 255) as u8
            };
            c.fb.put(
                x + xx,
                y + yy,
                Rgb {
                    r: mix(color.r, dst.r),
                    g: mix(color.g, dst.g),
                    b: mix(color.b, dst.b),
                },
            );
        }
    }
    c.mark_dirty(Rect {
        x,
        y,
        w: width,
        h: height,
    });
}

/// Present a userland-composited BGRX8888 surface into the active backend.
pub fn present_xrgb(data: &[u8], width: usize, height: usize, stride: usize) -> bool {
    if width == 0 || height == 0 || stride < width {
        return false;
    }
    let Some(required) = stride.checked_mul(height).and_then(|n| n.checked_mul(4)) else {
        return false;
    };
    if data.len() < required {
        return false;
    }
    {
        let mut guard = CONSOLE.lock();
        let Some(c) = guard.as_mut() else {
            return false;
        };
        let w = width.min(c.fb.width);
        let h = height.min(c.fb.height);
        for y in 0..h {
            for x in 0..w {
                let off = (y * stride + x) * 4;
                c.fb.put(
                    x,
                    y,
                    Rgb {
                        r: data[off + 2],
                        g: data[off + 1],
                        b: data[off],
                    },
                );
            }
        }
        c.render_console_region(Rect { x: 0, y: 0, w, h });
    }
    crate::drivers::virtio::gpu::flush_all();
    true
}

/// Mirror a raw userland console byte stream into the active graphical console.
///
/// ConsoleWrite is a byte ABI and callers may split a UTF-8 scalar across syscall
/// boundaries, so keep an incremental decoder in the Console rather than calling
/// `from_utf8` per chunk. Serial remains the authoritative headless sink; this is
/// the visible terminal path on UEFI machines without an interactive UART.
pub fn write_bytes(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    if SHELL_FOREGROUND.load(Ordering::Acquire) && !crate::process::current_process_is_console() {
        return;
    }
    let mut guard = CONSOLE.lock();
    let Some(c) = guard.as_mut() else { return };
    for &b in bytes {
        c.feed_byte(b);
    }
    c.repaint_dirty();
    drop(guard);
    crate::drivers::virtio::gpu::flush_all();
}

/// 把一条已经格式化的内核日志镜像到 framebuffer。fmt 的每个 `&str`
/// 都保证 UTF-8 有效，因此渲染层按 Unicode scalar 工作；原始 byte stream
/// 的增量解码器见 [`Utf8Decoder`]。
pub fn write_fmt_line(args: fmt::Arguments<'_>) {
    if SHELL_FOREGROUND.load(Ordering::Acquire) {
        return;
    }
    {
        // Graphical logging is a best-effort mirror. Never make a kernel control
        // path wait behind another CPU doing framebuffer work during SMP bring-up.
        let Some(mut guard) = CONSOLE.try_lock() else {
            return;
        };
        let Some(c) = guard.as_mut() else { return };
        let _ = c.write_fmt(args);
        c.newline();
        c.repaint_dirty();
    }
    // Kernel logging must never synchronously submit GPU commands. On SMP,
    // several CPUs can log while secondaries are coming online; coupling every
    // log line to TRANSFER+FLUSH serialises boot on the VirtIO control queue and
    // can deadlock/stall against device IRQ/queue activity. GOP remains directly
    // visible; ConsoleWrite and present_xrgb flush the VirtIO-GPU path. Serial
    // is the authoritative log sink.
}

#[cfg(test)]
fn pack_bgrx(c: Rgb) -> u32 {
    u32::from_le_bytes([c.b, c.g, c.r, 0])
}

fn console_cell_capacity(width: usize, height: usize) -> usize {
    let columns = width
        .saturating_sub(MARGIN * 2)
        .checked_div(CELL_ADVANCE)
        .unwrap_or(0)
        .saturating_add(1);
    let rows = height
        .saturating_sub(MARGIN + GLYPH_HEIGHT)
        .checked_div(GLYPH_HEIGHT + 2)
        .unwrap_or(0)
        .saturating_add(1);
    columns.saturating_mul(rows).clamp(1, MAX_CONSOLE_CELLS)
}

fn repaint_console() {
    let mut guard = CONSOLE.lock();
    if let Some(c) = guard.as_mut() {
        c.repaint_dirty();
    }
}

impl Console {
    fn repaint_dirty(&mut self) {
        let Some(rect) = self.dirty.take() else {
            return;
        };
        if self.console_cells.is_none() {
            return;
        }
        self.render_console_region(rect);
    }

    fn render_console_region(&self, rect: Rect) {
        let Some(cells) = self.console_cells.as_ref() else {
            return;
        };
        let fb = self.fb;
        let x1 = rect.x.min(fb.width);
        let y1 = rect.y.min(fb.height);
        let x2 = rect.x.saturating_add(rect.w).min(fb.width);
        let y2 = rect.y.saturating_add(rect.h).min(fb.height);
        for cell in cells.iter().filter(|cell| cell.codepoint != 0) {
            let x = cell.x as usize;
            let y = cell.y as usize;
            let width = cell.width as usize;
            if x < x2
                && x.saturating_add(width) > x1
                && y < y2
                && y.saturating_add(GLYPH_HEIGHT) > y1
            {
                let ch = char::from_u32(cell.codepoint).unwrap_or('?');
                let (rows, glyph_width) = glyph(ch).unwrap_or_else(|| glyph('?').unwrap());
                // The generated font stores scanlines bottom-to-top; emit
                // them in the console's logical top-to-bottom order.
                for (yy, row) in rows.iter().rev().enumerate() {
                    for xx in 0..glyph_width {
                        if row & (1u16 << (glyph_width - 1 - xx)) != 0 {
                            fb.put(x + xx, y + yy, FG);
                        }
                    }
                }
            }
        }
    }

    fn remove_cells_in_rect(&mut self, rect: Rect) {
        let x1 = rect.x;
        let y1 = rect.y;
        let x2 = rect.x.saturating_add(rect.w);
        let y2 = rect.y.saturating_add(rect.h);
        if let Some(cells) = self.console_cells.as_mut() {
            for cell in cells.iter_mut().filter(|cell| cell.codepoint != 0) {
                let x = cell.x as usize;
                let y = cell.y as usize;
                let width = (cell.width as usize).max(8);
                if x < x2
                    && x.saturating_add(width) > x1
                    && y < y2
                    && y.saturating_add(GLYPH_HEIGHT) > y1
                {
                    *cell = ConsoleCell::default();
                }
            }
        }
    }

    fn store_cell(&mut self, ch: char, width: usize) {
        let x = self.x.min(u16::MAX as usize) as u16;
        let y = self.y.min(u16::MAX as usize) as u16;
        let Some(cells) = self.console_cells.as_mut() else {
            return;
        };
        if let Some(cell) = cells
            .iter_mut()
            .find(|cell| cell.codepoint != 0 && cell.x == x && cell.y == y)
        {
            *cell = ConsoleCell {
                x,
                y,
                codepoint: ch as u32,
                width: width.min(u8::MAX as usize) as u8,
            };
        } else if let Some(cell) = cells.iter_mut().find(|cell| cell.codepoint == 0) {
            *cell = ConsoleCell {
                x,
                y,
                codepoint: ch as u32,
                width: width.min(u8::MAX as usize) as u8,
            };
        }
    }

    fn clear_console_layer(&mut self, rect: Rect) {
        let width = self.fb.width;
        let height = self.fb.height;
        let x1 = rect.x.min(width);
        let y1 = rect.y.min(height);
        let x2 = rect.x.saturating_add(rect.w).min(width);
        let y2 = rect.y.saturating_add(rect.h).min(height);
        self.remove_cells_in_rect(Rect {
            x: x1,
            y: y1,
            w: x2.saturating_sub(x1),
            h: y2.saturating_sub(y1),
        });
        for y in y1..y2 {
            for x in x1..x2 {
                self.fb.put(x, y, BG);
            }
        }
        self.mark_dirty(Rect {
            x: x1,
            y: y1,
            w: x2.saturating_sub(x1),
            h: y2.saturating_sub(y1),
        });
    }

    fn clear_cell(&mut self, x: usize, y: usize) {
        self.clear_console_layer(Rect {
            x,
            y,
            w: CELL_CLEAR_WIDTH,
            h: GLYPH_HEIGHT,
        });
    }

    fn backspace(&mut self) {
        let advance = if self.last_advance == 0 {
            CELL_ADVANCE
        } else {
            self.last_advance
        };
        self.x = self.x.saturating_sub(advance).max(MARGIN);
        self.clear_cell(self.x, self.y);
        self.last_advance = 0;
    }

    fn clear_screen(&mut self) {
        self.clear_console_layer(Rect {
            x: 0,
            y: 0,
            w: self.fb.width,
            h: self.fb.height,
        });
        self.x = MARGIN;
        self.y = MARGIN;
        self.last_advance = 0;
    }

    fn clear_line(&mut self) {
        self.clear_console_layer(Rect {
            x: self.x,
            y: self.y,
            w: self.fb.width.saturating_sub(self.x),
            h: GLYPH_HEIGHT,
        });
    }

    fn set_cursor(&mut self, row: u16, col: u16) {
        let line_height = GLYPH_HEIGHT + 2;
        let max_y = self.fb.height.saturating_sub(MARGIN + GLYPH_HEIGHT);
        let row = row.max(1) as usize;
        let col = col.max(1) as usize;
        self.y = MARGIN
            .saturating_add(row.saturating_sub(1).saturating_mul(line_height))
            .min(max_y);
        self.x = MARGIN
            .saturating_add(col.saturating_sub(1).saturating_mul(CELL_ADVANCE))
            .min(self.fb.width.saturating_sub(MARGIN + 8));
        self.last_advance = 0;
    }

    fn csi_param(&self, index: usize, default: u16) -> u16 {
        if index < self.csi_len as usize && self.csi_params[index] != 0 {
            self.csi_params[index]
        } else {
            default
        }
    }

    fn finish_csi_param(&mut self) {
        if self.csi_len < CSI_MAX_PARAMS as u8 {
            self.csi_params[self.csi_len as usize] = if self.csi_has_current {
                self.csi_current
            } else {
                0
            };
            self.csi_len += 1;
        }
        self.csi_current = 0;
        self.csi_has_current = false;
    }

    fn reset_csi(&mut self) {
        self.csi_params = [0; CSI_MAX_PARAMS];
        self.csi_len = 0;
        self.csi_current = 0;
        self.csi_has_current = false;
    }

    fn apply_csi(&mut self, final_byte: u8) {
        if self.csi_has_current || self.csi_len != 0 {
            self.finish_csi_param();
        }
        match final_byte {
            b'A' => {
                let n = self.csi_param(0, 1) as usize;
                self.y = self
                    .y
                    .saturating_sub(n.saturating_mul(GLYPH_HEIGHT + 2))
                    .max(MARGIN);
                self.last_advance = 0;
            }
            b'B' => {
                let n = self.csi_param(0, 1) as usize;
                let max_y = self.fb.height.saturating_sub(MARGIN + GLYPH_HEIGHT);
                self.y = self
                    .y
                    .saturating_add(n.saturating_mul(GLYPH_HEIGHT + 2))
                    .min(max_y);
                self.last_advance = 0;
            }
            b'C' => {
                let n = self.csi_param(0, 1) as usize;
                let max_x = self.fb.width.saturating_sub(MARGIN + 8);
                self.x = self
                    .x
                    .saturating_add(n.saturating_mul(CELL_ADVANCE))
                    .min(max_x);
                self.last_advance = 0;
            }
            b'D' => {
                let n = self.csi_param(0, 1) as usize;
                self.x = self
                    .x
                    .saturating_sub(n.saturating_mul(CELL_ADVANCE))
                    .max(MARGIN);
                self.last_advance = 0;
            }
            b'H' | b'f' => {
                self.set_cursor(self.csi_param(0, 1), self.csi_param(1, 1));
            }
            b'J' => {
                let mode = self.csi_param(0, 0);
                if mode == 0 || mode == 2 {
                    self.clear_screen();
                }
            }
            b'K' => {
                let mode = self.csi_param(0, 0);
                if mode == 0 || mode == 2 {
                    self.clear_line();
                }
            }
            // SGR/style changes are intentionally ignored; the kernel Console
            // has one fixed foreground color, but the escape sequence itself
            // must not become visible '?' glyphs.
            b'm' => {}
            _ => {}
        }
    }

    fn feed_text_byte(&mut self, b: u8) {
        match b {
            b'\n' => {
                self.decoder.reset();
                self.draw_char('\n');
            }
            b'\r' => {
                self.decoder.reset();
                self.draw_char('\r');
            }
            b'\t' => {
                self.decoder.reset();
                self.draw_char('\t');
            }
            0x08 | 0x7f => {
                self.decoder.reset();
                self.backspace();
            }
            0x00..=0x1f => {
                self.decoder.reset();
            }
            _ => {
                if let Some(ch) = self.decoder.push(b) {
                    self.draw_char(ch);
                }
            }
        }
    }

    fn feed_byte(&mut self, b: u8) {
        match self.escape {
            0 => {
                if b == 0x1b {
                    self.decoder.reset();
                    self.escape = 1;
                } else {
                    self.feed_text_byte(b);
                }
            }
            1 => {
                if b == b'[' {
                    self.reset_csi();
                    self.escape = 2;
                } else if b == b'c' {
                    self.clear_screen();
                    self.escape = 0;
                } else if b == 0x1b {
                    self.escape = 1;
                } else {
                    self.escape = 0;
                    self.feed_text_byte(b);
                }
            }
            _ => match b {
                0x1b => self.escape = 1,
                b'0'..=b'9' => {
                    self.csi_current = self
                        .csi_current
                        .saturating_mul(10)
                        .saturating_add((b - b'0') as u16)
                        .min(999);
                    self.csi_has_current = true;
                }
                b';' => self.finish_csi_param(),
                0x40..=0x7e => {
                    self.apply_csi(b);
                    self.escape = 0;
                    self.reset_csi();
                }
                _ => self.escape = 0,
            },
        }
    }

    fn fill_rect(&mut self, rect: Rect, color: Rgb) {
        let x1 = rect.x.min(self.fb.width);
        let y1 = rect.y.min(self.fb.height);
        let x2 = rect.x.saturating_add(rect.w).min(self.fb.width);
        let y2 = rect.y.saturating_add(rect.h).min(self.fb.height);
        for y in y1..y2 {
            for x in x1..x2 {
                self.fb.put(x, y, color);
            }
        }
        self.mark_dirty(Rect {
            x: x1,
            y: y1,
            w: x2.saturating_sub(x1),
            h: y2.saturating_sub(y1),
        });
    }

    fn mark_dirty(&mut self, r: Rect) {
        if r.w == 0 || r.h == 0 {
            return;
        }
        self.dirty = Some(match self.dirty {
            None => r,
            Some(a) => {
                let x = a.x.min(r.x);
                let y = a.y.min(r.y);
                let x2 = a.x.saturating_add(a.w).max(r.x.saturating_add(r.w));
                let y2 = a.y.saturating_add(a.h).max(r.y.saturating_add(r.h));
                Rect {
                    x,
                    y,
                    w: x2 - x,
                    h: y2 - y,
                }
            }
        });
    }

    fn newline(&mut self) {
        self.x = MARGIN;
        self.y = self.y.saturating_add(GLYPH_HEIGHT + 2);
        self.last_advance = 0;
        if self.y + GLYPH_HEIGHT + MARGIN >= self.fb.height {
            self.scroll();
        }
    }

    fn scroll(&mut self) {
        let dy = GLYPH_HEIGHT + 2;
        let end = self.fb.height.saturating_sub(dy);
        if !self.fb.volatile && !self.fb.flip_y && end > MARGIN {
            // A non-flipped VirtIO-GPU backing is normal RAM: one overlap-safe
            // memmove replaces ~1M volatile pixel read/writes on a 1280x800
            // scanout. This matters during SMP boot where several CPUs can emit
            // log lines concurrently.
            let rows = end - MARGIN;
            let row_bytes = self.fb.stride * 4;
            unsafe {
                core::ptr::copy(
                    (self.fb.base + (MARGIN + dy) * row_bytes) as *const u8,
                    (self.fb.base + MARGIN * row_bytes) as *mut u8,
                    rows * row_bytes,
                );
            }
        } else {
            // GOP/device memory, and flipped backings whose logical rows do not
            // form one forward physical range, require coordinate-aware copies.
            for y in MARGIN..end {
                for x in 0..self.fb.width {
                    if let Some(px) = self.fb.pixel(x, y + dy) {
                        self.fb.put(x, y, px);
                    }
                }
            }
        }
        self.fill_rect(
            Rect {
                x: 0,
                y: self.fb.height.saturating_sub(dy),
                w: self.fb.width,
                h: dy,
            },
            BG,
        );
        if let Some(cells) = self.console_cells.as_mut() {
            for cell in cells.iter_mut().filter(|cell| cell.codepoint != 0) {
                let y = cell.y as usize;
                if y < MARGIN + dy {
                    *cell = ConsoleCell::default();
                } else {
                    cell.y = (y - dy).min(u16::MAX as usize) as u16;
                }
            }
            self.mark_dirty(Rect {
                x: 0,
                y: MARGIN,
                w: self.fb.width,
                h: self.fb.height.saturating_sub(MARGIN),
            });
        }
        // `newline` has already advanced the cursor. Move that position up
        // with the scrolled pixels instead of recomputing a value that can
        // overlap the last visible glyph row.
        self.y = self.y.saturating_sub(dy).max(MARGIN);
        self.x = MARGIN;
        self.last_advance = 0;
    }

    fn draw_char(&mut self, ch: char) {
        match ch {
            '\n' => {
                self.newline();
                return;
            }
            '\r' => {
                self.x = MARGIN;
                self.last_advance = 0;
                return;
            }
            '\t' => {
                self.x = self.x.saturating_add(4 * 8);
                self.last_advance = 0;
                return;
            }
            _ => {}
        }
        let (rows, width) = glyph(ch).unwrap_or_else(|| glyph('?').unwrap());
        if self.x + width + MARGIN >= self.fb.width {
            self.newline();
        }
        self.clear_cell(self.x, self.y);
        if ch != ' ' {
            self.store_cell(ch, width);
        }
        // The generated font stores scanlines bottom-to-top; the console
        // coordinate system is top-to-bottom.
        for (yy, row) in rows.iter().rev().enumerate() {
            for xx in 0..width {
                if row & (1u16 << (width - 1 - xx)) != 0 {
                    self.fb.put(self.x + xx, self.y + yy, FG);
                }
            }
        }
        self.mark_dirty(Rect {
            x: self.x,
            y: self.y,
            w: width,
            h: GLYPH_HEIGHT,
        });
        self.last_advance = width + 1;
        self.x += self.last_advance;
    }
}

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            self.feed_byte(b);
        }
        Ok(())
    }
}

fn glyph(ch: char) -> Option<(&'static [u16; 16], usize)> {
    let cp = ch as u32;
    if (32..=126).contains(&cp) {
        return Some((&ASCII[(cp - 32) as usize], 8));
    }
    CJK.binary_search_by_key(&cp, |(v, _)| *v)
        .ok()
        .map(|i| (&CJK[i].1, 16))
}

/// 小型严格 UTF-8 流解码器；非法序列输出 U+FFFD 并重新同步。
#[derive(Copy, Clone, Debug, Default)]
pub struct Utf8Decoder {
    code: u32,
    need: u8,
    min: u32,
}

impl Utf8Decoder {
    pub const fn new() -> Self {
        Self {
            code: 0,
            need: 0,
            min: 0,
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    pub fn push(&mut self, b: u8) -> Option<char> {
        if self.need == 0 {
            match b {
                0x00..=0x7f => return char::from_u32(b as u32),
                0xc2..=0xdf => {
                    self.code = (b & 0x1f) as u32;
                    self.need = 1;
                    self.min = 0x80;
                }
                0xe0..=0xef => {
                    self.code = (b & 0x0f) as u32;
                    self.need = 2;
                    self.min = 0x800;
                }
                0xf0..=0xf4 => {
                    self.code = (b & 0x07) as u32;
                    self.need = 3;
                    self.min = 0x10000;
                }
                _ => return Some('\u{fffd}'),
            }
            return None;
        }
        if b & 0xc0 != 0x80 {
            *self = Self::new();
            return Some('\u{fffd}');
        }
        self.code = (self.code << 6) | (b & 0x3f) as u32;
        self.need -= 1;
        if self.need != 0 {
            return None;
        }
        let cp = self.code;
        let min = self.min;
        *self = Self::new();
        if cp < min || cp > 0x10ffff || (0xd800..=0xdfff).contains(&cp) {
            Some('\u{fffd}')
        } else {
            char::from_u32(cp).or(Some('\u{fffd}'))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framebuffer_flip_y_maps_logical_rows_to_physical_rows() {
        let mut backing = alloc::vec![0u32; 4 * 4];
        let fb = Framebuffer {
            base: backing.as_mut_ptr() as usize,
            size: backing.len() * 4,
            width: 4,
            height: 4,
            stride: 4,
            format: Format::Bgrx,
            volatile: false,
            flip_y: true,
        };
        let top = Rgb {
            r: 0x11,
            g: 0x22,
            b: 0x33,
        };
        let bottom = Rgb {
            r: 0xaa,
            g: 0xbb,
            b: 0xcc,
        };

        fb.put(0, 0, top);
        fb.put(1, 3, bottom);

        assert_eq!(backing[3 * 4], pack_bgrx(top));
        assert_eq!(backing[1], pack_bgrx(bottom));
    }

    fn test_console(width: usize, height: usize) -> (alloc::boxed::Box<[u32]>, Console) {
        let mut backing = alloc::vec![pack_bgrx(BG); width * height].into_boxed_slice();
        let fb = Framebuffer {
            base: backing.as_mut_ptr() as usize,
            size: width * height * 4,
            width,
            height,
            stride: width,
            format: Format::Bgrx,
            volatile: false,
            flip_y: false,
        };
        let console = Console {
            fb,
            x: MARGIN,
            y: MARGIN,
            dirty: None,
            console_cells: Some(
                alloc::vec![ConsoleCell::default(); console_cell_capacity(width, height)]
                    .into_boxed_slice(),
            ),
            decoder: Utf8Decoder::new(),
            escape: 0,
            csi_params: [0; CSI_MAX_PARAMS],
            csi_len: 0,
            csi_current: 0,
            csi_has_current: false,
            last_advance: 0,
        };
        (backing, console)
    }

    #[test]
    fn ansi_clear_and_home_are_control_sequences() {
        let (_backing, mut c) = test_console(128, 64);
        for &b in b"abc" {
            c.feed_byte(b);
        }
        assert!(c
            .console_cells
            .as_ref()
            .unwrap()
            .iter()
            .any(|cell| cell.codepoint != 0));

        for &b in b"\x1b[2J\x1b[H" {
            c.feed_byte(b);
        }
        assert_eq!((c.x, c.y), (MARGIN, MARGIN));
        assert!(c
            .console_cells
            .as_ref()
            .unwrap()
            .iter()
            .all(|cell| cell.codepoint == 0));
    }

    #[test]
    fn backspace_and_space_erase_the_previous_cell() {
        let (_backing, mut c) = test_console(128, 64);
        for &b in b"ab" {
            c.feed_byte(b);
        }
        let after_ab = c
            .console_cells
            .as_ref()
            .unwrap()
            .iter()
            .filter(|cell| cell.codepoint != 0)
            .count();
        c.feed_byte(0x08);
        let after_backspace = c
            .console_cells
            .as_ref()
            .unwrap()
            .iter()
            .filter(|cell| cell.codepoint != 0)
            .count();
        assert!(after_backspace < after_ab);
        assert_eq!(c.x, MARGIN + CELL_ADVANCE);

        // Re-create an occupied second cell and overwrite it with a space;
        // spaces must erase old glyph pixels instead of leaving stale ink.
        for &b in b"b" {
            c.feed_byte(b);
        }
        c.x = MARGIN + CELL_ADVANCE;
        c.last_advance = 0;
        let before_space = c
            .console_cells
            .as_ref()
            .unwrap()
            .iter()
            .filter(|cell| cell.codepoint != 0)
            .count();
        c.feed_byte(b' ');
        let after_space = c
            .console_cells
            .as_ref()
            .unwrap()
            .iter()
            .filter(|cell| cell.codepoint != 0)
            .count();
        assert!(after_space < before_space);
    }

    #[test]
    fn scroll_moves_cursor_with_the_scrolled_pixels() {
        let (_backing, mut c) = test_console(64, 64);
        for _ in 0..3 {
            c.feed_byte(b'\n');
        }
        assert_eq!(c.y, MARGIN + GLYPH_HEIGHT + 2);
    }

    #[test]
    fn console_cells_replay_after_compositor_present() {
        let (mut backing, mut c) = test_console(128, 64);
        let base_pixel = 0x0011_2233;
        c.feed_byte(b'A');
        c.repaint_dirty();
        backing.fill(base_pixel);
        c.render_console_region(Rect {
            x: 0,
            y: 0,
            w: 128,
            h: 64,
        });
        assert!(backing.iter().any(|pixel| *pixel != base_pixel));

        c.clear_screen();
        c.repaint_dirty();
        assert!(backing.iter().all(|pixel| *pixel == pack_bgrx(BG)));
        assert!(c
            .console_cells
            .as_ref()
            .unwrap()
            .iter()
            .all(|cell| cell.codepoint == 0));
    }

    #[test]
    fn glyph_bits_follow_font_scanline_orientation() {
        let (backing, mut c) = test_console(128, 64);
        c.feed_byte(b'A');
        let (rows, width) = glyph('A').unwrap();
        assert_eq!(width, 8);
        for yy in 0..GLYPH_HEIGHT {
            for xx in 0..width {
                let expected = rows[GLYPH_HEIGHT - 1 - yy] & (1u16 << (width - 1 - xx)) != 0;
                let pixel = backing[(MARGIN + yy) * 128 + MARGIN + xx];
                assert_eq!(pixel == pack_bgrx(FG), expected, "x={xx} y={yy}");
            }
        }
    }

    #[test]
    fn utf8_stream_decodes_chinese() {
        let mut d = Utf8Decoder::new();
        let mut out = alloc::string::String::new();
        for b in "中文A".as_bytes() {
            if let Some(ch) = d.push(*b) {
                out.push(ch);
            }
        }
        assert_eq!(out, "中文A");
    }
    #[test]
    fn utf8_rejects_overlong_and_bad_continuation() {
        let mut d = Utf8Decoder::new();
        assert_eq!(d.push(0xc0), Some('\u{fffd}'));
        assert_eq!(d.push(0xe4), None);
        assert_eq!(d.push(b'A'), Some('\u{fffd}'));
    }
    #[test]
    fn cjk_rom_contains_boot_glyphs() {
        for c in "中文内核初始化完成驱动用户态物理内存".chars() {
            assert!(glyph(c).is_some(), "missing {c}");
        }
    }
}
