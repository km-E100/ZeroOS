//! Display Foundation：UEFI GOP framebuffer + 软件 2D + UTF-8 图形控制台。
//!
//! 串口仍是权威诊断出口；图形 sink 是可选镜像。GOP 不存在/格式不支持时
//! 全部 API 静默 no-op，不影响 headless acceptance。

use core::fmt::{self, Write};
use core::ptr::{read_volatile, write_volatile};
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
        })
    }

    #[inline]
    fn offset(&self, x: usize, y: usize) -> Option<usize> {
        if x >= self.width || y >= self.height {
            return None;
        }
        let off = (y.checked_mul(self.stride)?.checked_add(x)?).checked_mul(4)?;
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

#[derive(Copy, Clone)]
struct Console {
    fb: Framebuffer,
    x: usize,
    y: usize,
    dirty: Option<Rect>,
}

static CONSOLE: Mutex<Option<Console>> = Mutex::new(None);

pub fn init() {
    let Some(fb) = Framebuffer::from_boot() else {
        return;
    };
    let reserved = crate::mm::phys::reserve_physical_range(fb.base, fb.size);
    let mut c = Console {
        fb,
        x: MARGIN,
        y: MARGIN,
        dirty: None,
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
    *CONSOLE.lock() = Some(c);
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
    };
    let mut c = Console {
        fb,
        x: MARGIN,
        y: MARGIN,
        dirty: None,
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
    if let Some(c) = CONSOLE.lock().as_mut() {
        c.fill_rect(
            Rect {
                x: 0,
                y: 0,
                w: c.fb.width,
                h: c.fb.height,
            },
            color,
        );
        c.x = MARGIN;
        c.y = MARGIN;
    }
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
        c.mark_dirty(Rect { x: 0, y: 0, w, h });
    }
    crate::drivers::virtio::gpu::flush_all();
    true
}

/// 把一条已经格式化的内核日志镜像到 framebuffer。fmt 的每个 `&str`
/// 都保证 UTF-8 有效，因此渲染层按 Unicode scalar 工作；原始 byte stream
/// 的增量解码器见 [`Utf8Decoder`]。
pub fn write_fmt_line(args: fmt::Arguments<'_>) {
    {
        // Graphical logging is a best-effort mirror. Never make a kernel control
        // path wait behind another CPU doing framebuffer work during SMP bring-up.
        let Some(mut guard) = CONSOLE.try_lock() else {
            return;
        };
        let Some(c) = guard.as_mut() else { return };
        let _ = c.write_fmt(args);
        c.newline();
    }
    // Kernel logging must never synchronously submit GPU commands. On SMP,
    // several CPUs can log while secondaries are coming online; coupling every
    // log line to TRANSFER+FLUSH serialises boot on the VirtIO control queue and
    // can deadlock/stall against device IRQ/queue activity. GOP remains directly
    // visible, while a VirtIO-GPU console is flushed by explicit presentation
    // paths (WindowServer/present_xrgb). Serial is the authoritative log sink.
}

impl Console {
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
        if self.y + GLYPH_HEIGHT + MARGIN >= self.fb.height {
            self.scroll();
        }
    }

    fn scroll(&mut self) {
        let dy = GLYPH_HEIGHT + 2;
        let end = self.fb.height.saturating_sub(dy);
        if !self.fb.volatile && end > MARGIN {
            // VirtIO-GPU backing is normal RAM: one overlap-safe memmove replaces
            // ~1M volatile pixel read/writes on a 1280x800 scanout. This matters
            // during SMP boot where several CPUs can emit log lines concurrently.
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
            // GOP/device memory requires volatile accesses.
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
        self.y = self.fb.height.saturating_sub(dy + MARGIN + GLYPH_HEIGHT);
        self.x = MARGIN;
    }

    fn draw_char(&mut self, ch: char) {
        match ch {
            '\n' => {
                self.newline();
                return;
            }
            '\r' => {
                self.x = MARGIN;
                return;
            }
            '\t' => {
                self.x = self.x.saturating_add(4 * 8);
                return;
            }
            _ => {}
        }
        let (rows, width) = glyph(ch).unwrap_or_else(|| glyph('?').unwrap());
        if self.x + width + MARGIN >= self.fb.width {
            self.newline();
        }
        for (yy, row) in rows.iter().enumerate() {
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
        self.x += width + 1;
    }
}

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for ch in s.chars() {
            self.draw_char(ch);
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
