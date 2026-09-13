#![no_std]
extern crate alloc;

use alloc::{vec, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use zero_abi::channels::{INPUT_EVENT_BUS, WINDOW_REQ, WINDOW_RESP};
use zero_abi::input::{InputEvent, KIND_ABS, KIND_BUTTON, KIND_REL};
use zero_abi::ipc::Message;
use zero_abi::protocol::window as wp;
use zero_abi::syscall::SysError;

static ABS_POINTER_SEEN: AtomicBool = AtomicBool::new(false);

pub const MAX_WINDOWS: usize = 32;
const SCREEN_WIDTH: usize = 1280;
const SCREEN_HEIGHT: usize = 720;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: u32,
    pub h: u32,
}
impl Rect {
    pub fn contains(self, x: i32, y: i32) -> bool {
        x >= self.x
            && y >= self.y
            && x < self.x.saturating_add(self.w as i32)
            && y < self.y.saturating_add(self.h as i32)
    }
    pub fn intersect(self, other: Rect) -> Option<Rect> {
        let x1 = self.x.max(other.x);
        let y1 = self.y.max(other.y);
        let x2 = self
            .x
            .saturating_add(self.w as i32)
            .min(other.x.saturating_add(other.w as i32));
        let y2 = self
            .y
            .saturating_add(self.h as i32)
            .min(other.y.saturating_add(other.h as i32));
        (x2 > x1 && y2 > y1).then_some(Rect {
            x: x1,
            y: y1,
            w: (x2 - x1) as u32,
            h: (y2 - y1) as u32,
        })
    }
}

#[derive(Clone)]
struct Window {
    id: u32,
    owner: u64,
    rect: Rect,
    title: [u8; 32],
    title_len: usize,
    surface: Vec<u32>, // BGRX in native u32 byte layout
    stride: usize,
}

pub struct Compositor {
    width: usize,
    height: usize,
    windows: Vec<Window>, // back -> front
    next_id: u32,
    focus: Option<u32>,
    pointer: (i32, i32),
    dragging: Option<(u32, i32, i32)>,
    dirty: Option<Rect>,
}
impl Compositor {
    pub fn new(width: usize, height: usize) -> Self {
        Self {
            width,
            height,
            windows: Vec::new(),
            next_id: 1,
            focus: None,
            pointer: (0, 0),
            dragging: None,
            dirty: Some(Rect {
                x: 0,
                y: 0,
                w: width as u32,
                h: height as u32,
            }),
        }
    }
    pub fn create(&mut self, owner: u64, rect: Rect, title: &[u8]) -> Option<u32> {
        if self.windows.len() >= MAX_WINDOWS || rect.w == 0 || rect.h == 0 {
            return None;
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let mut t = [0u8; 32];
        let n = title.len().min(t.len());
        t[..n].copy_from_slice(&title[..n]);
        self.windows.push(Window {
            id,
            owner,
            rect,
            title: t,
            title_len: n,
            surface: vec![0x0020_2020; rect.w as usize * rect.h as usize],
            stride: rect.w as usize,
        });
        self.focus = Some(id);
        self.mark_dirty(rect);
        Some(id)
    }
    pub fn destroy(&mut self, owner: u64, id: u32) -> bool {
        if let Some(i) = self
            .windows
            .iter()
            .position(|w| w.id == id && w.owner == owner)
        {
            let r = self.windows[i].rect;
            self.windows.remove(i);
            if self.focus == Some(id) {
                self.focus = self.windows.last().map(|w| w.id)
            }
            self.mark_dirty(r);
            true
        } else {
            false
        }
    }
    pub fn set_geometry(&mut self, owner: u64, id: u32, rect: Rect) -> bool {
        if rect.w == 0 || rect.h == 0 {
            return false;
        }
        let Some(i) = self
            .windows
            .iter()
            .position(|w| w.id == id && w.owner == owner)
        else {
            return false;
        };
        let old = self.windows[i].rect;
        self.windows[i].rect = rect;
        if self.windows[i].surface.len() != rect.w as usize * rect.h as usize {
            self.windows[i].surface = vec![0x0020_2020; rect.w as usize * rect.h as usize];
            self.windows[i].stride = rect.w as usize;
        }
        self.mark_dirty(old);
        self.mark_dirty(rect);
        true
    }
    pub fn raise(&mut self, owner: u64, id: u32) -> bool {
        let Some(i) = self
            .windows
            .iter()
            .position(|w| w.id == id && w.owner == owner)
        else {
            return false;
        };
        let w = self.windows.remove(i);
        let r = w.rect;
        self.windows.push(w);
        self.focus = Some(id);
        self.mark_dirty(r);
        true
    }
    pub fn hit_test(&self, x: i32, y: i32) -> Option<u32> {
        self.windows
            .iter()
            .rev()
            .find(|w| w.rect.contains(x, y))
            .map(|w| w.id)
    }
    pub fn pointer_motion(&mut self, dx: i32, dy: i32) {
        self.pointer.0 = (self.pointer.0 + dx).clamp(0, self.width.saturating_sub(1) as i32);
        self.pointer.1 = (self.pointer.1 + dy).clamp(0, self.height.saturating_sub(1) as i32);
        if let Some((id, ox, oy)) = self.dragging {
            if let Some(i) = self.windows.iter().position(|w| w.id == id) {
                let old = self.windows[i].rect;
                self.windows[i].rect.x = self.pointer.0 - ox;
                self.windows[i].rect.y = self.pointer.1 - oy;
                let new = self.windows[i].rect;
                self.mark_dirty(old);
                self.mark_dirty(new);
            }
        }
    }
    pub fn pointer_absolute_axis(&mut self, axis: u16, raw: i32) {
        let raw = raw.clamp(0, 0x7fff);
        let target = if axis == 0 {
            (raw as i64 * self.width.saturating_sub(1) as i64 / 0x7fff) as i32
        } else {
            (raw as i64 * self.height.saturating_sub(1) as i64 / 0x7fff) as i32
        };
        let (dx, dy) = if axis == 0 {
            (target - self.pointer.0, 0)
        } else {
            (0, target - self.pointer.1)
        };
        self.pointer_motion(dx, dy);
    }
    pub fn pointer_button(&mut self, pressed: bool) {
        if pressed {
            if let Some(id) = self.hit_test(self.pointer.0, self.pointer.1) {
                if let Some(i) = self.windows.iter().position(|w| w.id == id) {
                    let ox = self.pointer.0 - self.windows[i].rect.x;
                    let oy = self.pointer.1 - self.windows[i].rect.y;
                    let owner = self.windows[i].owner;
                    self.raise(owner, id);
                    self.dragging = Some((id, ox, oy));
                }
            }
        } else {
            self.dragging = None
        }
    }
    pub fn set_surface(
        &mut self,
        owner: u64,
        id: u32,
        pixels: &[u32],
        width: usize,
        height: usize,
        stride: usize,
    ) -> bool {
        let Some(i) = self
            .windows
            .iter()
            .position(|w| w.id == id && w.owner == owner)
        else {
            return false;
        };
        if width != self.windows[i].rect.w as usize
            || height != self.windows[i].rect.h as usize
            || stride < width
            || pixels.len() < stride * height
        {
            return false;
        }
        let mut out = vec![0u32; width * height];
        for y in 0..height {
            out[y * width..(y + 1) * width].copy_from_slice(&pixels[y * stride..y * stride + width])
        }
        self.windows[i].surface = out;
        self.windows[i].stride = width;
        let r = self.windows[i].rect;
        self.mark_dirty(r);
        true
    }
    pub fn compose(&mut self, out: &mut [u32], stride: usize) -> Option<Rect> {
        if out.len() < stride * self.height || stride < self.width {
            return None;
        }
        let dirty = self.dirty.take()?;
        let clip = dirty.intersect(Rect {
            x: 0,
            y: 0,
            w: self.width as u32,
            h: self.height as u32,
        })?;
        for y in clip.y..clip.y + clip.h as i32 {
            for x in clip.x..clip.x + clip.w as i32 {
                out[y as usize * stride + x as usize] = 0x0018_1a1f;
            }
        }
        for w in &self.windows {
            let Some(r) = w.rect.intersect(clip) else {
                continue;
            };
            for y in r.y..r.y + r.h as i32 {
                for x in r.x..r.x + r.w as i32 {
                    let sx = (x - w.rect.x) as usize;
                    let sy = (y - w.rect.y) as usize;
                    if sx < w.rect.w as usize && sy < w.rect.h as usize {
                        out[y as usize * stride + x as usize] = w.surface[sy * w.stride + sx];
                    }
                }
            }
        }
        Some(clip)
    }
    fn mark_dirty(&mut self, r: Rect) {
        self.dirty = Some(match self.dirty {
            None => r,
            Some(a) => {
                let x = a.x.min(r.x);
                let y = a.y.min(r.y);
                let x2 = (a.x + a.w as i32).max(r.x + r.w as i32);
                let y2 = (a.y + a.h as i32).max(r.y + r.h as i32);
                Rect {
                    x,
                    y,
                    w: (x2 - x) as u32,
                    h: (y2 - y) as u32,
                }
            }
        })
    }
    pub fn focus(&self) -> Option<u32> {
        self.focus
    }
}

fn u32_at(p: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(p[o..o + 4].try_into().unwrap_or([0; 4]))
}
fn i32_at(p: &[u8], o: usize) -> i32 {
    i32::from_le_bytes(p[o..o + 4].try_into().unwrap_or([0; 4]))
}

pub extern "C" fn server_main() -> ! {
    let _ = userlib::console_write(b"Zero OS WindowServer online\r\n");
    let mut comp = Compositor::new(SCREEN_WIDTH, SCREEN_HEIGHT);
    let _ = comp.create(
        0,
        Rect {
            x: 0,
            y: 0,
            w: SCREEN_WIDTH as u32,
            h: SCREEN_HEIGHT as u32,
        },
        b"Zero OS Terminal",
    );
    let mut frame = vec![0u32; SCREEN_WIDTH * SCREEN_HEIGHT];
    loop {
        let mut did = false;
        let mut msg = Message::empty();
        if let Ok(sender) = userlib::ipc_try_receive_from(WINDOW_REQ, &mut msg) {
            did = true;
            handle_request(&mut comp, sender, &msg);
        }
        let mut input = Message::empty();
        if userlib::ipc_try_receive(INPUT_EVENT_BUS, &mut input).is_ok() {
            did = true;
            handle_input(&mut comp, &input);
        }
        if comp.compose(&mut frame, SCREEN_WIDTH).is_some() {
            let bytes = unsafe {
                core::slice::from_raw_parts(frame.as_ptr().cast::<u8>(), frame.len() * 4)
            };
            let _ = userlib::display_present_bgrx(bytes, SCREEN_WIDTH, SCREEN_HEIGHT, SCREEN_WIDTH);
        }
        if !did {
            let _ = userlib::sleep_ticks(1);
        }
    }
}

fn handle_input(c: &mut Compositor, m: &Message) {
    if m.payload.len() < core::mem::size_of::<InputEvent>() {
        return;
    }
    let ev = unsafe { core::ptr::read_unaligned(m.payload.as_ptr().cast::<InputEvent>()) };
    match ev.kind {
        KIND_REL => {
            if ev.code == 0 {
                c.pointer_motion(ev.value, 0)
            } else if ev.code == 1 {
                c.pointer_motion(0, ev.value)
            }
        }
        KIND_ABS if ev.code <= 1 => {
            c.pointer_absolute_axis(ev.code, ev.value);
            if !ABS_POINTER_SEEN.swap(true, Ordering::SeqCst) {
                let _ = userlib::console_write(b"WindowServer: USB absolute pointer PASS\r\n");
            }
        }
        KIND_BUTTON => c.pointer_button(ev.value != 0),
        _ => {}
    }
}
fn respond(target: u64, code: u32, id: u32) {
    let mut r = Message::empty();
    r.code = code;
    r.payload[..4].copy_from_slice(&id.to_le_bytes());
    let _ = userlib::ipc_send_to(WINDOW_RESP, target, &r);
}
fn handle_request(c: &mut Compositor, sender: u64, m: &Message) {
    match m.code {
        wp::CREATE => {
            let r = Rect {
                x: i32_at(&m.payload, 0),
                y: i32_at(&m.payload, 4),
                w: u32_at(&m.payload, 8),
                h: u32_at(&m.payload, 12),
            };
            let title_end = m.payload[16..]
                .iter()
                .position(|b| *b == 0)
                .unwrap_or(m.payload.len() - 16);
            respond(
                sender,
                wp::OK,
                c.create(sender, r, &m.payload[16..16 + title_end])
                    .unwrap_or(0),
            );
        }
        wp::DESTROY => respond(
            sender,
            if c.destroy(sender, u32_at(&m.payload, 0)) {
                wp::OK
            } else {
                wp::ERR
            },
            0,
        ),
        wp::SET_GEOMETRY => {
            let id = u32_at(&m.payload, 0);
            let r = Rect {
                x: i32_at(&m.payload, 4),
                y: i32_at(&m.payload, 8),
                w: u32_at(&m.payload, 12),
                h: u32_at(&m.payload, 16),
            };
            respond(
                sender,
                if c.set_geometry(sender, id, r) {
                    wp::OK
                } else {
                    wp::ERR
                },
                id,
            )
        }
        wp::RAISE => {
            let id = u32_at(&m.payload, 0);
            respond(
                sender,
                if c.raise(sender, id) { wp::OK } else { wp::ERR },
                id,
            )
        }
        wp::SUBMIT_SHM => {
            let id = u32_at(&m.payload, 0);
            let handle = u32_at(&m.payload, 4);
            let w = u32_at(&m.payload, 8) as usize;
            let h = u32_at(&m.payload, 12) as usize;
            let stride = u32_at(&m.payload, 16) as usize;
            let ok = match userlib::shm_map(handle) {
                Ok(ptr) => {
                    let len = userlib::shm_len(handle).unwrap_or(0);
                    if len / 4 >= stride.saturating_mul(h) {
                        let px = unsafe { core::slice::from_raw_parts(ptr.cast::<u32>(), len / 4) };
                        c.set_surface(sender, id, px, w, h, stride)
                    } else {
                        false
                    }
                }
                Err(_) => false,
            };
            respond(sender, if ok { wp::OK } else { wp::ERR }, id)
        }
        _ => respond(sender, wp::ERR, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clipping_and_z_order() {
        let mut c = Compositor::new(8, 8);
        let a = c
            .create(
                1,
                Rect {
                    x: 0,
                    y: 0,
                    w: 4,
                    h: 4,
                },
                b"a",
            )
            .unwrap();
        let b = c
            .create(
                2,
                Rect {
                    x: 2,
                    y: 2,
                    w: 4,
                    h: 4,
                },
                b"b",
            )
            .unwrap();
        c.set_surface(1, a, &[0x11; 16], 4, 4, 4);
        c.set_surface(2, b, &[0x22; 16], 4, 4, 4);
        let mut out = [0u32; 64];
        c.compose(&mut out, 8);
        assert_eq!(out[0], 0x11);
        assert_eq!(out[2 * 8 + 2], 0x22);
    }
    #[test]
    fn hit_test_focus_and_drag() {
        let mut c = Compositor::new(100, 100);
        let a = c
            .create(
                1,
                Rect {
                    x: 10,
                    y: 10,
                    w: 20,
                    h: 20,
                },
                b"a",
            )
            .unwrap();
        assert_eq!(c.hit_test(15, 15), Some(a));
        c.pointer_motion(15, 15);
        c.pointer_button(true);
        c.pointer_motion(5, 7);
        c.pointer_button(false);
        assert_eq!(c.hit_test(20, 22), Some(a));
        assert_eq!(c.focus(), Some(a));
    }
    #[test]
    fn rect_intersection() {
        assert_eq!(
            Rect {
                x: 0,
                y: 0,
                w: 5,
                h: 5
            }
            .intersect(Rect {
                x: 3,
                y: 2,
                w: 5,
                h: 5
            }),
            Some(Rect {
                x: 3,
                y: 2,
                w: 2,
                h: 3
            })
        );
    }
}
