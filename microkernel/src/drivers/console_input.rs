//! Console text input fallback for platforms without an early/interactive UART.
//!
//! Raw input remains in the normalized InputEvent ring for inputd/WindowServer.
//! This module mirrors keyboard press events into a separate byte ring consumed
//! only by ConsoleRead, so terminal input never steals GUI input events.

use spin::Mutex;
use zero_abi::input::{InputEvent, KIND_KEY};

const CAP: usize = 256;

struct State {
    bytes: [u8; CAP],
    head: usize,
    tail: usize,
    shift: bool,
    caps: bool,
}

impl State {
    const fn new() -> Self {
        Self {
            bytes: [0; CAP],
            head: 0,
            tail: 0,
            shift: false,
            caps: false,
        }
    }

    fn push(&mut self, b: u8) {
        let next = (self.head + 1) % CAP;
        if next == self.tail {
            // Terminal typing is best effort. Prefer dropping the newest byte to
            // overwriting unread command text when an input source floods.
            return;
        }
        self.bytes[self.head] = b;
        self.head = next;
    }

    fn pop(&mut self) -> Option<u8> {
        if self.tail == self.head {
            return None;
        }
        let b = self.bytes[self.tail];
        self.tail = (self.tail + 1) % CAP;
        Some(b)
    }
}

static STATE: Mutex<State> = Mutex::new(State::new());

/// Mirror one normalized Linux-keycode event into terminal bytes.
/// Release events only update modifier state; key repeats (`value == 2`) are
/// accepted like presses so holding backspace/letters behaves naturally.
pub fn feed(event: &InputEvent) {
    if event.kind != KIND_KEY {
        return;
    }
    let mut s = STATE.lock();
    match event.code {
        42 | 54 => {
            s.shift = event.value != 0;
            return;
        }
        58 if event.value == 1 => {
            s.caps = !s.caps;
            return;
        }
        _ => {}
    }
    if event.value == 0 {
        return;
    }
    let Some(b) = keycode_to_ascii(event.code, s.shift, s.caps) else {
        return;
    };
    s.push(b);
}

pub fn read_into(out: &mut [u8]) -> usize {
    let mut s = STATE.lock();
    let mut n = 0;
    for dst in out {
        let Some(b) = s.pop() else { break };
        *dst = b;
        n += 1;
    }
    n
}

fn keycode_to_ascii(code: u16, shift: bool, caps: bool) -> Option<u8> {
    let letter = match code {
        30 => b'a',
        48 => b'b',
        46 => b'c',
        32 => b'd',
        18 => b'e',
        33 => b'f',
        34 => b'g',
        35 => b'h',
        23 => b'i',
        36 => b'j',
        37 => b'k',
        38 => b'l',
        50 => b'm',
        49 => b'n',
        24 => b'o',
        25 => b'p',
        16 => b'q',
        19 => b'r',
        31 => b's',
        20 => b't',
        22 => b'u',
        47 => b'v',
        17 => b'w',
        45 => b'x',
        21 => b'y',
        44 => b'z',
        _ => 0,
    };
    if letter != 0 {
        return Some(if shift ^ caps { letter - 32 } else { letter });
    }
    Some(match code {
        2 => {
            if shift {
                b'!'
            } else {
                b'1'
            }
        }
        3 => {
            if shift {
                b'@'
            } else {
                b'2'
            }
        }
        4 => {
            if shift {
                b'#'
            } else {
                b'3'
            }
        }
        5 => {
            if shift {
                b'$'
            } else {
                b'4'
            }
        }
        6 => {
            if shift {
                b'%'
            } else {
                b'5'
            }
        }
        7 => {
            if shift {
                b'^'
            } else {
                b'6'
            }
        }
        8 => {
            if shift {
                b'&'
            } else {
                b'7'
            }
        }
        9 => {
            if shift {
                b'*'
            } else {
                b'8'
            }
        }
        10 => {
            if shift {
                b'('
            } else {
                b'9'
            }
        }
        11 => {
            if shift {
                b')'
            } else {
                b'0'
            }
        }
        28 => b'\r',
        14 => 0x08,
        15 => b'\t',
        57 => b' ',
        12 => {
            if shift {
                b'_'
            } else {
                b'-'
            }
        }
        13 => {
            if shift {
                b'+'
            } else {
                b'='
            }
        }
        26 => {
            if shift {
                b'{'
            } else {
                b'['
            }
        }
        27 => {
            if shift {
                b'}'
            } else {
                b']'
            }
        }
        43 => {
            if shift {
                b'|'
            } else {
                b'\\'
            }
        }
        39 => {
            if shift {
                b':'
            } else {
                b';'
            }
        }
        40 => {
            if shift {
                b'"'
            } else {
                b'\''
            }
        }
        41 => {
            if shift {
                b'~'
            } else {
                b'`'
            }
        }
        51 => {
            if shift {
                b'<'
            } else {
                b','
            }
        }
        52 => {
            if shift {
                b'>'
            } else {
                b'.'
            }
        }
        53 => {
            if shift {
                b'?'
            } else {
                b'/'
            }
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_keycodes_translate_terminal_text() {
        assert_eq!(keycode_to_ascii(30, false, false), Some(b'a'));
        assert_eq!(keycode_to_ascii(30, true, false), Some(b'A'));
        assert_eq!(keycode_to_ascii(30, false, true), Some(b'A'));
        assert_eq!(keycode_to_ascii(30, true, true), Some(b'a'));
        assert_eq!(keycode_to_ascii(28, false, false), Some(b'\r'));
        assert_eq!(keycode_to_ascii(14, false, false), Some(0x08));
        assert_eq!(keycode_to_ascii(12, true, false), Some(b'_'));
    }

    #[test]
    fn feed_keeps_gui_event_semantics_separate() {
        let mut s = STATE.lock();
        *s = State::new();
        drop(s);
        feed(&InputEvent {
            kind: KIND_KEY,
            code: 42,
            value: 1,
            ..InputEvent::default()
        });
        feed(&InputEvent {
            kind: KIND_KEY,
            code: 30,
            value: 1,
            ..InputEvent::default()
        });
        feed(&InputEvent {
            kind: KIND_KEY,
            code: 30,
            value: 0,
            ..InputEvent::default()
        });
        feed(&InputEvent {
            kind: KIND_KEY,
            code: 42,
            value: 0,
            ..InputEvent::default()
        });
        let mut out = [0u8; 4];
        assert_eq!(read_into(&mut out), 1);
        assert_eq!(out[0], b'A');
    }
}
