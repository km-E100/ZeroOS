//! IRQ dispatch: low SGI/PPI/SPI table plus sparse GICv3 LPI handlers.

use crate::{arch, warn};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

pub const LOW_IRQ_COUNT: usize = 1024;
pub const LPI_BASE: u32 = 8192;
pub const MAX_IRQ: u32 = 65535;
const SGI_MAX: u32 = 15;
pub type IrqHandler = fn(u32);
static LOW_HANDLERS: Mutex<[Option<IrqHandler>; LOW_IRQ_COUNT]> = Mutex::new([None; LOW_IRQ_COUNT]);
static HIGH_HANDLERS: Mutex<Vec<(u32, IrqHandler)>> = Mutex::new(Vec::new());
static LOW_UNHANDLED: [AtomicU32; LOW_IRQ_COUNT] = [const { AtomicU32::new(0) }; LOW_IRQ_COUNT];
static OVERFLOW_HITS: AtomicU32 = AtomicU32::new(0);

pub fn handle_irq(irq: u32) -> bool {
    if irq > MAX_IRQ {
        let n = OVERFLOW_HITS.fetch_add(1, Ordering::Relaxed) + 1;
        warn_unhandled(irq, n);
        return false;
    }
    if irq <= SGI_MAX {
        return false;
    }
    if (irq as usize) < LOW_IRQ_COUNT {
        if let Some(h) = LOW_HANDLERS.lock()[irq as usize] {
            h(irq);
            return true;
        }
        let n = LOW_UNHANDLED[irq as usize].fetch_add(1, Ordering::Relaxed) + 1;
        warn_unhandled(irq, n);
        return false;
    }
    if let Some((_, h)) = HIGH_HANDLERS
        .lock()
        .iter()
        .find(|(id, _)| *id == irq)
        .copied()
    {
        h(irq);
        true
    } else {
        let n = OVERFLOW_HITS.fetch_add(1, Ordering::Relaxed) + 1;
        warn_unhandled(irq, n);
        false
    }
}

pub fn register_irq_handler(irq: u32, handler: IrqHandler) {
    if irq > MAX_IRQ {
        warn!("irq {} 越界，无法注册处理器", irq);
        return;
    }
    let overwritten = if (irq as usize) < LOW_IRQ_COUNT {
        let mut t = LOW_HANDLERS.lock();
        let old = t[irq as usize].is_some();
        t[irq as usize] = Some(handler);
        old
    } else {
        let mut t = HIGH_HANDLERS.lock();
        if let Some(e) = t.iter_mut().find(|(id, _)| *id == irq) {
            e.1 = handler;
            true
        } else {
            t.push((irq, handler));
            false
        }
    };
    if overwritten {
        warn!("irq {} 处理器被覆盖", irq);
    }
    #[cfg(not(test))]
    unsafe {
        arch::enable_irq(irq);
    }
    #[cfg(test)]
    let _ = irq;
}

pub fn unregister_irq_handler(irq: u32) {
    if irq > MAX_IRQ {
        return;
    }
    if (irq as usize) < LOW_IRQ_COUNT {
        LOW_HANDLERS.lock()[irq as usize] = None;
    } else {
        HIGH_HANDLERS.lock().retain(|(id, _)| *id != irq);
    }
    #[cfg(not(test))]
    unsafe {
        arch::disable_irq(irq);
    }
    #[cfg(test)]
    let _ = irq;
}
fn warn_unhandled(irq: u32, hits: u32) {
    if hits == 1 || hits == 1000 || hits == 100000 {
        warn!("irq {} 无处理器，累计未处理 {} 次", irq, hits);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn h(_: u32) {}
    #[test]
    fn sparse_lpi_registration() {
        register_irq_handler(9000, h);
        assert!(handle_irq(9000));
        unregister_irq_handler(9000);
    }
}
