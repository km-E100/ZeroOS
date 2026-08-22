//! IRQ 分发：256 槽处理器表 + 注册/注销 + 未处理中断计数。
//!
//! 假中断（spurious）风暴防御：未注册处理器时按 irq 计数，并按对数
//! 间隔（1 / 1000 / 100000 次）告警，避免被高频假中断刷爆串口日志，
//! 同时保留可观测性。

use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

use crate::arch;
use crate::warn;

/// 中断号上限（对应 GIC SPI 最大 255 + SGI/PPI）。
pub const MAX_IRQ: usize = 256;
/// SGI（软件触发中断，0..=15）在本内核不使用，一律不处理。
const SGI_MAX: u32 = 15;

pub type IrqHandler = fn(u32);

static IRQ_HANDLERS: Mutex<[Option<IrqHandler>; MAX_IRQ]> = Mutex::new([None; MAX_IRQ]);

/// 未处理中断计数：每个 irq 一个计数器。
static UNHANDLED_HITS: [AtomicU32; MAX_IRQ] = [const { AtomicU32::new(0) }; MAX_IRQ];

/// 越界中断（spurious 1023 等）独立计数。
static OVERFLOW_HITS: AtomicU32 = AtomicU32::new(0);

/// 分发中断到已注册处理器。
/// 返回 true 表示已处理；false 表示无处理器（调用方负责 end，防风暴）。
pub fn handle_irq(irq: u32) -> bool {
    // 越界（含 GIC spurious 1023）：不处理，由调用方 end 掉。
    if (irq as usize) >= MAX_IRQ {
        let hits = OVERFLOW_HITS.fetch_add(1, Ordering::Relaxed) + 1;
        warn_unhandled(irq, hits);
        return false;
    }
    // SGI 不处理（本项目未启用核间中断）。
    if irq <= SGI_MAX {
        return false;
    }
    let handler = IRQ_HANDLERS.lock()[irq as usize];
    if let Some(handler) = handler {
        handler(irq);
        true
    } else {
        let hits = UNHANDLED_HITS[irq as usize].fetch_add(1, Ordering::Relaxed) + 1;
        warn_unhandled(irq, hits);
        false
    }
}

/// 注册 IRQ 处理器并启用对应中断。
/// 槽位已有处理器时告警（覆盖检测），但不阻止覆盖。
pub fn register_irq_handler(irq: u32, handler: IrqHandler) {
    let index = irq as usize;
    if index >= MAX_IRQ {
        warn!("irq {} 越界，无法注册处理器", irq);
        return;
    }
    let overwritten = {
        let mut table = IRQ_HANDLERS.lock();
        let occupied = table[index].is_some();
        table[index] = Some(handler);
        occupied
    };
    if overwritten {
        warn!("irq {} 处理器被覆盖", irq);
    }
    unsafe {
        arch::enable_irq(irq);
    }
}

/// 注销 IRQ 处理器并屏蔽对应中断。
pub fn unregister_irq_handler(irq: u32) {
    let index = irq as usize;
    if index >= MAX_IRQ {
        warn!("irq {} 越界，无法注销处理器", irq);
        return;
    }
    {
        let mut table = IRQ_HANDLERS.lock();
        table[index] = None;
    }
    unsafe {
        arch::disable_irq(irq);
    }
}

/// 按对数间隔告警：1 / 1000 / 100000 次未处理时各输出一次。
fn warn_unhandled(irq: u32, hits: u32) {
    if hits == 1 || hits == 1_000 || hits == 100_000 {
        warn!("irq {} 无处理器，累计未处理 {} 次", irq, hits);
    }
}
