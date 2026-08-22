use spin::Mutex;
use zero_abi::ipc::{ChannelDesc, Message};
use zero_abi::ProcessId;

const MAX_CHANNELS: usize = 32;
const MAX_QUEUE: usize = 16;

static CHANNEL_TABLE: Mutex<ChannelTable> = Mutex::new(ChannelTable::new());

pub fn init() {
    CHANNEL_TABLE.lock().reset();
}

pub fn create_channel(desc: ChannelDesc) -> Result<(), IpcError> {
    CHANNEL_TABLE.lock().create(desc, None)
}

pub fn create_channel_for(owner: ProcessId, desc: ChannelDesc) -> Result<(), IpcError> {
    CHANNEL_TABLE.lock().create(desc, Some(owner))
}

pub fn send(caller: ProcessId, chan: u32, msg: &Message) -> Result<(), IpcError> {
    // 锁纪律：持通道表锁完成入队并取出待唤醒者；释放锁后才触碰调度器。
    let wake = CHANNEL_TABLE.lock().send(caller, chan, *msg)?;
    if let Some(pid) = wake {
        crate::scheduler::wake(pid);
    }
    Ok(())
}

/// 登记阻塞接收等待者。成功后调用方应立即 scheduler::block_current()。
pub fn register_waiter(caller: ProcessId, chan: u32) -> Result<(), IpcError> {
    CHANNEL_TABLE.lock().register_waiter(caller, chan)
}

pub fn receive(caller: ProcessId, chan: u32) -> Result<Message, IpcError> {
    CHANNEL_TABLE.lock().receive(caller, chan)
}

#[derive(Debug)]
pub enum IpcError {
    NotReady,
    ChannelBusy,
    Invalid,
    Empty,
    AccessDenied,
}

struct ChannelTable {
    channels: [Channel; MAX_CHANNELS],
}

impl ChannelTable {
    const fn new() -> Self {
        Self {
            channels: [Channel::new(); MAX_CHANNELS],
        }
    }

    fn reset(&mut self) {
        for channel in self.channels.iter_mut() {
            channel.reset();
        }
    }

    fn create(&mut self, desc: ChannelDesc, owner: Option<ProcessId>) -> Result<(), IpcError> {
        if self.channels.iter().any(|c| c.in_use && c.id == desc.id) {
            return Err(IpcError::Invalid);
        }

        if let Some(channel) = self.channels.iter_mut().find(|c| !c.in_use) {
            channel.configure(desc, owner);
            Ok(())
        } else {
            Err(IpcError::ChannelBusy)
        }
    }

    /// 发送。成功时返回该通道上**待唤醒的接收者**（如有）——调用方
    /// 必须在释放 CHANNEL_TABLE 锁之后调用 scheduler::wake（锁序：
    /// 通道表 → 就绪队列，绝不反向，也不得持锁进调度器）。
    fn send(&mut self, caller: ProcessId, chan: u32, msg: Message) -> Result<Option<ProcessId>, IpcError> {
        let channel = self
            .channels
            .iter_mut()
            .find(|c| c.in_use && c.id == chan)
            .ok_or(IpcError::Invalid)?;
        channel.ensure_access(caller)?;
        channel.queue.push(msg, channel.capacity)?;
        Ok(channel.pop_waiter())
    }

    fn receive(&mut self, caller: ProcessId, chan: u32) -> Result<Message, IpcError> {
        let channel = self
            .channels
            .iter_mut()
            .find(|c| c.in_use && c.id == chan)
            .ok_or(IpcError::Invalid)?;
        channel.ensure_access(caller)?;
        channel.queue.pop()
    }

    /// 登记接收等待者（阻塞式接收的挂起点）。容量 4：超出返回 Busy，
    /// 调用方应退化为轮询（与 Mach msg-wait 上限语义同型）。
    fn register_waiter(&mut self, caller: ProcessId, chan: u32) -> Result<(), IpcError> {
        let channel = self
            .channels
            .iter_mut()
            .find(|c| c.in_use && c.id == chan)
            .ok_or(IpcError::Invalid)?;
        channel.ensure_access(caller)?;
        if channel
            .waiters
            .iter()
            .any(|w| *w == Some(caller))
        {
            return Ok(()); // 重复登记幂等
        }
        if let Some(slot) = channel.waiters.iter_mut().find(|w| w.is_none()) {
            *slot = Some(caller);
            Ok(())
        } else {
            Err(IpcError::ChannelBusy)
        }
    }

    /// 注销等待者（进程退出/不再等待时；当前由 wake 消费替代，
    /// 保留给未来超时/信号路径）。
    #[allow(dead_code)]
    fn unregister_waiter(&mut self, caller: ProcessId, chan: u32) {
        if let Some(channel) = self.channels.iter_mut().find(|c| c.in_use && c.id == chan) {
            for w in channel.waiters.iter_mut() {
                if *w == Some(caller) {
                    *w = None;
                }
            }
        }
    }
}

/// 每通道接收等待者上限。超出后调用方退化为轮询。
const WAITERS_PER_CHANNEL: usize = 4;

#[derive(Copy, Clone)]
struct Channel {
    in_use: bool,
    id: u32,
    capacity: usize,
    owner: Option<ProcessId>,
    queue: MessageQueue,
    /// 阻塞接收的等待者队列（send 成功后逐一唤醒）。
    waiters: [Option<ProcessId>; WAITERS_PER_CHANNEL],
}

impl Channel {
    const fn new() -> Self {
        Self {
            in_use: false,
            id: 0,
            capacity: 0,
            owner: None,
            queue: MessageQueue::new(),
            waiters: [None; WAITERS_PER_CHANNEL],
        }
    }

    fn reset(&mut self) {
        self.in_use = false;
        self.id = 0;
        self.capacity = 0;
        self.owner = None;
        self.queue.reset();
        self.waiters = [None; WAITERS_PER_CHANNEL];
    }

    fn configure(&mut self, desc: ChannelDesc, owner: Option<ProcessId>) {
        self.in_use = true;
        self.id = desc.id;
        self.capacity = usize::min(desc.capacity as usize, MAX_QUEUE).max(1);
        self.owner = owner;
        self.queue.reset();
        self.waiters = [None; WAITERS_PER_CHANNEL];
    }

    /// 取走一个等待者（FIFO）。send 成功后由调用方触发调度器唤醒。
    fn pop_waiter(&mut self) -> Option<ProcessId> {
        for w in self.waiters.iter_mut() {
            if let Some(pid) = w.take() {
                return Some(pid);
            }
        }
        None
    }

    fn ensure_access(&self, caller: ProcessId) -> Result<(), IpcError> {
        if let Some(owner) = self.owner {
            if owner != caller {
                return Err(IpcError::AccessDenied);
            }
        }
        Ok(())
    }
}

#[derive(Copy, Clone)]
struct MessageQueue {
    buf: [Message; MAX_QUEUE],
    head: usize,
    tail: usize,
    len: usize,
}

impl MessageQueue {
    const fn new() -> Self {
        Self {
            buf: [Message::empty(); MAX_QUEUE],
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    fn reset(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.len = 0;
    }

    fn push(&mut self, msg: Message, capacity: usize) -> Result<(), IpcError> {
        if self.len == capacity {
            return Err(IpcError::ChannelBusy);
        }
        self.buf[self.tail] = msg;
        self.tail = (self.tail + 1) % MAX_QUEUE;
        self.len += 1;
        Ok(())
    }

    fn pop(&mut self) -> Result<Message, IpcError> {
        if self.len == 0 {
            return Err(IpcError::Empty);
        }
        let msg = self.buf[self.head];
        self.head = (self.head + 1) % MAX_QUEUE;
        self.len -= 1;
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(n: u32) -> Message {
        let mut m = Message::empty();
        m.code = n;
        m
    }

    #[test]
    fn queue_empty_pop() {
        let mut q = MessageQueue::new();
        assert!(matches!(q.pop(), Err(IpcError::Empty)));
    }

    #[test]
    fn queue_push_pop_roundtrip() {
        let mut q = MessageQueue::new();
        for n in 1..=8 {
            q.push(msg(n), MAX_QUEUE).unwrap();
        }
        for n in 1..=8 {
            assert_eq!(q.pop().unwrap().code, n);
        }
        assert!(matches!(q.pop(), Err(IpcError::Empty)));
    }

    #[test]
    fn queue_full_rejected() {
        let mut q = MessageQueue::new();
        for n in 0..MAX_QUEUE {
            q.push(msg(n as u32), MAX_QUEUE).unwrap();
        }
        // 容量=16 时第 17 个被拒
        assert!(matches!(
            q.push(msg(999), MAX_QUEUE),
            Err(IpcError::ChannelBusy)
        ));
        // 限定更小 capacity 同样生效
        let mut q2 = MessageQueue::new();
        for n in 0..4 {
            q2.push(msg(n as u32), 4).unwrap();
        }
        assert!(matches!(q2.push(msg(4), 4), Err(IpcError::ChannelBusy)));
    }

    #[test]
    fn queue_wrap_around() {
        let mut q = MessageQueue::new();
        for n in 0..MAX_QUEUE {
            q.push(msg(n as u32), MAX_QUEUE).unwrap();
        }
        for n in 0..MAX_QUEUE {
            assert_eq!(q.pop().unwrap().code, n as u32);
        }
        // head 已绕回，再入队出队顺序仍正确（容量仍为 MAX_QUEUE）
        for n in 100..(100 + MAX_QUEUE) {
            q.push(msg(n as u32), MAX_QUEUE).unwrap();
        }
        for n in 100..(100 + MAX_QUEUE) {
            assert_eq!(q.pop().unwrap().code, n as u32);
        }
        assert!(matches!(q.pop(), Err(IpcError::Empty)));
    }

    #[test]
    fn channel_capacity_floor() {
        // configure 会把容量夹在 [1, MAX_QUEUE]
        let mut c = Channel::new();
        c.configure(
            ChannelDesc { id: 1, capacity: 0 },
            None,
        );
        assert_eq!(c.capacity, 1);
        c.configure(
            ChannelDesc {
                id: 1,
                capacity: 999,
            },
            None,
        );
        assert_eq!(c.capacity, MAX_QUEUE);
    }
}
