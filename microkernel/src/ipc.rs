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
    CHANNEL_TABLE.lock().send(caller, chan, *msg)
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

    fn send(&mut self, caller: ProcessId, chan: u32, msg: Message) -> Result<(), IpcError> {
        let channel = self
            .channels
            .iter_mut()
            .find(|c| c.in_use && c.id == chan)
            .ok_or(IpcError::Invalid)?;
        channel.ensure_access(caller)?;
        channel.queue.push(msg, channel.capacity)
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
}

#[derive(Copy, Clone)]
struct Channel {
    in_use: bool,
    id: u32,
    capacity: usize,
    owner: Option<ProcessId>,
    queue: MessageQueue,
}

impl Channel {
    const fn new() -> Self {
        Self {
            in_use: false,
            id: 0,
            capacity: 0,
            owner: None,
            queue: MessageQueue::new(),
        }
    }

    fn reset(&mut self) {
        self.in_use = false;
        self.id = 0;
        self.capacity = 0;
        self.owner = None;
        self.queue.reset();
    }

    fn configure(&mut self, desc: ChannelDesc, owner: Option<ProcessId>) {
        self.in_use = true;
        self.id = desc.id;
        self.capacity = usize::min(desc.capacity as usize, MAX_QUEUE).max(1);
        self.owner = owner;
        self.queue.reset();
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
