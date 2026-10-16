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
    send_inner(caller, None, chan, msg)
}

/// Targeted delivery: the envelope stays on the shared channel but only `target`
/// can dequeue it. This fixes response theft between concurrent service clients
/// without multiplying channel IDs. Existing `send` remains broadcast/first-reader.
pub fn send_to(
    caller: ProcessId,
    target: ProcessId,
    chan: u32,
    msg: &Message,
) -> Result<(), IpcError> {
    send_inner(caller, Some(target), chan, msg)
}

fn send_inner(
    caller: ProcessId,
    target: Option<ProcessId>,
    chan: u32,
    msg: &Message,
) -> Result<(), IpcError> {
    let wake = CHANNEL_TABLE.lock().send(caller, target, chan, *msg)?;
    if let Some(pid) = wake {
        crate::scheduler::wake(pid);
    }
    Ok(())
}

/// 登记阻塞接收等待者。成功后调用方应立即 scheduler::block_current()。
pub fn register_waiter(caller: ProcessId, chan: u32) -> Result<(), IpcError> {
    CHANNEL_TABLE.lock().register_waiter(caller, chan)
}

pub fn receive(caller: ProcessId, chan: u32) -> Result<(ProcessId, Message), IpcError> {
    CHANNEL_TABLE.lock().receive(caller, chan)
}

/// Atomically receive an eligible envelope or register `caller` as a waiter.
///
/// This is the only safe primitive for blocking receive on SMP. A split
/// `receive() -> Empty; register_waiter()` sequence has a lost-wakeup window:
/// another CPU can enqueue the response between the two calls, observe no
/// waiter, and leave the receiver sleeping forever with a message already in
/// the queue. Holding CHANNEL_TABLE across both decisions closes that window.
pub fn receive_or_register_waiter(
    caller: ProcessId,
    chan: u32,
) -> Result<Option<(ProcessId, Message)>, IpcError> {
    CHANNEL_TABLE
        .lock()
        .receive_or_register_waiter(caller, chan)
}

#[derive(Debug)]
pub enum IpcError {
    NotReady,
    ChannelBusy,
    Invalid,
    Empty,
    AccessDenied,
    /// 通道组策略拒绝（第十三刀）：通道 tx_groups/rx_groups 掩码非 0
    /// 而调用方有效能力位图与之无交集——与 owner 不符的
    /// [`IpcError::AccessDenied`] 区分开，主机测试可精确断言两条
    /// 拒绝路径；对用户态统一映射 PermissionDenied。
    PolicyDenied,
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
    ///
    /// 访问控制两道闸（第十三刀起）：owner 匹配 + tx 组策略。
    fn send(
        &mut self,
        caller: ProcessId,
        target: Option<ProcessId>,
        chan: u32,
        msg: Message,
    ) -> Result<Option<ProcessId>, IpcError> {
        let channel = self
            .channels
            .iter_mut()
            .find(|c| c.in_use && c.id == chan)
            .ok_or(IpcError::Invalid)?;
        channel.ensure_access(caller)?;
        channel.ensure_groups(channel.tx_groups, caller)?;
        channel.queue.push(
            Envelope {
                sender: caller,
                target: target.unwrap_or(ProcessId::new(0)),
                message: msg,
            },
            channel.capacity,
        )?;
        Ok(channel.pop_waiter_for(target))
    }

    /// 接收。owner 匹配 + rx 组策略。
    fn receive(&mut self, caller: ProcessId, chan: u32) -> Result<(ProcessId, Message), IpcError> {
        let channel = self
            .channels
            .iter_mut()
            .find(|c| c.in_use && c.id == chan)
            .ok_or(IpcError::Invalid)?;
        channel.ensure_access(caller)?;
        channel.ensure_groups(channel.rx_groups, caller)?;
        let env = channel.queue.pop_for(caller)?;
        Ok((env.sender, env.message))
    }

    /// Atomic blocking-receive decision: dequeue now if possible, otherwise
    /// install the waiter before releasing CHANNEL_TABLE.
    fn receive_or_register_waiter(
        &mut self,
        caller: ProcessId,
        chan: u32,
    ) -> Result<Option<(ProcessId, Message)>, IpcError> {
        let channel = self
            .channels
            .iter_mut()
            .find(|c| c.in_use && c.id == chan)
            .ok_or(IpcError::Invalid)?;
        channel.ensure_access(caller)?;
        channel.ensure_groups(channel.rx_groups, caller)?;
        match channel.queue.pop_for(caller) {
            Ok(env) => Ok(Some((env.sender, env.message))),
            Err(IpcError::Empty) => {
                if channel.waiters.iter().any(|w| *w == Some(caller)) {
                    return Ok(None);
                }
                if let Some(slot) = channel.waiters.iter_mut().find(|w| w.is_none()) {
                    *slot = Some(caller);
                    Ok(None)
                } else {
                    Err(IpcError::ChannelBusy)
                }
            }
            Err(err) => Err(err),
        }
    }

    /// 登记接收等待者（阻塞式接收的挂起点）。容量 4：超出返回 Busy，
    /// 调用方应退化为轮询（与 Mach msg-wait 上限语义同型）。
    /// 等待即未来接收 ⇒ 同样受 rx 组策略约束（不能绕过掩码占坑）。
    fn register_waiter(&mut self, caller: ProcessId, chan: u32) -> Result<(), IpcError> {
        let channel = self
            .channels
            .iter_mut()
            .find(|c| c.in_use && c.id == chan)
            .ok_or(IpcError::Invalid)?;
        channel.ensure_access(caller)?;
        channel.ensure_groups(channel.rx_groups, caller)?;
        if channel.waiters.iter().any(|w| *w == Some(caller)) {
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
    /// 发送许可位图（第十三刀；0 = 全通，向后兼容缺省）。
    tx_groups: u32,
    /// 接收许可位图（第十三刀；0 = 全通）。
    rx_groups: u32,
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
            tx_groups: 0,
            rx_groups: 0,
            queue: MessageQueue::new(),
            waiters: [None; WAITERS_PER_CHANNEL],
        }
    }

    fn reset(&mut self) {
        self.in_use = false;
        self.id = 0;
        self.capacity = 0;
        self.owner = None;
        self.tx_groups = 0;
        self.rx_groups = 0;
        self.queue.reset();
        self.waiters = [None; WAITERS_PER_CHANNEL];
    }

    fn configure(&mut self, desc: ChannelDesc, owner: Option<ProcessId>) {
        self.in_use = true;
        self.id = desc.id;
        self.capacity = usize::min(desc.capacity as usize, MAX_QUEUE).max(1);
        self.owner = owner;
        self.tx_groups = desc.tx_groups;
        self.rx_groups = desc.rx_groups;
        self.queue.reset();
        self.waiters = [None; WAITERS_PER_CHANNEL];
    }

    /// 取走一个等待者（FIFO）。send 成功后由调用方触发调度器唤醒。
    fn pop_waiter_for(&mut self, target: Option<ProcessId>) -> Option<ProcessId> {
        if let Some(target) = target {
            if let Some(w) = self.waiters.iter_mut().find(|w| **w == Some(target)) {
                return w.take();
            }
            return None;
        }
        for w in self.waiters.iter_mut() {
            if w.is_some() {
                return w.take();
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

    /// 组策略判定（第十三刀）：掩码 0 = 全通；非 0 要求调用方有效能力
    /// （静态位图 ∪ 动态授予，见 security::effective_caps）与掩码有
    /// 交集——"任一组命中即放行"的或语义，最小授权按需配位。
    fn ensure_groups(&self, mask: u32, caller: ProcessId) -> Result<(), IpcError> {
        if group_allows(mask, crate::security::effective_caps(caller)) {
            Ok(())
        } else {
            Err(IpcError::PolicyDenied)
        }
    }
}

/// 组许可纯函数（主机单测钉死允许/拒绝矩阵）：掩码为空放行一切
/// （向后兼容：引导期预建通道全通）；非空时按位与求交。
fn group_allows(mask: u32, caller_caps: u32) -> bool {
    mask == 0 || caller_caps & mask != 0
}

#[derive(Copy, Clone)]
struct Envelope {
    sender: ProcessId,
    /// pid=0 means broadcast/first eligible reader.
    target: ProcessId,
    message: Message,
}

impl Envelope {
    const EMPTY: Self = Self {
        sender: ProcessId::new(0),
        target: ProcessId::new(0),
        message: Message::empty(),
    };
}

#[derive(Copy, Clone)]
struct MessageQueue {
    buf: [Envelope; MAX_QUEUE],
    head: usize,
    tail: usize,
    len: usize,
}

impl MessageQueue {
    const fn new() -> Self {
        Self {
            buf: [Envelope::EMPTY; MAX_QUEUE],
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

    fn push(&mut self, msg: Envelope, capacity: usize) -> Result<(), IpcError> {
        if self.len == capacity {
            return Err(IpcError::ChannelBusy);
        }
        self.buf[self.tail] = msg;
        self.tail = (self.tail + 1) % MAX_QUEUE;
        self.len += 1;
        Ok(())
    }

    fn pop(&mut self) -> Result<Envelope, IpcError> {
        self.pop_for(ProcessId::new(0))
    }

    /// Remove the first broadcast envelope or envelope targeted at `caller`,
    /// preserving relative order of all other entries. Queue is only 16 deep, so
    /// the bounded O(n) compaction is simpler and safer than per-client queues.
    fn pop_for(&mut self, caller: ProcessId) -> Result<Envelope, IpcError> {
        if self.len == 0 {
            return Err(IpcError::Empty);
        }
        let mut found = None;
        for off in 0..self.len {
            let idx = (self.head + off) % MAX_QUEUE;
            let target = self.buf[idx].target.raw();
            if target == 0 || (caller.raw() != 0 && target == caller.raw()) {
                found = Some(off);
                break;
            }
        }
        let Some(off) = found else {
            return Err(IpcError::Empty);
        };
        let idx = (self.head + off) % MAX_QUEUE;
        let out = self.buf[idx];
        for j in off..self.len - 1 {
            let from = (self.head + j + 1) % MAX_QUEUE;
            let to = (self.head + j) % MAX_QUEUE;
            self.buf[to] = self.buf[from];
        }
        self.tail = (self.tail + MAX_QUEUE - 1) % MAX_QUEUE;
        self.len -= 1;
        Ok(out)
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

    fn env(n: u32) -> Envelope {
        Envelope {
            sender: ProcessId::new(11),
            target: ProcessId::new(0),
            message: msg(n),
        }
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
            q.push(env(n), MAX_QUEUE).unwrap();
        }
        for n in 1..=8 {
            assert_eq!(q.pop().unwrap().message.code, n);
        }
        assert!(matches!(q.pop(), Err(IpcError::Empty)));
    }

    #[test]
    fn atomic_receive_register_closes_prequeued_wakeup_gap() {
        let mut t = ChannelTable::new();
        t.create(ChannelDesc::open(0x2a0, 4), None).unwrap();
        let alice = ProcessId::new(7);
        let bob = ProcessId::new(8);
        let m = msg(99);
        // Response lands before the would-be receiver registers. The atomic
        // primitive must consume it immediately and leave no stale waiter.
        t.send(bob, Some(alice), 0x2a0, m).unwrap();
        let got = t.receive_or_register_waiter(alice, 0x2a0).unwrap();
        assert_eq!(got.unwrap().1.code, 99);
        let c = t
            .channels
            .iter()
            .find(|c| c.in_use && c.id == 0x2a0)
            .unwrap();
        assert!(!c.waiters.iter().any(|w| *w == Some(alice)));
    }

    #[test]
    fn atomic_receive_register_wakes_after_registration() {
        let mut t = ChannelTable::new();
        t.create(ChannelDesc::open(0x2a1, 4), None).unwrap();
        let alice = ProcessId::new(7);
        let bob = ProcessId::new(8);
        assert!(t
            .receive_or_register_waiter(alice, 0x2a1)
            .unwrap()
            .is_none());
        let wake = t.send(bob, Some(alice), 0x2a1, msg(42)).unwrap();
        assert_eq!(wake, Some(alice));
        assert_eq!(t.receive(alice, 0x2a1).unwrap().1.code, 42);
    }

    #[test]
    fn targeted_envelopes_cannot_be_stolen() {
        let mut q = MessageQueue::new();
        let mut a = env(1);
        a.target = ProcessId::new(7);
        let mut b = env(2);
        b.target = ProcessId::new(8);
        q.push(a, MAX_QUEUE).unwrap();
        q.push(b, MAX_QUEUE).unwrap();
        assert_eq!(q.pop_for(ProcessId::new(8)).unwrap().message.code, 2);
        assert!(matches!(q.pop_for(ProcessId::new(8)), Err(IpcError::Empty)));
        assert_eq!(q.pop_for(ProcessId::new(7)).unwrap().message.code, 1);
    }

    #[test]
    fn queue_full_rejected() {
        let mut q = MessageQueue::new();
        for n in 0..MAX_QUEUE {
            q.push(env(n as u32), MAX_QUEUE).unwrap();
        }
        // 容量=16 时第 17 个被拒
        assert!(matches!(
            q.push(env(999), MAX_QUEUE),
            Err(IpcError::ChannelBusy)
        ));
        // 限定更小 capacity 同样生效
        let mut q2 = MessageQueue::new();
        for n in 0..4 {
            q2.push(env(n as u32), 4).unwrap();
        }
        assert!(matches!(q2.push(env(4), 4), Err(IpcError::ChannelBusy)));
    }

    #[test]
    fn queue_wrap_around() {
        let mut q = MessageQueue::new();
        for n in 0..MAX_QUEUE {
            q.push(env(n as u32), MAX_QUEUE).unwrap();
        }
        for n in 0..MAX_QUEUE {
            assert_eq!(q.pop().unwrap().message.code, n as u32);
        }
        // head 已绕回，再入队出队顺序仍正确（容量仍为 MAX_QUEUE）
        for n in 100..(100 + MAX_QUEUE) {
            q.push(env(n as u32), MAX_QUEUE).unwrap();
        }
        for n in 100..(100 + MAX_QUEUE) {
            assert_eq!(q.pop().unwrap().message.code, n as u32);
        }
        assert!(matches!(q.pop(), Err(IpcError::Empty)));
    }

    #[test]
    fn channel_capacity_floor() {
        // configure 会把容量夹在 [1, MAX_QUEUE]
        let mut c = Channel::new();
        c.configure(ChannelDesc::open(1, 0), None);
        assert_eq!(c.capacity, 1);
        c.configure(ChannelDesc::open(1, 999), None);
        assert_eq!(c.capacity, MAX_QUEUE);
    }

    // ══ 第十三刀：RX/TX 组许可（允许/拒绝矩阵）══════════════════

    use zero_abi::cap::{CAP_SECURE_IPC, CAP_SPAWN_SVC};

    /// 有状态用例（CHANNEL_TABLE / security 测试覆盖表是全局的）串行化：
    /// cargo test 默认多线程并行，不锁必竞态。
    static TEST_SERIAL: Mutex<()> = Mutex::new(());

    #[test]
    fn group_allows_matrix() {
        // 掩码 0 = 全通（向后兼容不变量的纯函数面）
        assert!(group_allows(0, 0));
        assert!(group_allows(0, CAP_SECURE_IPC));
        // 非空掩码：任一命中位放行
        assert!(group_allows(CAP_SECURE_IPC, CAP_SECURE_IPC));
        assert!(group_allows(CAP_SECURE_IPC | CAP_SPAWN_SVC, CAP_SECURE_IPC));
        assert!(group_allows(CAP_SECURE_IPC | CAP_SPAWN_SVC, CAP_SPAWN_SVC));
        // 无交集拒绝
        assert!(!group_allows(CAP_SECURE_IPC, 0));
        assert!(!group_allows(CAP_SECURE_IPC, CAP_SPAWN_SVC));
        assert!(!group_allows(CAP_SPAWN_SVC, CAP_SECURE_IPC));
    }

    /// 建一条 tx=CAP_SECURE_IPC、rx=CAP_SECURE_IPC 的受保护通道，
    /// 全通对照通道与 owner 型通道各一。
    fn setup_protected_channels() {
        CHANNEL_TABLE.lock().reset();
        create_channel(ChannelDesc {
            id: 0x270,
            capacity: 4,
            tx_groups: CAP_SECURE_IPC,
            rx_groups: CAP_SECURE_IPC,
        })
        .unwrap();
        create_channel(ChannelDesc::open(0x271, 4)).unwrap();
    }

    const ALICE: ProcessId = ProcessId::new(11); // 持组位
    const BOB: ProcessId = ProcessId::new(12); // 无组位
    const CH: u32 = 0x270;
    const OPEN_CH: u32 = 0x271;

    fn set_caps(pid: ProcessId, caps: u32) {
        crate::security::test_set_caps(pid, caps);
    }

    #[test]
    fn protected_channel_tx_deny_without_group() {
        let _serial = TEST_SERIAL.lock();
        setup_protected_channels();
        set_caps(ALICE, CAP_SECURE_IPC);
        set_caps(BOB, 0);
        // 允许：持组位发送
        assert!(send(ALICE, CH, &msg(1)).is_ok());
        // 拒绝：无组位 → PolicyDenied（与 owner 型 AccessDenied 区分）
        assert!(matches!(
            send(BOB, CH, &msg(2)),
            Err(IpcError::PolicyDenied)
        ));
        // 对照：全通通道对无任何能力的进程也放行（向后兼容）
        assert!(send(BOB, OPEN_CH, &msg(3)).is_ok());
        assert!(receive(BOB, OPEN_CH).is_ok());
    }

    #[test]
    fn protected_channel_rx_matrix() {
        let _serial = TEST_SERIAL.lock();
        setup_protected_channels();
        set_caps(ALICE, CAP_SECURE_IPC);
        set_caps(BOB, 0);
        send(ALICE, CH, &msg(7)).unwrap();
        // 无组接收者被拒且消息不被消费
        assert!(matches!(receive(BOB, CH), Err(IpcError::PolicyDenied)));
        // 持组接收者取到消息
        assert_eq!(receive(ALICE, CH).unwrap().1.code, 7);
        // 阻塞等待登记同样受 rx 组约束
        assert!(register_waiter(ALICE, CH).is_ok());
        assert!(matches!(
            register_waiter(BOB, CH),
            Err(IpcError::PolicyDenied)
        ));
    }

    #[test]
    fn dynamic_grant_flips_denial_to_allow() {
        let _serial = TEST_SERIAL.lock();
        setup_protected_channels();
        set_caps(BOB, 0);
        assert!(matches!(
            send(BOB, CH, &msg(1)),
            Err(IpcError::PolicyDenied)
        ));
        // securityd 动态签发后（测试直接钉住有效能力，等价于授予生效）
        set_caps(BOB, CAP_SECURE_IPC);
        assert!(send(BOB, CH, &msg(2)).is_ok());
        // revoke 后再拒
        set_caps(BOB, 0);
        assert!(matches!(
            send(BOB, CH, &msg(3)),
            Err(IpcError::PolicyDenied)
        ));
    }

    #[test]
    fn policy_denied_distinct_from_owner_denied() {
        let _serial = TEST_SERIAL.lock();
        // owner 型拒绝（create_channel_for 指定属主）保持 AccessDenied；
        // 组策略拒绝是 PolicyDenied——两条路径可精确区分。
        CHANNEL_TABLE.lock().reset();
        create_channel_for(ALICE, ChannelDesc::open(0x272, 4)).unwrap();
        set_caps(BOB, CAP_SECURE_IPC);
        // BOB 虽有组位，但不是通道属主 → owner 闸先拦
        assert!(matches!(
            send(BOB, 0x272, &msg(1)),
            Err(IpcError::AccessDenied)
        ));
    }
}
