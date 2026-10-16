//! # security —— capability 动态签发与登录会话核心（第十三刀）
//!
//! 微内核侧的安全台账：securityd（EL0 服务）经号位 40/41
//! `CapGrant`/`CapRevoke` 在此落账，进程经号位 43-45 建立会话并查询。
//!
//! ## 设计要点
//!
//! 1. **活算模型（live evaluation）**：授予/撤销**从不改写**进程表里的
//!    静态能力位图。目标的有效能力 = 静态位图 ∪ Σ{有效授予的 caps}，
//!    每次门控判定时现算（[`effective_caps`]）。收益：
//!    - 撤销即时生效，无需回写各进程；
//!    - fork 天然不继承动态授予——子 pid 名下无台账记录，静态位图照旧
//!      继承（最小授权：动态签发的权柄不随血脉扩散）；
//!    - 过期惰性判定（被查询时才失效），零中断开销。
//! 2. **逻辑时钟**：单核实验内核无墙钟，TTL 以全局逻辑时钟近似单调
//!    时间——每次任意系统调用步进 1（syscalls::handle 入口调用
//!    [`advance_clock`]）。过期惰性判定：被查询时才失效，不占中断预算。
//! 3. **会话绑定**：授予在签发时记下目标的**当前会话 id**；会话注销
//!    （su 换会话 / 会话领袖消亡）时其名下全部授予一并失效——跨会话
//!    重放防线。session==0 的授予视为未绑定（无会话进程间的演示授权）。
//! 4. **登录令牌一次性消费**：含 `CAP_SESSION` 的授予只能被
//!    SessionBegin 消费一次，消费即摘除（防重放）。
//! 5. **签发权不可转授**：caps 含 `CAP_ISSUER` 的请求一律拒绝——
//!    签发权扩散等于整个策略体系失效。
//!
//! ## 锁纪律
//!
//! 台账锁（BOOK）在外层、进程表锁在内层（本模块读目标静态位图/会话
//! 时短暂获取）。全仓库无人反向持有进程表锁来拿台账锁（full_reap /
//! waitpid 的回收钩子都在释放表锁之后调用 [`on_process_gone`]），无
//! 死锁环。
//!
//! ## 主机测试
//!
//! 决策核心收敛在纯结构体 [`GrantBook`]（不含全局态与进程表依赖），
//! 主机单测直接驱动它覆盖签发/撤销/过期/会话绑定矩阵；全局包装只做
//! 锁与进程表读取的搬运。

use alloc::vec::Vec;
use spin::Mutex;
use zero_abi::cap::{CAP_ISSUER, CAP_SESSION};
use zero_abi::ProcessId;

/// 授予台账容量（超限拒绝新签发；16 对实验系统远超并发需求）。
pub(crate) const MAX_GRANTS: usize = 16;
/// 存活会话容量。
const MAX_SESSIONS: usize = 8;

/// Legacy hook kept ABI-internal for callers from the syscall entry. TTL is now
/// based on real monotonic milliseconds, so syscall frequency cannot extend or
/// shorten a grant.
pub fn advance_clock() {}

pub fn now() -> u64 {
    crate::time::monotonic_ms()
}

/// 签发失败原因（对外映射见 syscalls.rs 号位 40 臂）。
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IssueError {
    /// 能力位图为空或包含 CAP_ISSUER（不可转授）。
    InvalidScope,
    /// 目标 PID 当前不存在。禁止给“未来 PID”预埋授权。
    NoSuchProcess,
    /// 台账已满。
    TableFull,
}

/// 会话建立失败原因。
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SessionError {
    /// token 不存在 / 已消费 / 已撤销。
    NoSuchToken,
    /// token 属于其他进程（防挪用）或不含 CAP_SESSION。
    NotYours,
    /// token 已过有效期。
    Expired,
    /// 会话表满。
    TableFull,
}

/// 一条能力授予（台账行）。
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Grant {
    /// 内核分配的令牌编号（从 1 起单调；0 不是合法 token）。
    token: u64,
    /// 被授予进程。
    pid: ProcessId,
    /// 授予的能力位（保证不含 CAP_ISSUER，见 GrantBook::issue）。
    caps: u32,
    /// 失效时刻（monotonic millisecond deadline；u64::MAX = 不过期）。
    expires_at: u64,
    /// 签发时目标的会话 id；0 = 未绑定（任何会话下都有效）。
    session: u64,
    /// 含 CAP_SESSION ⇒ 由 SessionBegin 一次性消费。
    login_once: bool,
}

impl Grant {
    /// 有效判定（纯函数）：在账（未撤销/未消费）+ 未过期 + 会话匹配
    /// （未绑定或等于当前会话）。
    fn covers(&self, pid: ProcessId, session: u64, now: u64) -> bool {
        self.pid == pid && now < self.expires_at && (self.session == 0 || self.session == session)
    }
}

/// 存活会话记录。
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct SessionRecord {
    id: u64,
    leader: ProcessId,
}

/// 台账决策核心（纯结构体，主机单测直接驱动；全局包装薄壳搬运）。
pub(crate) struct GrantBook {
    grants: Vec<Grant>,
    sessions: Vec<SessionRecord>,
    next_token: u64,
    next_session: u64,
}

impl GrantBook {
    pub(crate) const fn new() -> Self {
        Self {
            grants: Vec::new(),
            sessions: Vec::new(),
            next_token: 1,
            next_session: 1,
        }
    }

    /// 惰性清扫过期授予（变更前调用；过期行就地摘除）。
    fn sweep(&mut self, now: u64) {
        self.grants.retain(|g| now < g.expires_at);
    }

    /// 动态签发一条授予，返回令牌编号。
    ///
    /// - caps 为空或含 CAP_ISSUER → [`IssueError::InvalidScope`]；
    /// - 台账满 → [`IssueError::TableFull`]；
    /// - ttl == 0 视为不过期（expires_at 封顶 u64::MAX）。
    pub(crate) fn issue(
        &mut self,
        target: ProcessId,
        caps: u32,
        ttl: u64,
        target_session: u64,
        now: u64,
    ) -> Result<u64, IssueError> {
        if caps == 0 || caps & CAP_ISSUER != 0 {
            return Err(IssueError::InvalidScope);
        }
        // 先惰性清扫过期行、再判容量：过期名额即时可复用。
        self.sweep(now);
        if self.grants.len() >= MAX_GRANTS {
            return Err(IssueError::TableFull);
        }
        let token = self.next_token;
        self.next_token += 1;
        self.grants.push(Grant {
            token,
            pid: target,
            caps,
            expires_at: if ttl == 0 {
                u64::MAX
            } else {
                now.saturating_add(ttl)
            },
            session: target_session,
            login_once: caps & CAP_SESSION != 0,
        });
        Ok(token)
    }

    /// 按令牌撤销；返回是否存在该行（不存在=已被撤销或从未签发，
    /// 上层如实报 NotFound 不静默）。
    pub(crate) fn revoke(&mut self, token: u64) -> bool {
        let before = self.grants.len();
        self.grants.retain(|g| g.token != token);
        before != self.grants.len()
    }

    /// 目标的有效能力 = base ∪ Σ{有效授予}（活算，模块文档第 1 点）。
    pub(crate) fn effective(&self, pid: ProcessId, base: u32, session: u64, now: u64) -> u32 {
        let mut caps = base;
        for g in self.grants.iter() {
            if g.covers(pid, session, now) {
                caps |= g.caps;
            }
        }
        caps
    }

    /// 建立会话：消费一枚本进程名下的登录令牌（一次性），返回
    /// `(新 sid, Option<被注销的旧 sid>)`。
    ///
    /// su 场景（调用方已领有会话）：先注销旧会话——台账侧失效绑定旧
    /// 会话的授予并摘除记录；其余成员的会话字段清场由内核包装层完成
    /// （本纯核心不触进程表）。
    pub(crate) fn begin_session(
        &mut self,
        caller: ProcessId,
        token: u64,
        now: u64,
    ) -> Result<(u64, Option<u64>), SessionError> {
        let idx = match self.grants.iter().position(|g| g.token == token) {
            Some(idx) => idx,
            None => return Err(SessionError::NoSuchToken),
        };
        let grant = self.grants[idx];
        if grant.pid != caller || !grant.login_once {
            return Err(SessionError::NotYours);
        }
        if now >= grant.expires_at {
            return Err(SessionError::Expired);
        }
        // 会话表容量：领袖换会话（复用名额）不算新占。
        let replacing = self.sessions.iter().any(|s| s.leader == caller);
        if !replacing && self.sessions.len() >= MAX_SESSIONS {
            return Err(SessionError::TableFull);
        }
        // 一次性消费：摘除令牌（防重放的关键一步）。
        self.grants.remove(idx);

        let mut dead_sid = None;
        if let Some(pos) = self.sessions.iter().position(|s| s.leader == caller) {
            dead_sid = Some(self.sessions[pos].id);
            self.purge_session_book(dead_sid.unwrap_or(0));
        }
        let sid = self.next_session;
        self.next_session += 1;
        self.sessions.push(SessionRecord {
            id: sid,
            leader: caller,
        });
        Ok((sid, dead_sid))
    }

    /// 台账侧会话注销：失效绑定该会话的全部授予 + 摘除会话记录。
    fn purge_session_book(&mut self, sid: u64) {
        if sid == 0 {
            return;
        }
        self.grants.retain(|g| g.session != sid);
        self.sessions.retain(|s| s.id != sid);
    }

    /// 进程消亡钩子：清除其名下授予；若它是会话领袖则注销该会话，
    /// 返回 Some(dead_sid) 提示包装层清理其余成员的会话字段。
    pub(crate) fn on_process_gone(&mut self, pid: ProcessId) -> Option<u64> {
        self.grants.retain(|g| g.pid != pid);
        let pos = self.sessions.iter().position(|s| s.leader == pid)?;
        let sid = self.sessions[pos].id;
        self.purge_session_book(sid);
        Some(sid)
    }

    /// 存活会话快照（SessionList 系统调用的数据源）。
    pub(crate) fn sessions_snapshot(&self) -> Vec<(u64, ProcessId)> {
        self.sessions.iter().map(|s| (s.id, s.leader)).collect()
    }

    /// 在账授予数（诊断用）。
    #[cfg(test)]
    pub(crate) fn grant_count(&self) -> usize {
        self.grants.len()
    }
}

static BOOK: Mutex<Option<GrantBook>> = Mutex::new(None);

pub fn init() {
    *BOOK.lock() = Some(GrantBook::new());
}

fn with_book<R>(f: impl FnOnce(&mut GrantBook) -> R) -> R {
    let mut guard = BOOK.lock();
    // init 先于一切并发路径执行（kernel_main 串行段）；防御式兜底。
    let book = guard.get_or_insert_with(GrantBook::new);
    f(book)
}

/// 目标的有效能力（活算）：静态位图 ∪ 有效授予。IPC 组校验、
/// SpawnService/CreateChannel 门控统一走这里。
///
/// 【主机测试接缝】cfg(test) 下 TEST_CAPS_OVERRIDE 非空的 pid 直接
/// 返回覆盖值——ipc/syscalls 单测无需真实进程表记录即可驱动矩阵。
pub fn effective_caps(pid: ProcessId) -> u32 {
    #[cfg(test)]
    if let Some(caps) = test_caps_lookup(pid) {
        return caps;
    }
    let base = crate::process::capabilities_of_pid(pid);
    let session = crate::process::session_of_pid(pid);
    with_book(|book| book.effective(pid, base, session, now()))
}

/// 动态签发（号位 40 内核臂）。目标会话取自进程表现值。
pub fn issue_grant(target: ProcessId, caps: u32, ttl: u64) -> Result<u64, IssueError> {
    if crate::process::slot_for_pid(target).is_none() {
        return Err(IssueError::NoSuchProcess);
    }
    let target_session = crate::process::session_of_pid(target);
    let now = now();
    with_book(|book| book.issue(target, caps, ttl, target_session, now))
}

/// 撤销（号位 41 内核臂）。None = 未知令牌。
pub fn revoke_grant(token: u64) -> Option<()> {
    with_book(|book| book.revoke(token).then_some(()))
}

/// 建立会话（号位 43 内核臂）。dead_sid 非零时清场旧会话成员。
pub fn begin_session(caller: ProcessId, token: u64) -> Result<u64, SessionError> {
    let (sid, dead_sid) = with_book(|book| book.begin_session(caller, token, now()))?;
    if let Some(dead) = dead_sid {
        crate::process::clear_session_members(dead, caller);
    }
    crate::process::set_session(caller, sid);
    Ok(sid)
}

/// 进程回收钩子（process.rs 的 full_reap / 收尸路径在释放表锁后调用）：
/// 清其授予；若其为会话领袖则注销会话并清场成员。
pub fn on_process_gone(pid: ProcessId) {
    let dead_sid = with_book(|book| book.on_process_gone(pid));
    if let Some(sid) = dead_sid {
        crate::process::clear_session_members(sid, pid);
    }
}

/// 会话清单快照（号位 45 SessionList 数据源）。
pub fn sessions_snapshot() -> Vec<(u64, ProcessId)> {
    with_book(|book| book.sessions_snapshot())
}

// ── 主机测试接缝 ─────────────────────────────────────────────────────

#[cfg(test)]
static TEST_CAPS_OVERRIDE: Mutex<Vec<(ProcessId, u32)>> = Mutex::new(Vec::new());

#[cfg(test)]
fn test_caps_lookup(pid: ProcessId) -> Option<u32> {
    TEST_CAPS_OVERRIDE
        .lock()
        .iter()
        .find(|(p, _)| *p == pid)
        .map(|(_, c)| *c)
}

/// 测试专用：钉住某 pid 的有效能力（仅 cfg(test) 可见；真实构建不编译）。
#[cfg(test)]
pub(crate) fn test_set_caps(pid: ProcessId, caps: u32) {
    let mut overrides = TEST_CAPS_OVERRIDE.lock();
    match overrides.iter_mut().find(|(p, _)| *p == pid) {
        Some(entry) => entry.1 = caps,
        None => overrides.push((pid, caps)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use zero_abi::cap::{CAP_SECURE_IPC, CAP_SPAWN_SVC};

    fn pid(n: u64) -> ProcessId {
        ProcessId::new(n)
    }

    /// 每个用例独立台账（纯结构体，无全局态污染）。
    fn book() -> GrantBook {
        GrantBook::new()
    }

    #[test]
    fn issue_rejects_empty_scope_and_issuer_bit() {
        let mut b = book();
        assert_eq!(b.issue(pid(5), 0, 100, 0, 0), Err(IssueError::InvalidScope));
        assert_eq!(
            b.issue(pid(5), CAP_ISSUER, 100, 0, 0),
            Err(IssueError::InvalidScope),
            "签发权不可转授"
        );
        assert_eq!(
            b.issue(pid(5), CAP_SECURE_IPC | CAP_ISSUER, 100, 0, 0),
            Err(IssueError::InvalidScope),
            "混入签发权同样拒绝"
        );
        assert_eq!(b.grant_count(), 0);
    }

    #[test]
    fn effective_is_base_union_active_grants() {
        let mut b = book();
        // 签发：target=pid(5)，绑定会话 10，不过期（ttl=0），签发于 now=3
        let token = b.issue(pid(5), CAP_SECURE_IPC, 0, 10, 3).expect("issue");
        // base ∪ 授予
        assert_eq!(
            b.effective(pid(5), CAP_SPAWN_SVC, 10, 7),
            CAP_SPAWN_SVC | CAP_SECURE_IPC
        );
        // 其他 pid / 其他会话不受波及（会话绑定生效）
        assert_eq!(b.effective(pid(6), 0, 10, 7), 0);
        assert_eq!(b.effective(pid(5), 0, 11, 7), 0);
        // 未绑定授予（session=0）对任何会话生效
        let unbound = b.issue(pid(7), CAP_SECURE_IPC, 0, 0, 3).unwrap();
        assert_eq!(b.effective(pid(7), 0, 42, 7), CAP_SECURE_IPC);
        // 撤销后回落到 base
        assert!(b.revoke(token));
        assert!(b.revoke(unbound));
        assert_eq!(b.effective(pid(5), CAP_SPAWN_SVC, 10, 7), CAP_SPAWN_SVC);
        assert!(!b.revoke(token), "重复撤销如实报不存在");
    }

    #[test]
    fn ttl_zero_means_never_expire_and_ttl_counts_from_now() {
        let mut b = book();
        // 均签发于 now=0：forever 不过期；short 的 expires_at=0+10
        let _t_forever = b.issue(pid(1), CAP_SECURE_IPC, 0, 0, 0).unwrap();
        let _t_short = b.issue(pid(2), CAP_SECURE_IPC, 10, 0, 0).unwrap();
        // now=9：两者都活着
        assert_eq!(b.effective(pid(1), 0, 0, 9), CAP_SECURE_IPC);
        assert_eq!(b.effective(pid(2), 0, 0, 9), CAP_SECURE_IPC);
        // now=10：TTL=10 的恰好过期（有效条件是 now < expires_at）
        assert_eq!(b.effective(pid(2), 0, 0, 10), 0);
        // 不过期授予在任何时刻都活
        assert_eq!(b.effective(pid(1), 0, 0, u64::MAX - 1), CAP_SECURE_IPC);
    }

    #[test]
    fn sweep_prunes_expired_rows_and_frees_capacity() {
        let mut b = book();
        for i in 0..MAX_GRANTS {
            assert!(b.issue(pid(i as u64 + 1), CAP_SECURE_IPC, 5, 0, 0).is_ok());
        }
        // 表满
        assert_eq!(
            b.issue(pid(99), CAP_SECURE_IPC, 5, 0, 0),
            Err(IssueError::TableFull)
        );
        // 时间前进越过全部 TTL：惰性清扫释放容量
        assert!(b.issue(pid(99), CAP_SECURE_IPC, 100, 0, 50).is_ok());
    }

    #[test]
    fn login_token_is_one_shot_consumable_by_owner_only() {
        let mut b = book();
        let token = b.issue(pid(7), CAP_SESSION, 0, 0, 0).unwrap();
        // 非本进程不可消费
        assert_eq!(
            b.begin_session(pid(8), token, 1),
            Err(SessionError::NotYours)
        );
        // 本进程首刷成功：sid 从 1 起；令牌被消费
        let (sid, dead) = b.begin_session(pid(7), token, 2).expect("begin");
        assert_eq!((sid, dead), (1, None));
        assert_eq!(b.grant_count(), 0, "登录令牌一次性消费即摘除");
        // 重放同一令牌：NoSuchToken
        assert_eq!(
            b.begin_session(pid(7), token, 3),
            Err(SessionError::NoSuchToken),
            "跨会话重放防线"
        );
    }
    #[test]
    fn su_switch_purges_old_session_grants_and_reports_dead_sid() {
        let mut b = book();
        let first_token = b.issue(pid(7), CAP_SESSION, 0, 0, 0).unwrap();
        let (_, dead_none) = b.begin_session(pid(7), first_token, 1).unwrap();
        assert_eq!(dead_none, None);
        let old_sid = b.sessions_snapshot()[0].0;

        // 绑定旧会话的演示授予
        let demo = b.issue(pid(8), CAP_SECURE_IPC, 0, old_sid, 1).unwrap();
        // 未绑定授予（session=0）：换会话不应误伤
        let unbound = b.issue(pid(8), CAP_SPAWN_SVC, 0, 0, 0).unwrap();

        // su：领袖换新登录令牌再入会话
        let new_token = b.issue(pid(7), CAP_SESSION, 0, 0, 0).unwrap();
        let (new_sid, dead) = b.begin_session(pid(7), new_token, 4).expect("su begin");
        assert_ne!(new_sid, old_sid);
        assert_eq!(dead, Some(old_sid));

        // 旧会话绑定授予已失效；未绑定授予存活
        assert!(!b.revoke(demo), "旧会话授予应已被 purge");
        assert!(b.effective(pid(8), 0, old_sid, 5) & CAP_SECURE_IPC == 0);
        assert!(b.effective(pid(8), 0, 0, 5) & CAP_SPAWN_SVC != 0);
        assert!(b.revoke(unbound), "未绑定授予不受换会话影响");
        // 会话表只剩新会话
        assert_eq!(b.sessions_snapshot(), vec![(new_sid, pid(7))]);
    }

    #[test]
    fn process_gone_clears_grants_and_dissolves_leaded_session() {
        let mut b = book();
        let login = b.issue(pid(7), CAP_SESSION, 0, 0, 0).unwrap();
        let sid = b.begin_session(pid(7), login, 1).unwrap().0;
        // 成员进程的会话绑定授予（领袖死后应随会话注销失效）
        let member_grant = b.issue(pid(8), CAP_SECURE_IPC, 0, sid, 1).unwrap();

        // 普通进程消亡：只清自己的授予，会话不受波及
        let plain = b.issue(pid(9), CAP_SECURE_IPC, 0, 0, 0).unwrap();
        assert_eq!(b.on_process_gone(pid(9)), None);
        assert!(!b.revoke(plain), "死者的授予应随消亡清除");
        assert!(b.revoke(member_grant), "会话仍在时成员授予应存活");

        // 领袖消亡：会话注销并提示清场
        assert_eq!(b.on_process_gone(pid(7)), Some(sid));
        assert!(b.sessions_snapshot().is_empty());
    }

    #[test]
    fn expired_login_token_cannot_establish_session() {
        let mut b = book();
        let token = b.issue(pid(7), CAP_SESSION, 5, 0, 0).unwrap();
        assert_eq!(
            b.begin_session(pid(7), token, 6),
            Err(SessionError::Expired)
        );
        // 过期令牌不被消费（仍可被 revoke 观测到）——但已无意义，
        // sweep 后消失即可。
        b.sweep(7);
        assert_eq!(b.grant_count(), 0);
    }

    #[test]
    fn tokens_are_monotonic_and_nonzero() {
        let mut b = book();
        let t1 = b.issue(pid(1), CAP_SECURE_IPC, 0, 0, 0).unwrap();
        let t2 = b.issue(pid(2), CAP_SECURE_IPC, 0, 0, 0).unwrap();
        assert_ne!(t1, 0);
        assert_ne!(t2, 0);
        assert_ne!(t1, t2);
        let t3 = b.issue(pid(3), CAP_SECURE_IPC, 0, 0, 0).unwrap();
        assert!(t3 > t2 && t2 > t1, "token 单调递增便于审计排序");
    }

    #[test]
    fn sessions_snapshot_lists_all_live_sessions() {
        let mut b = book();
        let t1 = b.issue(pid(1), CAP_SESSION, 0, 0, 0).unwrap();
        b.begin_session(pid(1), t1, 0).unwrap();
        let t2 = b.issue(pid(2), CAP_SESSION, 0, 0, 0).unwrap();
        b.begin_session(pid(2), t2, 0).unwrap();
        let snap = b.sessions_snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[1], (2, pid(2)));
    }
}
