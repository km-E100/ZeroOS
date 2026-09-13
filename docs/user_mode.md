# 用户态/内核态切换概览

本节记录 Zero OS 当前的用户态进程运行流程，并说明如何扩展自定义用户任务。

## 核心要点

- **TrapFrame**：`microkernel/src/process.rs` 中的 `TrapFrame` 保存 x0–x30、`SP_EL0`、`ELR_EL1`、`SPSR_EL1`、`SP_EL1`。异常入口 (`trap_entry`) 在进入内核时将寄存器写入该结构；`restore_context` 在返回用户态前按相同布局恢复。
- **异常入口**：`microkernel/src/arch/aarch64.rs` 的 `__vector_sync_el0_64`、`__vector_irq_el0_64` 将控制权转交给 `trap_entry`，后者保存现场并调用 `__zero_trap_handler`。
- **系统调用约定**：
  - `svc #0`：通用系统调用，x0 为编号，x1–x4 为参数。当前实现支持 `SendMessage`(0)、`ReceiveMessage`(1)。
  - `svc #1`：yield，调用调度器将当前线程重新入队。
  - `svc #2`：exit，标记当前线程终止并调度下一任务。
- **地址空间**：`microkernel/src/mm/address_space.rs` 封装用户页表；每个用户线程 spawn 时分配独立页表副本，调度器会在切换时写入/清空 `TTBR0_EL1`。
- **示例任务**：`microkernel/src/user_demo.rs` 提供内置用户线程，每次循环触发 `svc #1`，执行 5 次后通过 `svc #2` 退出。

## 自定义用户任务

要运行自定义用户程序，可参考 `user_demo::user_entry`：

```rust
#[inline(always)]
unsafe fn svc_call(code: u16, args: [u64; 4]) -> u64 {
    let mut ret;
    core::arch::asm!(
        "mov x0, {code}\n mov x1, {a0}\n mov x2, {a1}\n \
         mov x3, {a2}\n mov x4, {a3}\n svc #0\n mov {ret}, x0",
        code = in(reg) code as u64,
        a0 = in(reg) args[0],
        a1 = in(reg) args[1],
        a2 = in(reg) args[2],
        a3 = in(reg) args[3],
        ret = out(reg) ret,
        options(nostack)
    );
    ret
}
```

- 将用户入口函数声明为 `pub extern "C" fn(...) -> !`，并在 `kernel_main` 中通过 `process::spawn_user` 注册。
- 若需要独立编译的用户进程，可按照相同 ABI 构建 `staticlib`，再于 `zero-kernel` 链接阶段引入。

## 调试建议

1. 通过 `info!` 或串口输出确认 trap 触发顺序（例如增加日志：进入/返回用户态）。
2. 若发生未定义异常，串口日志会打印 `ESR_EL1/FAR_EL1`，根据异常码定位问题。
3. 推荐在 QEMU 下运行，配合 `-d cpu,unimp` 或 GDB 观察 `ELR_EL1/SPSR_EL1`，确保返回地址、特权级设置正确。

完成后，可使用 `cargo run -p xtask -- build-image` 生成 `target/zero-os.elf`，并在 QEMU 中观察用户任务依次 yield、退出，验证用户态 ↔ 内核态 切换链路。 
