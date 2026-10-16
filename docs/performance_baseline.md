# 性能基线（第十四刀立项）

> 采集入口：`scripts/perf-baseline.sh`（输出建议入库 `docs/perf-history/`）。
> 原则：粗粒度、可复现、零插桩——先有趋势线，再做微基准。

## 指标定义

| 指标 | 采集方式 | 健康判据 |
| --- | --- | --- |
| 主机测试总数/耗时 | `cargo test -p …` 的 `test result` 与 `real` | 总数只增不减；耗时无跳变 |
| build-iso 全链耗时 | `/usr/bin/time -p cargo run -p xtask -- build-iso` | 无恶化趋势；磁盘闸触发=失败 |
| 上电→shell 提示符 | test-boot 串口日志行差粗估 | 稳定在个位数秒 |

## 首次基线（2026-08-24 · 第十四刀当日）

- 主机测试：微内核 141 + abi 17（含模糊属性测试）+ fsd 5 + userlib/securityd 等，
  全绿；微内核套件耗时 ~0.08s。
- 实机验收（scripts/acceptance.sh）：注入段约 60s，13 项判定
  （shell-up / 三服务在线 / login / secdemo / su / sessions / sleepdemo /
  forktest / blktest / fstest / fsdemo）。
- 构建磁盘闸：3072MB（xtask SIZE_LIMIT_MB），purge 自救路径验证可用。

## 已知性能语义（第十一刀落地时锁定）

- MLFQ：4 级，时间片 4/8/16/32 tick，200 tick 全局优先级提升。
- Sleep(ticks)：定时器轮，唤醒侧陷阱帧回写 elapsed（零额外切换）。
- FPU 惰性保存：非 FP 用户每次 trap 省 ~528B 存取（32×stp+2×mrs）；
  FP 用户跨切换付一次 EC=0x07 断链陷阱。
- COW fork（第十刀）：fork 复制页数 copied=0（实机证据，见 STATUS）。
