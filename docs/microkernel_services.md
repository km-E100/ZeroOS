# 微内核与用户态服务器交互

Zero OS 采用微内核架构，关键服务（IPC、文件系统、用户会话、安全）在用户态运行。`BootInfo` 将服务器入口地址传递给微内核，微内核启动流程如下：

1. `boot::init_arch` 完成 CPU、MMU 设置后调用 `services::launch_core`。
2. `launch_core` 根据 `BootInfo` 创建 `ServiceDescriptor`，通过 `process::spawn` 为每个服务器建立初始线程。
3. `scheduler::enqueue` 将进程加入运行队列，调度器循环调度。
4. IPC 通过微内核 `ipc` 模块的信箱队列实现，服务器之间使用消息传递共享数据。

服务器类型简介：
- **ipc-router**：为其他服务器提供名称与通道映射。
- **zfs-fs**：Zero File System 文件服务器，处理文件操作、`.app` 安装。
- **launchd**：守护进程管理器，加载系统服务与用户会话。
- **securityd**：权限、签名验证、密钥管理。

后续增加的服务可使用 `services::register_service` 注册自定义入口，微内核会按需启动并监控其生命周期。
