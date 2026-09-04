# 微信新消息 Balloon Tip / 防撤回 — Handoff

最后更新：2026-09-04（正文布局修复并完成实机验证后）

面向使用者的功能和启动说明见 [`README.md`](README.md)；本文件面向继续调试和维护的开发者。

## 0. 当前结论

本轮目标已经完成：在微信 Windows **4.1.9.57 x64** 中，收到新消息时可以从真实的通知对象提取发送者和正文，并显示 Balloon Tip；原有防撤回路径仍然可用。

当前不要再把时间花在重新寻找 `RBX` 或“最长字符串”上。用户提供的对象 dump 已经确定：Flash 调用者现场的 `RDI` 才是当前事件对象，正文固定字段为 `RDI+0x48`（首选）和 `RDI+0x2D0`（另一份表示），`RDI+0x68` 是无关的上一段对话。

文档之外本轮没有待合并的代码改动。继续工作应从“多消息类型回归测试和诊断开关收尾”开始，而不是重做已经验证的捕获逻辑。

## 1. 目标与验收范围

目标是同时保持两条能力：

1. 防撤回：跳过删除调用、保留原文，并按 `tip_phrase` 写入撤回提示。
2. 新消息通知：用微信真实的发送者和正文显示 Windows Balloon Tip。

已验证的通知结果：

- 文本消息能显示真实正文和对方昵称。
- 图片、动画表情等非文本消息能显示类型占位符（例如 `[图片]`、`[动画表情]`）。
- 多次 `FlashWindowEx` 调用不会导致每次都创建气泡；当前实现有约 3 秒全局节流。
- 防撤回产生的内部 Add2DB 不会被误报成新消息，使用 `suppress_next_notify` 抑制。
- `Shell_NotifyIconW`、`FlashWindowEx` 的 IAT/delay-IAT 替换均保留原函数调用，不改变微信原行为。

## 2. 本轮具体完成的代码修改

### 2.1 `native/RevokeHook/RevokeHook/dllmain.cpp`

- 给每线程 `ThreadState` 增加 Flash caller 现场、Add2DB 暂存候选和诊断 dump 去重状态。
- 从第一次 `FlashWindowEx` 返回地址反推出调用点：支持当前版本的 `FF 15` delay-IAT call，也兼容 `E8` direct call。
- 通过 PE `.pdata` 找到包含函数，再扫描 `Weixin.dll .text` 中调用该 helper 的 call site，并动态安装 VEH 断点。
- 在 caller 断点保存 `RCX/RDX/R8/R9/RAX/RBX/RSI/RDI/R14/R15/RSP`；Flash 事件到达时只接受约 1.5 秒内的同线程现场。
- 增加 `ReadFlashWindowInfoSafe()`，把 `FLASHWINFO` 的 SEH 读取拆开，避免 MSVC C2712。
- `ObserveFlashWindowEx()` 只把带 `FLASHW_TRAY` 的调用当作新消息时序锚点。
- `CaptureNotifyMessage()` 增加 4.1.9.57 的直接字段读取：`+0x48`、`+0x2D0`、`+0x1A0`，并固定排除 `+0x68`；发送者读取 `+0x160` 昵称，`+0x000` wxid 回退。
- 当 `+0x48` 与 `+0x2D0` 不一致时输出差异日志并选择 `+0x48`。
- Flash caller 的候选优先于可能来自其他线程或上一条消息的 Add2DB 候选，解决正文串线问题。
- Add2DB 路径统一调用 `CaptureNotifyMessage()`，保留原有扫描和消息类型占位符作为回退。
- 解析 Add2DB 调用点的 `E8 rel32` 目标后再安装目标入口断点，修复旧日志中的 `Unexpected call opcode ...: CC`。
- 将目标入口的辅助字符串日志改为 `NotifyTarget.R9(auxiliary-wxid)`，避免误导后续分析。
- 增加 `notify_new_message`、`notify_dump_all`、`notify_probe_text` 配置读取，以及寄存器/栈/嵌套对象/特殊文本探针转储。

### 2.2 `native/RevokeHook/RevokeHook/inline_hook.cpp`

- 实现 `Shell_NotifyIconW`、`FlashWindowEx`、`FlashWindow` 的普通 IAT 与 delay-IAT 替换。
- `HookedFlashWindowEx()` 保存 `_ReturnAddress()`，调用 `ObserveFlashWindowEx()` 后再调用原函数。
- `ShowNotification()` 做约 3 秒节流并创建后台线程。
- `NotificationThread()` 创建隐藏窗口，加载 DLL 同目录的 `IcoE.ico`，依次执行：
  `NIM_ADD → NIM_SETVERSION(NOTIFYICON_VERSION_4) → NIM_MODIFY(NIF_INFO)`，等待约 6 秒后 `NIM_DELETE`。
- 导出 `SendWindowsNotification(const char*, const char*)`，供 `dllmain.cpp` 传入 UTF-8 标题和正文。

### 2.3 工程、构建和配置

- `RevokeHook.vcxproj` 已将 `inline_hook.cpp` 纳入 Release|x64 构建。
- `build.bat` 复制 `IcoE.ico` 到 `dist/`，并对每个复制步骤检查失败状态。
- `config.yml` 增加：

```yaml
notify_new_message: true
notify_dump_all: true
notify_probe_text: "__WA_NOTIFY_PROBE_7F3A__"
```

- 当前 `dist/RevokeHook.dll` 已成功构建、发布并注入；本轮只改文档，不需要为了文档再次编译。

## 3. 用户 dump 得出的最终字段结论

用户在同一对话中提供的 dump（相对 `NotifyDump.RDI`）为：

| 偏移 | 实际含义 | 处理方式 |
| --- | --- | --- |
| `+0x000` | 对方唯一用户名（wxid） | 昵称缺失时作为标题回退。 |
| `+0x048` | 当前消息正文 | **首选正文**。 |
| `+0x068` | 另一次/上一段对话正文 | **必须排除**，不能交给通知。 |
| `+0x140` | 对方头像 URL | 仅诊断记录，当前不显示。 |
| `+0x160` | 对方昵称 | **首选标题**。 |
| `+0x290` | wxid + 时间戳元数据 | 不是正文。 |
| `+0x2D0` | 当前正文的另一份表示 | `+0x48` 不可读时回退。 |
| `+0x1A0` | 旧路径/兼容正文候选 | Flash 固定字段都不可读时最后回退。 |

两个一模一样的 `test123456` 对象 dump 出现在 `RDI+0x048` 和 `RDI+0x2D0`，不是重复正文，而是同一条消息在对象中的两份表示。这个结论解释了此前“拿到的 content 和真实不一致”：旧逻辑扫描到了 `RBX` 或 `+0x68` 的旧数据。

### Add2DB 现场的注意事项

当前 Config3 搜到的 `Add2DBOffset` 是 wrapper 里的直接 `call`（本次日志为 `0x34A68DB`），不是固定目标函数入口。现场关系如下：

| 现场 | 消息对象 | 另一参数 |
| --- | --- | --- |
| wrapper 调用点 | 原始 `R9`（第 4 个参数） | 原始 `R8`（第 3 个参数，作为候选传递） |
| 目标入口 | `R8` | `R9` 在实际日志中是辅助 wxid，标签为 `NotifyTarget.R9(auxiliary-wxid)`，不能当正文 |
| Flash caller | `RDI` | 正文从上表固定字段读取 |

`dllmain.cpp` 中仍有一处历史注释把目标入口 `R9` 简写为“正文参数”；运行逻辑和日志标签已经按实测处理，后续若整理注释只改说明，不要据旧注释改回读取策略。

## 4. 实际验证证据

当前 `dist/RevokeHook.log` 已记录以下成功序列（地址每次启动可能变化）：

```text
[RevokeHook] Use config: ... DelMsg=0x227B4BE Add2DB=0x34A68DB
[Add2DB] Target entry breakpoint ... (call site ...68DB)
[RevokeHook] AddBp ...68DB OK
[Hook] Shell_NotifyIconW IAT hooked in ...
[Hook] FlashWindowEx IAT hooked in ...
[FlashProbe] caller breakpoint ... -> helper ...
[FlashProbe] discovered 1 caller breakpoint(s)
[FlashProbe] direct fields +0x48=1 +0x2D0=1 +0x1A0 content=[贼高啊]
[FlashProbe] direct sender nickname=[颜旭] wxid=[wxid_wtipu220it0g11] selected=[颜旭]
[FlashProbe] caller candidate captured=1 from=[颜旭] content=[贼高啊]
[FlashProbe] sending notification from=[颜旭] content=[贼高啊]
[Toast] NIM_ADD success
[Toast] Balloon tip displayed
```

此前也验证过 `test123`、普通文本、图片和动画表情。当前日志中 `Unexpected call opcode` 为 0；出现 `CC` 时应先怀疑旧 DLL/旧微信进程，而不是马上改偏移。

## 5. 当前运行状态和配置

- 本次验证的目标微信主进程 PID 为 **34176**（微信是多进程，重启后 PID 会变化；以启动器检测到的托盘窗口所属 PID 为准）。
- 启动器在注入完成后已退出，DLL 留在微信进程内。
- `dist/RevokeHook.dll`、`dist/IcoE.ico`、`dist/config.yml` 均已发布。
- 当前配置（仓库根目录和 `dist/` 的副本）为：

```yaml
notify_new_message: true
notify_dump_all: true
notify_probe_text: "__WA_NOTIFY_PROBE_7F3A__"
debug: true
```

- `notify_dump_all` 会产生大量日志，且只读微信对象；它不是正式性能优化后的默认模式。
- Config3 云端地址依次为 `https://raw.githubusercontent.com/EEEEhex/RevokeHook/main/Config3.json` 和 `http://47.109.182.110:8123/api/get_config3`；`REVOKEHOOK_CONFIG3_URL` 会优先尝试指定地址，失败后仍可回退随包副本。

## 6. 接下来要做什么（按优先级）

以下是下一位维护者应直接执行的清单。每项都写了验证重点，完成后在本文件追加日期和结果。

### P0 — 完成文本与节流回归

1. **中文正文确认**

   - 保持 `notify_probe_text` 不变，发送一条包含中文、标点和 emoji 的唯一文本，例如 `中文探针-星河-20260904-🙂`。
   - 在 `dist/RevokeHook.log` 搜索 `[FlashProbe] direct fields`、`direct sender`、`sending notification`。
   - 验收：气泡正文与聊天窗口逐字一致；`+0x48` 和 `+0x2D0` 至少一个可读；无 UTF-8 截断乱码。
   - 若要确认探针路径，再发送精确的 `__WA_NOTIFY_PROBE_7F3A__`，记录 `[NotifyProbe] marker=` 的 `object_offset`，不要据 `RBX` 段落下结论。

2. **重复消息与 3 秒去重**

   - 快速发送两条完全相同正文，再等待超过 3 秒发送第三条。
   - 对比 `[FlashProbe] sending notification`、`[Toast] Notification thread created` 和 `[Toast] Balloon tip displayed` 的数量。
   - 预期：短时间内至少有一次被 3 秒全局节流；超过 3 秒的新事件可以再次显示。
   - 记录微信多次 `FlashWindowEx` 调用是否造成额外气泡。当前实现是时间节流，不是按消息 ID 的去重，不能把它误写成强一致的消息去重。

### P1 — 扩展消息类型和窗口状态

3. **消息类型矩阵**

   分别测试单聊和群聊中的：

   - 图片、动画表情、文件；
   - 语音、视频、链接/小程序；
   - 普通短文本、长文本、包含换行和 emoji 的文本。

   每次记录 `msgType`、`selected` 标题、`content` 以及是否走 Flash caller 或 pending Add2DB 回退。验收重点是：群聊标题是否为实际发言人昵称，非文本是否只显示合理占位符，不能误选 `<msgsource>` 或头像 URL。

4. **前台/后台行为**

   - 微信窗口前台时发送消息一次，最小化/切换到其他窗口后再发送一次。
   - 记录 `FlashWindowEx flags`；只有包含 `FLASHW_TRAY` 的事件才会触发当前通知路径，这是设计条件。
   - 若产品需求是“前台也必须通知”，需要先确认期望，再单独设计触发策略；不要直接删掉 `FLASHW_TRAY` 过滤，以免把其他窗口动画当成新消息。

5. **防撤回回归**

   - 收到普通文本后让对方撤回；测试自己撤回（根据 `anti_revoke_self` 当前值）；测试图片/长文本撤回。
   - 验收：原文仍保留，撤回提示模板正常，`Add2DB` 的提示不产生额外新消息气泡，不出现两条撤回提示。
   - 重点查看 `[Add2DB] Suppress target entry for anti-recall path`，确认 `suppress_next_notify` 只抑制对应的一次内部调用，不会吞掉下一条真实消息。

### P2 — 关闭诊断并准备可交付配置

6. **验证完后关闭全量 dump**

   将仓库根目录 `config.yml` 改为：

```yaml
notify_dump_all: false
notify_probe_text: ""
```

   保留 `debug: true` 做最后一轮回归；确认无误后再决定是否关闭 `debug`。运行 `build.bat` 让配置同步到 `dist/`，不要只改其中一份。

7. **清理发布目录前的检查**

   - 关闭微信并确认旧 DLL 已卸载，再构建/复制。
   - 启动新注入器，确认初始化日志、一次文本通知和一次撤回流程都成功。
   - 不要提交或覆盖用户已有的诊断 dump、对象日志或未跟踪工具文件；只按需求处理文档/源文件。

### P2 — 微信升级后的兼容性流程

微信升级后按以下顺序重新确认：

1. `Config3.json` 是否有精确版本；若没有，记录 `Config3Service` 选中的邻近版本。
2. `DelMsgOffset`、`Add2DBOffset` 是否能搜索出来，且 Add2DB 调用点首字节仍是 `E8`。
3. 目标入口断点是否成功，日志不应出现 `Unexpected call opcode ... CC`。
4. `FlashWindowEx` 是否仍为实际触发点，caller discovery 是否发现有效 call site。
5. 在 caller dump 中重新确认 `RDI`、`+0x48/+0x2D0`、昵称和 wxid；若布局变化，先记录新 dump，再最小化修改 `CaptureNotifyMessage()`。
6. 完成文本、群聊、媒体和撤回回归后，才更新 README/HANDOFF 的版本结论。

## 7. 重新构建和注入

文档修改不需要构建；代码或配置修改后使用：

```text
退出微信（必要时结束全部 Weixin.exe）
build.bat
dist/WeChatAntiRecall.exe
```

`build.bat` 的完整步骤是：

- `msbuild native/RevokeHook/RevokeHook.sln /m /p:Configuration=Release /p:Platform=x64`
- 编译 `native/update_stub.c`
- `dotnet publish` .NET 8 启动器为 self-contained win-x64 single-file
- 复制 DLL、stub、配置、Config3 和图标到 `dist/`

如果需要分开构建，原生 DLL 的工程是 `native/RevokeHook/RevokeHook.sln`，不是根目录的 C# 解决方案。启动器从 `AppContext.BaseDirectory` 找 DLL 和配置，IDE 直接运行时必须保证这两个文件就在输出目录。

## 8. 关键阅读入口

| 任务 | 文件 | 入口 |
| --- | --- | --- |
| 启动、搜索、注入总流程 | `src/WeChatAntiRecall/MainWindow.xaml.cs` | `RunAsync()` |
| 偏移搜索 | `src/WeChatAntiRecall/OffsetSearch.cs`、`Services/CallChainSearchService.cs` | `OffsetSearch.Run()`、`Search()` |
| 共享内存和远程注入 | `src/WeChatAntiRecall/Injector.cs` | `Inject()` |
| DLL 初始化 | `native/RevokeHook/RevokeHook/dllmain.cpp` | `DllMain()`、`ReadExternalConfig()` |
| 断点分派 | 同上 | `OnTargetHit()` |
| Flash 事件关联 | 同上 | `EnsureFlashCallerBreakpoints()`、`ObserveFlashWindowEx()` |
| 正文/标题提取 | 同上 | `CaptureNotifyMessage()` |
| API hook 与气泡 | `native/RevokeHook/RevokeHook/inline_hook.cpp` | `InitNotifyIatHook()`、`HookedFlashWindowEx()`、`ShowNotification()` |
| 断点基础设施 | `native/RevokeHook/RevokeHook/vehbp.cpp` | `VehBp_Init/Set/Uninit()` |
| 撤回模板与类型占位符 | `native/RevokeHook/RevokeHook/revoke_tip.h` | `render()`、`messageKindPlaceholder()` |

推荐调试顺序：先看初始化和 RVA → 再看 Add2DB target breakpoint → 再看 caller discovery → 再看 `RDI` 直接字段 → 最后看 Toast。不要先用全进程字符串扫描猜正文。

## 9. 已知陷阱与明确不要做的事

- **不要调用 `InitInlineHooks()`。** 它会给 `user32.dll` 导出入口直接写 5 字节 `E9`，历史上会导致微信崩溃；正式路径只用 IAT/delay-IAT + VEH。
- **不要用 `RBX` 作为 Flash 消息对象。** 它可能指向内部缓存、加密串、配置或旧对话。
- **不要读取 `RDI+0x68` 作为正文。** 用户 dump 已证明它属于无关上一段对话。
- **不要把 `NotifyTarget.R9` 当正文。** 当前版本它是辅助 wxid；正文必须从 Flash caller 的 `RDI` 固定字段取得。
- **不要把绝对地址写入 Config3 或 YAML。** 地址受 ASLR 影响，Config3 提供的是特征码，启动器传的是 RVA。
- **不要为了验证而修改微信磁盘上的 `Weixin.dll`。** 当前方案只读文件搜索、运行时注入和进程内断点。
- **不要把诊断 dump 当成最终消息解析器。** 新消息类型应先通过探针和字段对照确认，再做最小代码调整。

## 10. 交付前完成标准

只有满足以下条件，才可以把目标标记为“稳定交付”：

- 文本（含中文/emoji）、重复消息、群聊和至少三种媒体类型回归通过。
- 前台/后台行为符合明确的产品预期。
- 收到和撤回流程互不干扰，撤回提示不重复。
- 最新日志无 `Unexpected call opcode`、无异常退出，且 `Balloon tip displayed` 与预期事件数相符。
- `notify_dump_all=false`、`notify_probe_text=""` 已同步到 `dist/config.yml`。
- README 的支持版本和本文件的验证日期已更新。
