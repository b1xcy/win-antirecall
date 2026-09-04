# win-antirecall

Windows 微信防撤回与新消息气泡通知。项目由一个一次性运行的 C# 启动器和一个注入到微信进程中的 C++ DLL 组成：启动器负责找到当前版本的偏移、等待登录并注入；DLL 负责防撤回、消息内容读取和通知显示。

> 当前实机验证基线：微信 Windows **4.1.9.57 x64**（`Weixin.exe` / `Weixin.dll`）。微信内部对象布局和代码偏移不是稳定 ABI，其他版本必须重新验证，不能把本文的偏移直接套用到未知版本。

维护者接续当前进度请先阅读 [`HANDOFF.md`](HANDOFF.md)，其中记录了实机证据、已知陷阱和下一步验收清单。

## 已实现的功能

### 防撤回

- 在 `DeleteMessages` 调用点使用 VEH + `INT3` 断点跳过真正的删除调用，打开的会话中原消息仍然保留。
- 从撤回 XML 提取发送者、时间和原文，按 `tip_phrase` 渲染自定义撤回提示。
- 在 `Add2DB` 的撤回关联路径中生成新的 `srvid`，写入提示并避免同一撤回事件插入两次。
- 群聊会过滤 `<msgsource>` 等元数据，优先选择相邻正文；图片、语音、视频等非文本消息使用类型占位符（例如 `[图片]`）。
- `anti_revoke_self` 控制是否连自己的撤回也拦截；`block_update` 可结束并替换 `WeixinUpdate.exe`，DLL 注入后还会每 2 秒检查一次更新进程。

### 新消息 Windows Balloon Tip

设置 `notify_new_message: true` 后，收到消息时用 `IcoE.ico` 显示右下角气泡：

- 标题优先使用对方昵称，缺少昵称时回退到 wxid。
- 正文使用真实消息内容；图片、动画表情、文件等使用类型预览。
- 采用 `Shell_NotifyIconW` 的 `NIM_ADD → NIM_SETVERSION → NIM_MODIFY` 流程，通知在线程中创建隐藏窗口，不阻塞微信消息线程。
- 对同一时间窗口内的重复触发做约 3 秒节流；微信一次消息可能多次调用闪烁 API。
- Hook wrapper 始终调用系统原函数，不修改 `FlashWindowEx` 的参数、返回值或微信原有通知行为。`FlashWindowEx` 只被用作“新消息事件已经到达”的时序锚点。

当前版本中普通收消息时没有稳定命中 `Shell_NotifyIconW`，真正可靠的触发点是带 `FLASHW_TRAY` 标志的 `FlashWindowEx`。因此不要把“安装了 Shell hook”误认为“Shell hook 是主路径”。

## 快速开始

### 环境要求

- Windows x64。
- 已安装微信 4.x；本文验证的是 4.1.9.57 x64。
- 构建需要 Visual Studio 2022 Build Tools（含 C++ x64 工具链，脚本默认调用 `vcvars64.bat`）和 .NET 8 SDK。
- 注入需要对目标微信进程有足够权限；若微信安装在受保护目录，禁用更新器可能需要管理员权限。

### 构建发布包

在仓库根目录运行：

```bat
build.bat
```

脚本依次完成：

1. 构建 `native\RevokeHook\RevokeHook.sln` 的 `Release|x64` DLL。
2. 编译空实现更新器 `native\update_stub.c`。
3. 将 .NET 8 WPF 启动器发布为 self-contained、win-x64、single-file 程序。
4. 把 DLL、更新器、`config.yml`、`Config3.json` 和 `IcoE.ico` 复制到 `dist\`。

如果 DLL 仍被微信加载，先退出持有它的微信进程，再重新构建和复制；不能在旧 DLL 尚未卸载时依赖覆盖结果。

### 运行

1. 编辑仓库根目录的 `config.yml`（构建时会复制到 `dist\config.yml`）。
2. 双击或运行 `dist\WeChatAntiRecall.exe`。
3. 启动器会在需要时启动微信；在微信窗口中完成登录。
4. 检测到微信托盘窗口后，启动器自动计算偏移、写入运行时共享内存并注入 `dist\RevokeHook.dll`。
5. 注入完成后启动器退出，DLL 留在微信进程中继续工作。

启动器不会把偏移写回 YAML。每次启动都会针对磁盘上的 `Weixin.dll` 重新搜索，并在注入前把本次结果传给 DLL。

## 配置

`config.yml` 是简单的 `key: value` 文件，不是完整 YAML 解析器；值中若包含复杂 YAML 语法不要依赖它的行为。

| 键 | 默认/当前值 | 作用 |
| --- | --- | --- |
| `tip_phrase` | `已拦截 {from} 于 {time} 撤回：{content}` | 撤回提示模板；支持 `{from}`、`{time}`、`{content}`。 |
| `anti_revoke_self` | `true`（当前配置） | 是否拦截自己撤回的消息。 |
| `block_update` | `true`（当前配置） | 结束更新进程并尝试替换 `WeixinUpdate.exe`。 |
| `notify` | `false` | 注入完成后由启动器显示一次提示；与新消息通知无关。 |
| `debug` | `true` | 开启 DLL 调试日志，同时保留启动器界面日志。 |
| `notify_new_message` | `true`（当前配置） | 开启新消息 Balloon Tip。此项主要由 DLL 读取。 |
| `notify_dump_all` | `true`（当前诊断配置） | 转储消息对象中的寄存器、栈和可识别 `std::string` 字段；只读内存。 |
| `notify_probe_text` | `__WA_NOTIFY_PROBE_7F3A__` | 用于偏移定位的精确文本标记；设为空字符串可关闭匹配。 |

日常使用可先保留：

```yaml
notify_new_message: true
debug: true
notify_dump_all: false
notify_probe_text: ""
```

当前为了继续验证不同消息类型，仓库里的诊断开关仍为 `true`。完成后续验证后应关闭转储和探针，减少日志量。

### Config3 来源和版本选择

启动器每次搜索前会优先尝试以下地址（也可用 `REVOKEHOOK_CONFIG3_URL` 指定一个优先地址）：

- `https://raw.githubusercontent.com/EEEEhex/RevokeHook/main/Config3.json`
- `http://47.109.182.110:8123/api/get_config3`

下载内容会先校验为非空的版本字典，再替换本地副本。网络不可用时使用随包的 `src\WeChatAntiRecall\Config3.json`/`dist\Config3.json`。版本匹配先尝试规范化后的精确版本；没有精确项时选择不高于当前版本的最高项，再退回最近的更高项。

## 工作原理

整体时序如下：

```text
MainWindow.RunAsync
  -> 找到 Weixin.dll / 拉取 Config3.json
  -> 搜索 DelMsg、Add2DB RVA
  -> 等待登录托盘
  -> 共享内存传递 RVA
  -> LoadLibraryW 远程注入 RevokeHook.dll
  -> DLL 安装 VEH 断点和 IAT/delay-IAT hook
  -> DelMsg 防撤回；FlashWindowEx 触发新消息捕获
```

### 1. C# 启动器

入口是 `src\WeChatAntiRecall\MainWindow.xaml.cs` 的 `RunAsync()`，顺序固定为：

1. `AppConfig.Load()` 读取启动器目录旁的 `config.yml`。
2. `OffsetSearch.Run()` 通过注册表 `HKCU\Software\Tencent\Weixin\InstallPath` 找到当前版本的 `Weixin.dll`。
3. `CloudConfigService` 优先下载最新 `Config3.json`；网络失败时使用随包副本。可用环境变量 `REVOKEHOOK_CONFIG3_URL` 指定额外地址。
4. `CallChainSearchService` 在 PE 的 `.rdata` 搜索三个加密字符串，在 `.text` 查找 RIP-relative `lea`，结合 `.pdata` 函数边界和最多三层 `call` 链确定两个 RVA。
5. `TrayWait` 等待类名/标题包含 `WxTrayIconMessageWindow` 的托盘窗口，并由窗口所属进程取得真正的微信 PID。未登录直接关闭微信时，启动器会一起退出。
6. `Injector.Inject()` 将 `WHR1` magic、`DelMsgOffset`、`Add2DBOffset` 写入 `Local\WeChatAntiRecall.Runtime.v1` 文件映射，再用 `SeDebugPrivilege`、`VirtualAllocEx`、`WriteProcessMemory` 和 `CreateRemoteThread(LoadLibraryW)` 注入 DLL。

偏移搜索不是把地址硬编码到配置文件：Config3 只提供版本特征，运行时根据实际映像重新算出 RVA。`Weixin.dll` 基址每次启动也可能不同。

### 2. DLL 初始化与 VEH

`native\RevokeHook\RevokeHook\dllmain.cpp` 的 `DllMain(PROCESS_ATTACH)`：

- 从 DLL 自身目录读取 `config.yml`，从共享内存读取本次 RVA。
- 等待 `Weixin.dll` 加载，计算 `imgbase + RVA`。
- 初始化 `vehbp.cpp` 的 VEH 软断点系统，并在 `DelMsg`、`Add2DB` 调用点安装 `INT3`。
- 先解析 `Add2DB` 调用点的 `E8 rel32` 目标，再安装目标入口断点；这样不会把尚未解析的 `0xCC` 断点字节当成调用指令。
- `block_update` 开启时启动每 2 秒结束 `WeixinUpdate.exe` 的线程。

VEH 命中断点后会恢复原字节、执行回调、设置单步标志，下一次单步异常再写回 `0xCC`。每线程状态保存在 TLS 中，避免把不同消息线程的候选内容混在一起。

### 3. 防撤回路径

`OnTargetHit()` 的 `DelMsg` 分支会在候选对象的 MSVC `std::string` 中识别撤回 XML，读取原文并渲染 `revoke_tip.h` 中的模板。必要时先扩容字符串、压缩 XML，再把通知参数改为允许显示；随后将 `RIP` 跳过当前 5 字节 `call` 并把 `RAX` 设为成功值，相当于阻止删除调用。

`Add2DB` 只有在同线程刚刚处理过撤回消息时才进入原有的数据库提示替换逻辑。普通新消息的 Add2DB 命中只用于候选捕获，不会被当成撤回消息改写。撤回路径设置了 `suppress_next_notify`，所以写入撤回提示的那次内部 Add2DB 不会再产生新消息 Balloon Tip。

### 4. 通知 API hook

活动实现位于 `native\RevokeHook\RevokeHook\inline_hook.cpp` 的 `InitNotifyIatHook()`：

- 对主模块和 `Weixin.dll` 的普通 IAT、delay-IAT 都尝试替换 `SHELL32!Shell_NotifyIconW`、`USER32!FlashWindowEx`、`USER32!FlashWindow`。
- `HookedShellNotifyIconW` 能读取微信自己构造的 `NOTIFYICONDATAW`，但在 4.1.9.57 普通收消息时没有稳定命中。
- `HookedFlashWindowEx` 记录返回地址，调用 `ObserveFlashWindowEx()` 后原样调用 `USER32` 原函数。

第一次收到闪烁调用时，`ObserveFlashWindowEx()` 根据返回地址识别 `FF 15` delay-IAT 或 `E8` call，找到包含函数，再扫描 `.text` 中调用同一辅助函数的 call site 并安装临时 VEH 断点。调用者断点把寄存器现场保存到 TLS；下一次带 `FLASHW_TRAY` 的 `FlashWindowEx` 到达时，读取新鲜现场（约 1.5 秒内）完成消息关联。

### 5. 已确认的消息对象布局（微信 4.1.9.57 x64）

调用者现场的 **`RDI` 才是当前 Flash 事件对应的通知消息对象**。早期使用 `RBX` 或“扫描到的最长字符串”会得到旧对话、配置文本或其他对象，导致正文与真实消息不一致。

相对 `RDI` 的字段结论如下：

| 相对偏移 | 含义 | 使用规则 |
| --- | --- | --- |
| `+0x000` | 对方唯一 wxid | 昵称缺失时作为标题回退。 |
| `+0x048` | 当前消息正文 | **首选正文**。 |
| `+0x068` | 另一段/上一段对话正文 | 与当前事件无关，**必须排除**。 |
| `+0x140` | 对方头像 URL | 目前只作诊断字段，不用于标题/正文。 |
| `+0x160` | 对方昵称 | **首选标题**。 |
| `+0x1A0` | 兼容旧路径的正文候选 | `+0x48`、`+0x2D0` 都不可读时回退。 |
| `+0x290` | wxid + 时间戳元数据 | 识别为元数据，不当正文。 |
| `+0x2D0` | 当前正文的另一份表示 | `+0x48` 不可读时使用；两者不一致时记录日志并选 `+0x48`。 |

这些字段都是 MSVC `std::string`，转储中的 `size`/`cap` 是字符串元数据，`storage` 是实际 SSO 或堆存储地址，不是另一个对象偏移。

### 6. Add2DB 参数重排

`Config3` 找到的 `Add2DBOffset`（当前实测 `0x34A68DB`）落在 wrapper 内的直接 `call`，不是稳定的目标函数入口。当前版本现场要按下面方式理解：

| 位置 | 消息对象 | 其他字符串 |
| --- | --- | --- |
| wrapper 断点 | 原始 `R9`（第 4 个参数） | 原始 `R8`（第 3 个参数，作为候选传递） |
| 目标入口断点 | `R8` | `R9` 在实际日志中是辅助 wxid，标签为 `NotifyTarget.R9(auxiliary-wxid)`，**不能当正文** |
| Flash caller | `RDI` | 正文从对象固定字段读取 |

因此通知正文最终以 Flash caller 的 `RDI+0x48` 为准，Add2DB 只作为时序候选和兼容回退。这样也解决了候选来自其他线程或上一条消息时覆盖当前正文的问题。

### 7. Balloon Tip 显示

`SendWindowsNotification(from, content)` 做 UTF-8 → UTF-16 转换，并将正文按 UTF-8 边界截断到约 200 字节。后台线程：

1. 创建隐藏 `STATIC` 窗口。
2. 从 DLL 同目录加载 `IcoE.ico`（缺失时使用系统信息图标）。
3. `NIM_ADD` 创建临时托盘图标。
4. `NIM_SETVERSION` 设置 `NOTIFYICON_VERSION_4`。
5. `NIM_MODIFY` 填入标题、正文和图标，显示 balloon。
6. 等待约 6 秒后 `NIM_DELETE` 并销毁窗口。

## 从哪里入手（维护和调试顺序）

按下面顺序阅读，能最快定位问题：

| 关注点 | 首先打开 | 关键函数/变量 |
| --- | --- | --- |
| 启动失败、找不到微信 | `src\WeChatAntiRecall\MainWindow.xaml.cs`、`TrayWait.cs` | `RunAsync()`、`WaitForLoginPid()` |
| 偏移搜索错误 | `OffsetSearch.cs`、`Services\CallChainSearchService.cs` | `OffsetSearch.Run()`、`Search()`、`TargetCallRva` |
| 注入失败或 DLL 读不到偏移 | `Injector.cs`、`dllmain.cpp` | `Injector.Inject()`、`LoadRuntimeOffsets()` |
| 撤回逻辑回归 | `dllmain.cpp`、`vehbp.cpp`、`revoke_tip.h` | `OnTargetHit()`、`ApplyCustomTip()` |
| 正文/发送者不正确 | `dllmain.cpp` | `ObserveFlashWindowEx()`、`CaptureNotifyMessage()`、`RDI` 字段表 |
| Hook 未命中 | `inline_hook.cpp` | `InitNotifyIatHook()`、`HookedFlashWindowEx()` |
| 气泡不显示 | `inline_hook.cpp` | `ShowNotification()`、`NotificationThread()`、`IcoE.ico` |

实际排查时先看 `RevokeHook.log` 的初始化行，再确认 `FlashProbe` 是否发现 caller，最后比较 `direct fields` 和 `sending notification`；不要一开始就重新搜索全进程字符串。

## 日志与诊断

当 `debug: true` 时，日志写在：

```text
dist\RevokeHook.log
```

日志文件位于启动器/DLL 同目录；DLL 在首次 `PROCESS_ATTACH` 初始化时以覆盖方式打开并写入，后续持续追加本次运行日志。当前方案不再生成 `RevokeHook.ini`，配置只读 `config.yml`。

常见的成功标志：

```text
[RevokeHook] Use config: ... DelMsg=0x... Add2DB=0x...
[Add2DB] Target entry breakpoint ... (call site ...)
[Hook] FlashWindowEx IAT hooked in ...
[FlashProbe] caller breakpoint ... -> helper ...
[FlashProbe] discovered 1 caller breakpoint(s)
[FlashProbe] direct fields +0x48=1 +0x2D0=1 ...
[FlashProbe] direct sender nickname=[...] wxid=[...] selected=[...]
[FlashProbe] sending notification from=[...] content=[...]
[Toast] Balloon tip displayed
```

### 全量转储和特殊文本探针

诊断开关打开时，每个线程对同一消息对象只转储一次：

- `NotifyDump` 行记录寄存器、前 8 个栈参数和对象地址。
- `Dump` 行扫描对象约 `0x500` 字节内的 MSVC `std::string`，打印相对偏移、`storage`、`size/capacity`、分类和值；同时递归一层嵌套对象。
- `notify_probe_text` 匹配到时会额外输出 `[NotifyProbe] marker=... object_offset=+0x...`。
- 探针只扫描当前对象的已提交内存和字符串存储区，不遍历整个进程，也不修改微信对象。

定位新版本字段时，发送与 `notify_probe_text` 完全相同的文本，然后：

1. 在日志搜索 `[NotifyProbe] marker=`。
2. 记录 `NotifyDump.RDI`（或 `FlashCaller`）对应的 `object_offset`。
3. 对照同一段落里的 `+0x000`、`+0x048`、`+0x068`、`+0x160`、`+0x2D0` 等字段，确认哪个是当前消息，而不是旧会话或元数据。
4. 同时保留 `Add2DBTarget` 段落；目标入口的 `R9` 只作为辅助 wxid 参考。

## 常见问题

### 日志出现 `Unexpected call opcode ...: CC`

这表示旧版本逻辑在 `Add2DB` 调用点已经写入 `INT3` 后，才尝试读取原始 `E8`。当前实现已改为“先解析目标、安装目标断点，再安装调用点断点”。若仍看到此行，通常是微信进程里还加载着旧 DLL：退出微信全部进程，重新 `build.bat`，再启动注入器。

### Hook 成功但没有新消息气泡

确认：

- `dist\config.yml` 的 `notify_new_message: true`；
- `debug: true` 且日志出现 `FlashWindowEx IAT hooked`；
- 微信确实产生了带 `FLASHW_TRAY` 的后台通知（前台窗口可能不闪烁）；
- `IcoE.ico` 与 DLL 在同一目录；
- 没有把 `notify` 误当成 `notify_new_message`。

### 气泡正文不对

先确认运行的是当前 DLL，然后只按 `FlashCaller.RDI` 读取固定字段。不要使用 `RBX`、`RDI+0x68`、最长字符串启发式或 `NotifyTarget.R9` 作为正文。必要时打开特殊文本探针重新核对对象布局。

### 注入或偏移搜索失败

检查微信是否为 x64、`Weixin.dll` 是否存在、Config3 是否有当前版本或可用的邻近版本条目，以及启动器是否能访问目标进程。云端 Config3 失败时必须确保 `dist\Config3.json` 仍存在。

### 重新启用全局 inline hook 后崩溃

不要调用 `InitInlineHooks()`。其中的实现会直接给 `user32.dll` 导出入口写入 5 字节 `E9`，此前会导致微信崩溃。当前正式路径只使用 IAT/delay-IAT hook 加 VEH 断点。

## 目录和关键文件

| 路径 | 用途 |
| --- | --- |
| `src\WeChatAntiRecall\MainWindow.xaml.cs` | 启动器总流程。 |
| `src\WeChatAntiRecall\OffsetSearch.cs` | 读取 Config3 并启动偏移搜索。 |
| `src\WeChatAntiRecall\Services\CallChainSearchService.cs` | PE、字符串、反汇编和调用链搜索。 |
| `src\WeChatAntiRecall\Injector.cs` | 共享内存和远程 DLL 注入。 |
| `src\WeChatAntiRecall\TrayWait.cs` | 启动微信、等待登录托盘并取得 PID。 |
| `native\RevokeHook\RevokeHook\dllmain.cpp` | 配置、VEH、防撤回、消息捕获和事件关联。 |
| `native\RevokeHook\RevokeHook\inline_hook.cpp` | IAT/delay-IAT hook 与 Balloon Tip 显示。 |
| `native\RevokeHook\RevokeHook\vehbp.cpp` / `vehbp.h` | VEH + `INT3` 断点基础设施。 |
| `native\RevokeHook\RevokeHook\revoke_tip.h` | 撤回 XML、模板和消息类型预览工具。 |
| `src\WeChatAntiRecall\Config3.json` | 随包的本地特征码回退。 |
| `src\WeChatAntiRecall\Res\IcoE.ico` | 启动器和通知图标源文件。 |
| `config.yml` | 配置源文件，构建时复制到 `dist\`。 |
| `build.bat` | 完整构建和发布脚本。 |
| `dist\` | 可直接运行的发布目录，含 `RevokeHook.log`。 |

`native\RevokeHook\RevokeHook\iat_hook.cpp`、`find_flash.cpp` 等是早期/诊断辅助代码；当前 Release 项目实际编译并使用的是 `inline_hook.cpp`、`dllmain.cpp` 和 `vehbp.cpp`。

## 已知限制

- 只针对 Windows x64 微信进程；微信升级后必须重新验证 Config3、调用点和 `RDI` 对象布局。
- Balloon Tip 受 Windows 通知设置、微信前后台状态和 `FlashWindowEx` 调用条件影响；Hook 不承诺禁止任务栏闪烁。
- 消息正文目前按 UTF-8 预览并截断，复杂消息类型以占位符显示，不等于完整媒体内容。
- 这是进程注入和内存读取工具，只应在自己控制的微信安装和测试环境中使用；不要把未知版本的偏移或第三方 DLL 混入正式运行目录。
