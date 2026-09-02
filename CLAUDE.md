# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

微信 4.x Windows 防撤回。启动器搜索 `Weixin.dll` 偏移并注入 `RevokeHook.dll`；不修改磁盘上的 `Weixin.dll`。打开的会话里原文保留（跳过 `DeleteMessages`）；自定义撤回提示写入数据库，切换会话再回来后显示。

只针对微信 4.x（进程 `Weixin.exe`、模块 `Weixin.dll`）。安装路径来自 `HKCU\Software\Tencent\Weixin\InstallPath`。

## Commands

没有测试项目，也没有独立 lint 目标。日常构建用仓库根目录的 `build.bat`（需要 VS 2022 Build Tools 的 `vcvars64.bat`，路径写死在脚本里）。

```bat
build.bat
```

步骤：`RevokeHook.dll`（Release|x64）→ `update_stub.exe` → 把 C# 启动器 `dotnet publish` 成 self-contained 单文件到 `dist\` → 拷贝 DLL / stub / `config.yml` / `Config3.json`。产物：`dist\WeChatAntiRecall.exe`。

分开构建：

```bat
msbuild native\RevokeHook\RevokeHook.sln /p:Configuration=Release /p:Platform=x64
cl /nologo /O1 /DUNICODE /D_UNICODE native\update_stub.c /link /SUBSYSTEM:WINDOWS /OUT:native\update_stub.exe
dotnet publish src\WeChatAntiRecall\WeChatAntiRecall.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -o dist
dotnet build src\WeChatAntiRecall\WeChatAntiRecall.csproj -c Debug
```

`WeChatAntiRecall.sln` 只含 C# 启动器。原生 DLL 是另一套 `native\RevokeHook\RevokeHook.sln`（v143，x64 Release 用 `/MT`）。从 IDE 跑启动器不会自动带上 `RevokeHook.dll`；注入需要 `AppContext.BaseDirectory` 里同时有 DLL 和 `config.yml`。偏移通过命名共享内存 `Local\WeChatAntiRecall.Runtime.v1` 传给 DLL，不写 `RevokeHook.ini`。

`dist\`、`**/x64/`、`**/bin/`、`**/obj/` 已 gitignore。

## Architecture

两段式：C# WPF 启动器（.NET 8，`net8.0-windows`，win-x64）做一次性准备后退出；C++ DLL 留在微信进程里用 VEH + INT3 挂钩。

### 启动器流水线

`MainWindow.RunAsync` 顺序：

1. `AppConfig.Load()` 读旁边的 `config.yml`（手写 YAML，不是完整解析器）。
2. `OffsetSearch.Run`：定位 `Weixin.dll` → 拉/回退 `Config3.json` → Capstone 调链搜索，返回两个 RVA（不落盘）。
3. 若 `block_update`：结束 `WeixinUpdate.exe`，把安装目录里的更新器改名为 `.bak`，再拷入空实现 `update_stub.exe`（Program Files 可能需要管理员；启动器清单是 `asInvoker`）。
4. 若尚未运行则启动 `Weixin.exe`。
5. 等到出现托盘窗口（类名/标题含 `WxTrayIconMessageWindow`），取其 PID。未登录就关微信会抛 `WeChatExitedException` 并一起退出。
6. `Injector.Inject`：先把两个 RVA 写入命名文件映射 `Local\WeChatAntiRecall.Runtime.v1`（magic `WHR1`），再 `SeDebugPrivilege` + `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread(LoadLibraryW)`。映射在 `LoadLibraryW` 的远程线程（DllMain）读完后才关掉。
7. 可选右下角 `NotificationWindow`，然后 `Shutdown`。注入成功后启动器不常驻。

### 偏移搜索（必须理解的不变量）

`Config3.json` 是 `版本号 → {sig1,sig2,sig3}`。三个 sig 是 `Weixin.dll` `.rdata` 里的加密字符串字节：

| 字段 | 对应函数 |
| --- | --- |
| sig1 | `CoReplaceOriginMessageByRevoke`（origin） |
| sig2 | `DeleteMessages` |
| sig3 | `CoAddMessageToDB` |

`CallChainSearchService`：在 `.rdata` 找字符串 → `.text` 里 RIP-relative `lea` → PE 异常目录（pdata）划函数边界 → 从 origin 往下搜最多 3 层 `call`。删除链还要求该 `call` 前 0x100 字节内有把 rcx/rdx/r8/r9 或 `[rsp+disp]` 置零的指令。传给 DLL 的不是函数入口：

- `DelMsgOffset` = 删除链的 **RootCallRva**（origin 里那条 `E8` 的 RVA）。命中后 hook 把 `RIP += 5`、`RAX = 1`，等于跳过这次 5 字节 `call`。
- `Add2DBOffset` = 添加链的 **TargetCallRva**（直接打到 `CoAddMessageToDB` 的那条 `call`，通常在 wrapper 里）。

版本匹配：精确归一化相等，否则用 ≤ 当前版本的最高 Config3 条目，再否则用最近的更高版本。云端优先：`https://raw.githubusercontent.com/EEEEhex/RevokeHook/main/Config3.json`，其次 `http://47.109.182.110:8123/api/get_config3`；可用环境变量 `REVOKEHOOK_CONFIG3_URL` 覆盖。失败则用随包 `Config3.json`。

反汇编走 NuGet `capstone` 4.0.2（`cs_open`/`cs_disasm`）。原生 capstone 不可用时，`call` 扫描退回扫 `E8 rel32`。

### 注入 DLL

`DllMain` 的 `lpReserved` 在 `LoadLibraryW` 注入时是 NULL。设置从 DLL 同目录的 `config.yml` 读取（与启动器同一份：`tip_phrase` / `anti_revoke_self` / `block_update` / `debug`）；两个 RVA 从命名映射 `Local\WeChatAntiRecall.Runtime.v1` 读取。然后最多等 30s 让 `Weixin.dll` 加载完，再按 `imgbase + offset` 下 INT3。

`vehbp.cpp`：最多 64 个软断点。命中 `EXCEPTION_BREAKPOINT` 后恢复原字节、把 RIP 拨回、跑回调、设 TF；`EXCEPTION_SINGLE_STEP` 再写回 `0xCC`。pending 单步索引存在 TLS。

`OnTargetHit`（`dllmain.cpp`）两条路径，布局在**第一次命中时扫描并缓存**（参数下标、`std::string` 偏移、srvid 偏移），之后走缓存：

- **DelMsg**：在 RDX/R8/R9 指向的对象里找含「撤回」/`recalled` 的 MSVC `std::string`。自己撤回且 `AntiRevokeSelf=false` 则放过。原文预览扫描对象上的 `std::string`（`debug` 时 dump 带 `class=plain|msgsource|wxid|...`）。群聊必须丢掉 `<msgsource>` 元数据，优先取它前后 `0x20` 对齐的正文槽，而不是死读 `+0x1A0`。图片等变成 `[图片]`。结果写入 TLS `pending_content`，必要时改 XML，并把 notify 参数置 1，然后跳过 `call`。
- **Add2DB**：仅当本线程刚防撤回过。给消息换一个 MD5 派生的新 srvid（避免和已删 id 冲突），`ForceAllowNewId`，再用 `revoke_tip` 把自定义短语写进 revoke XML（先扩容 `std::string`，失败则压缩 XML）。同一 srvid 不插两条提示。

`StdString` 按 MSVC 布局：16 字节 SSO / 堆指针 + `size` + `capability`。写长 tip 时用微信进程的 `ucrtbase!malloc` 扩容。

`revoke_tip.h` 从 macOS `wechat-antirecall` 移植，无 Windows 头。占位符 `{from}` `{time}` `{content}`；`{from}`/`{time}` 来自撤回 XML，`{content}` 来自 DelMsg 捕获或 `newmsgid` 缓存。WeChat 4.1.9 可见 tip 在 `<content>` 而不一定在 `<replacemsg>`。

`block_update` 在 DLL 里还会每 2s 结束一次 `WeixinUpdate.exe`。

## Config and logs

用户配置：`config.yml`（构建拷到 `dist\`）。启动器认识的键：

| 键 | 作用 |
| --- | --- |
| `tip_phrase` | 自定义撤回提示，占位符 `{from}` `{time}` `{content}` |
| `anti_revoke_self` | 是否拦截自己撤回 |
| `block_update` | 禁用/结束 `WeixinUpdate.exe` |
| `notify` | 注入完成后右下角弹窗 |
| `debug` | 启动器日志 + DLL 写同目录 `RevokeHook.log` |

DLL 在 `PROCESS_ATTACH` 时自己解析 `config.yml`。改 tip 或开关后必须再跑一次启动器重新注入。偏移不写进 YAML，由启动器每次搜索后通过共享内存传入。

调试：`debug: true` 时 DLL 每次 `PROCESS_ATTACH` 清空并写 `RevokeHook.dll` 同目录（即 `WeChatAntiRecall.exe` 旁边）的 `RevokeHook.log`，同时 `OutputDebugStringA`。
