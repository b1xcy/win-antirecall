# win-antirecall

微信 4.x Windows 防撤回。点击 `WeChatAntiRecall.exe`：启动微信 → 等待登录托盘 → 注入 Hook。

- 跳过 `DeleteMessages`，原文留在打开的会话里
- 自定义撤回提示写入数据库，**切换会话再回来**后显示
- `{from}` / `{time}` 来自微信撤回 XML；`{content}` 从 DelMsg 消息对象的 `std::string` 字段读取（群聊会跳过 `<msgsource>`，优先取它相邻的正文；长文本预览、图片显示为 `[图片]`），写入时扩容 `std::string`
- 不修改微信磁盘上的 `Weixin.dll`
- `Config3.json` **优先从上游云端拉取**，失败则回退随包附带的本地副本（上游不可用时仍能工作）

## 使用

1. 运行 `build.bat`（或直接使用 `dist\`）
2. 打开 `dist\WeChatAntiRecall.exe`
3. 若弹出登录窗口，在微信里登录；检测到托盘后自动注入。未登录就关闭微信时，本程序会一起退出。注入成功后启动器自动退出。

编辑 `dist\config.yml`：

```yaml
tip_phrase: "已拦截 {from} 于 {time} 撤回：{content}"
anti_revoke_self: false
block_update: false    # true = 拦截 WeixinUpdate.exe
notify: false          # true = 注入完成后右下角弹窗
debug: true
```

`block_update` 为 true 时：启动前尝试结束并改名 `WeixinUpdate.exe`（Program Files 可能需要管理员）；注入后 Hook 会在微信进程里定时结束更新进程。

## 目录

| 路径 | 说明 |
| --- | --- |
| `src/WeChatAntiRecall/` | 启动器（搜索偏移、等登录、注入） |
| `src/WeChatAntiRecall/Config3.json` | 本地回退特征码（构建时拷到 `dist\`） |
| `native/RevokeHook/` | 注入 DLL |
| `config.yml` | 用户配置 |
| `dist/` | 发布目录 |

日志：`WeChatAntiRecall.exe` 同目录下的 `RevokeHook.log`（`debug: true` 时）。设置只读 `config.yml`，不再生成 `RevokeHook.ini`。

`Config3.json` 云端地址：

- `https://raw.githubusercontent.com/EEEEhex/RevokeHook/main/Config3.json`
- `http://47.109.182.110:8123/api/get_config3`

可用环境变量 `REVOKEHOOK_CONFIG3_URL` 覆盖。
