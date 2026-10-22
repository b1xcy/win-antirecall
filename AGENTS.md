# Repository Guidelines

## Project Structure & Module Organization

- `src/GreenSoftAntiRecall/`: .NET 8 WPF launcher, injection, configuration, and offset discovery. `Services/` contains search and configuration services; `Models/` contains configuration models; `Res/` holds the application icon.
- `native/RevokeHook/RevokeHook/`: C++ DLL. `dllmain.cpp` handles message capture and recall interception; `vehbp.cpp` manages breakpoints; `inline_hook.cpp` handles notifications and API hooks.
- `native/update_stub.c`: replacement updater executable.
- `config.yml` and `Config3.json`: runtime settings and version signatures. `dist/` contains ignored build artifacts.
- Read `HANDOFF.md` for debugging evidence and `CLAUDE.md` for architecture details. The root solution contains only the launcher; the native solution is separate.

## Build, Test, and Development Commands

Use Windows x64, .NET 8 SDK, and Visual Studio 2022 Build Tools with C++ support. `build.bat` hardcodes the VS toolchain path.

```powershell
cmd /c build.bat
dotnet build src/GreenSoftAntiRecall/GreenSoftAntiRecall.csproj -c Debug
# Run in an x64 Developer Command Prompt:
msbuild native/RevokeHook/RevokeHook.sln /p:Configuration=Release /p:Platform=x64
```

The full build publishes the launcher and copies runtime files into `dist/`. Run `dist/GreenSoftAntiRecall.exe` for integration checks. Fully exit 某绿色软件 before replacing a loaded DLL or validating changes after reinjection.

## Coding Style & Naming Conventions

Use four-space indentation and match surrounding brace placement. C# uses file-scoped namespaces, PascalCase types/methods, and camelCase locals. Preserve native conventions such as `g_` globals and existing Win32 signatures. Keep edits focused. Native compilation uses `/utf-8`; no dedicated formatter or lint target exists.

## Testing Guidelines

No automated test project or coverage threshold exists. Build affected components and manually verify against 某绿色软件 4.1.9.57 x64. Check single/group messages, Unicode, media previews, recall behavior, foreground/background transitions, notification cancellation, sender avatars, and chat navigation. Record the 某绿色软件 version, configuration, and results. Inspect `RevokeHook.log` with `debug: true`; remove private message content from shared logs.

## Commit & Pull Request Guidelines

Use existing prefixes: `fix:`, `feat:`, and `ci:` with concise descriptions. PRs should explain the trigger and resulting behavior, link relevant issues, list validation, and include screenshots for notification changes. Keep generated binaries out of commits.

## Configuration & Agent Instructions

Preserve runtime offset discovery; never patch the installed target module or enable the unsafe `InitInlineHooks()` path. Runtime interop identifiers for the target app live in `src/GreenSoftAntiRecall/TargetApp.cs` and `native/RevokeHook/RevokeHook/target_app.h`; keep them encoded and use those helpers instead of hardcoding names. Keep configuration beside the deployed DLL. Python tooling must use `uv run`; manage dependencies through `uv add`/`uv remove`, commit `uv.lock`, and ignore `.venv/` when introduced. Never use system pip or manually edit dependency sections.

## User Confirmation Requirements

- 更新代码后，若构建、复制或替换产物时遇到某绿色软件占用文件（例如 `RevokeHook.dll`），先询问一次用户是否需要结束（kill）某绿色软件应用以完成更新，并等待明确答复后再进行后续操作。用户同意后才结束某绿色软件并继续更新；用户拒绝则保留某绿色软件运行并按其答复处理。不要自行结束进程、反复询问或在答复前改用其他交付目录。
- 每次彻底完成代码改动及必要验证后，都要询问用户是否需要执行 git commit 和 push。等待明确答复后再执行，提交和推送范围以用户授权为准。
