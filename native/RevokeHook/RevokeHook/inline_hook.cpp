#include "framework.h"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <delayimp.h>
#include <intrin.h>
#include <shellapi.h>
#include <string>

// 外部日志函数
extern void OutputDebugPrintf(const char* fmt, ...);
extern "C" void ObserveFlashWindowEx(uintptr_t return_address, const FLASHWINFO *flash_info);

// 防止频繁通知
static DWORD g_LastNotifyTime = 0;

// NotificationParams - 传递给后台线程的参数
struct NotificationParams
{
    wchar_t from[256];
    wchar_t content[512];
};

static DWORD WINAPI NotificationThread(LPVOID param)
{
    __try
    {
        NotificationParams* np = (NotificationParams*)param;

        OutputDebugPrintf("[Toast] Thread started: from=[%S] content=[%S]", np->from, np->content);

        // 创建隐藏窗口
        HWND hWnd = CreateWindowExW(0, L"STATIC", L"NotifyWindow", 0, 0, 0, 0, 0,
            nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);

        if (!hWnd)
        {
            OutputDebugPrintf("[Toast] CreateWindowExW failed: %lu", GetLastError());
            delete np;
            return 1;
        }

        // 获取 DLL 所在目录的 IcoE.ico
        wchar_t iconPath[MAX_PATH] = {0};
        HMODULE hModule = nullptr;
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCWSTR)&NotificationThread, &hModule) && hModule)
        {
            GetModuleFileNameW(hModule, iconPath, MAX_PATH);
            wchar_t* lastSlash = wcsrchr(iconPath, L'\\');
            if (lastSlash)
            {
                wcscpy_s(lastSlash + 1, MAX_PATH - (lastSlash + 1 - iconPath), L"IcoE.ico");
            }
        }

        // 加载图标
        HICON hIconTray = nullptr;
        HICON hIconBalloon = nullptr;

        if (iconPath[0] && GetFileAttributesW(iconPath) != INVALID_FILE_ATTRIBUTES)
        {
            hIconTray = (HICON)LoadImageW(nullptr, iconPath, IMAGE_ICON, 16, 16, LR_LOADFROMFILE);
            hIconBalloon = (HICON)LoadImageW(nullptr, iconPath, IMAGE_ICON, 32, 32, LR_LOADFROMFILE);
            OutputDebugPrintf("[Toast] Loading icon from: %S", iconPath);
        }

        if (!hIconTray)
        {
            hIconTray = LoadIcon(nullptr, IDI_INFORMATION);
            OutputDebugPrintf("[Toast] Using fallback tray icon");
        }
        if (!hIconBalloon)
        {
            hIconBalloon = LoadIcon(nullptr, IDI_INFORMATION);
            OutputDebugPrintf("[Toast] Using fallback balloon icon");
        }

        // 步骤 1: NIM_ADD 添加托盘图标
        NOTIFYICONDATAW nid = {};
        nid.cbSize = sizeof(NOTIFYICONDATAW);
        nid.hWnd = hWnd;
        nid.uID = 1;
        nid.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
        nid.uCallbackMessage = WM_APP + 1;
        nid.hIcon = hIconTray;
        wcsncpy_s(nid.szTip, sizeof(nid.szTip) / sizeof(nid.szTip[0]), L"WeChat", _TRUNCATE);

        if (!Shell_NotifyIconW(NIM_ADD, &nid))
        {
            OutputDebugPrintf("[Toast] NIM_ADD failed: %lu", GetLastError());
            DestroyWindow(hWnd);
            delete np;
            return 1;
        }

        OutputDebugPrintf("[Toast] NIM_ADD success");

        // 步骤 2: NIM_SETVERSION 设置版本 4
        nid.uVersion = NOTIFYICON_VERSION_4;
        if (!Shell_NotifyIconW(NIM_SETVERSION, &nid))
        {
            OutputDebugPrintf("[Toast] NIM_SETVERSION failed: %lu", GetLastError());
        }

        // 步骤 3: NIM_MODIFY 显示 balloon tip
        nid.uFlags = NIF_INFO;
        wcsncpy_s(nid.szInfoTitle, sizeof(nid.szInfoTitle) / sizeof(nid.szInfoTitle[0]), np->from, _TRUNCATE);
        wcsncpy_s(nid.szInfo, sizeof(nid.szInfo) / sizeof(nid.szInfo[0]), np->content, _TRUNCATE);
        nid.dwInfoFlags = NIIF_USER | NIIF_LARGE_ICON;
        nid.hBalloonIcon = hIconBalloon;

        if (!Shell_NotifyIconW(NIM_MODIFY, &nid))
        {
            OutputDebugPrintf("[Toast] NIM_MODIFY failed: %lu", GetLastError());
        }
        else
        {
            OutputDebugPrintf("[Toast] Balloon tip displayed");
        }

        // 等待 balloon tip 显示
        Sleep(6000);

        // 清理
        Shell_NotifyIconW(NIM_DELETE, &nid);
        DestroyWindow(hWnd);
        delete np;

        return 0;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        OutputDebugPrintf("[Toast] Exception in notification thread: 0x%X", GetExceptionCode());
        return 1;
    }
}

static void ShowNotification(const char* from, const char* content)
{
    DWORD now = GetTickCount();
    if (now - g_LastNotifyTime < 3000)
    {
        return;
    }
    g_LastNotifyTime = now;

    NotificationParams* np = new NotificationParams();

    // 转换 UTF-8 到 UTF-16
    MultiByteToWideChar(CP_UTF8, 0, from ? from : "WeChat", -1, np->from, 256);
    MultiByteToWideChar(CP_UTF8, 0, content ? content : "New Message", -1, np->content, 512);

    HANDLE hThread = CreateThread(nullptr, 0, NotificationThread, np, 0, nullptr);
    if (hThread)
    {
        CloseHandle(hThread);
        OutputDebugPrintf("[Toast] Notification thread created");
    }
    else
    {
        OutputDebugPrintf("[Toast] CreateThread failed: %lu", GetLastError());
        delete np;
    }
}

using ShellNotifyIconWFunc = BOOL (WINAPI *)(DWORD, PNOTIFYICONDATAW);
static ShellNotifyIconWFunc g_originalShellNotifyIconW = nullptr;
static thread_local bool g_insideShellNotifyHook = false;

using FlashWindowExFunc = BOOL (WINAPI *)(PFLASHWINFO);
using FlashWindowFunc = BOOL (WINAPI *)(HWND, BOOL);
static FlashWindowExFunc g_originalFlashWindowEx = nullptr;
static FlashWindowFunc g_originalFlashWindow = nullptr;

static std::string WideToUtf8(const wchar_t *value)
{
    if (value == nullptr || value[0] == L'\0')
        return {};

    int length = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
    if (length <= 1)
        return {};

    std::string result((size_t)length, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, -1, &result[0], length, nullptr, nullptr);
    result.resize((size_t)length - 1);
    return result;
}

static bool CopyShellNotification(const NOTIFYICONDATAW *data,
    wchar_t *title, size_t titleCount, wchar_t *body, size_t bodyCount)
{
    if (data == nullptr || title == nullptr || body == nullptr)
        return false;

    __try
    {
        if (!(data->uFlags & NIF_INFO))
            return false;
        wcsncpy_s(title, titleCount, data->szInfoTitle, _TRUNCATE);
        wcsncpy_s(body, bodyCount, data->szInfo, _TRUNCATE);
        return body[0] != L'\0';
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static bool CaptureShellNotification(const NOTIFYICONDATAW *data,
    std::string &from, std::string &content)
{
    wchar_t title[sizeof(data->szInfoTitle) / sizeof(wchar_t)] = {};
    wchar_t body[sizeof(data->szInfo) / sizeof(wchar_t)] = {};
    if (!CopyShellNotification(data, title, _countof(title), body, _countof(body)))
        return false;
    from = WideToUtf8(title);
    content = WideToUtf8(body);
    return !content.empty();
}

static bool HookIatEntry(HMODULE module, const char *dllName, const char *functionName,
    void *replacement, void **original)
{
    if (module == nullptr || replacement == nullptr)
        return false;

    auto *dos = reinterpret_cast<IMAGE_DOS_HEADER *>(module);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    auto *nt = reinterpret_cast<IMAGE_NT_HEADERS64 *>(
        reinterpret_cast<uint8_t *>(module) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;

    const auto &imports = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imports.VirtualAddress == 0 || imports.Size == 0)
        return false;

    auto *descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(
        reinterpret_cast<uint8_t *>(module) + imports.VirtualAddress);
    for (; descriptor->Name != 0; ++descriptor)
    {
        const char *name = reinterpret_cast<const char *>(
            reinterpret_cast<uint8_t *>(module) + descriptor->Name);
        if (_stricmp(name, dllName) != 0 || descriptor->OriginalFirstThunk == 0)
            continue;

        auto *thunk = reinterpret_cast<IMAGE_THUNK_DATA64 *>(
            reinterpret_cast<uint8_t *>(module) + descriptor->FirstThunk);
        auto *originalThunk = reinterpret_cast<IMAGE_THUNK_DATA64 *>(
            reinterpret_cast<uint8_t *>(module) + descriptor->OriginalFirstThunk);

        for (; originalThunk->u1.AddressOfData != 0; ++thunk, ++originalThunk)
        {
            if ((originalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
                continue;

            auto *importName = reinterpret_cast<IMAGE_IMPORT_BY_NAME *>(
                reinterpret_cast<uint8_t *>(module) + originalThunk->u1.AddressOfData);
            if (strcmp(reinterpret_cast<const char *>(importName->Name), functionName) != 0)
                continue;

            void *previous = reinterpret_cast<void *>(thunk->u1.Function);
            if (previous == replacement)
                return true;

            DWORD oldProtect = 0;
            if (!VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function),
                PAGE_READWRITE, &oldProtect))
                return false;

            if (original != nullptr && *original == nullptr)
                *original = previous;
            InterlockedExchangePointer(
                reinterpret_cast<PVOID volatile *>(&thunk->u1.Function), replacement);
            VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function),
                oldProtect, &oldProtect);
            return true;
        }
    }
    return false;
}

static bool HookDelayIatEntry(HMODULE module, const char *dllName, const char *functionName,
    void *replacement, void **original)
{
    if (module == nullptr || replacement == nullptr)
        return false;

    auto *base = reinterpret_cast<uint8_t *>(module);
    auto *dos = reinterpret_cast<IMAGE_DOS_HEADER *>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    auto *nt = reinterpret_cast<IMAGE_NT_HEADERS64 *>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;

    const auto &delays = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (delays.VirtualAddress == 0 || delays.Size == 0)
        return false;

    auto *descriptor = reinterpret_cast<ImgDelayDescr *>(base + delays.VirtualAddress);
    for (; descriptor->rvaDLLName != 0; ++descriptor)
    {
        auto *name = reinterpret_cast<const char *>(base + descriptor->rvaDLLName);
        if (_stricmp(name, dllName) != 0)
            continue;

        auto *thunk = reinterpret_cast<IMAGE_THUNK_DATA64 *>(base + descriptor->rvaIAT);
        auto *originalThunk = reinterpret_cast<IMAGE_THUNK_DATA64 *>(base + descriptor->rvaINT);
        for (; originalThunk->u1.AddressOfData != 0; ++thunk, ++originalThunk)
        {
            if ((originalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
                continue;

            auto *importName = reinterpret_cast<IMAGE_IMPORT_BY_NAME *>(
                base + originalThunk->u1.AddressOfData);
            if (strcmp(reinterpret_cast<const char *>(importName->Name), functionName) != 0)
                continue;

            void *previous = reinterpret_cast<void *>(thunk->u1.Function);
            if (previous == replacement)
                return true;

            DWORD oldProtect = 0;
            if (!VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function),
                PAGE_READWRITE, &oldProtect))
                return false;

            if (original != nullptr && *original == nullptr)
                *original = previous;
            InterlockedExchangePointer(
                reinterpret_cast<PVOID volatile *>(&thunk->u1.Function), replacement);
            VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function),
                oldProtect, &oldProtect);
            return true;
        }
    }
    return false;
}

static BOOL WINAPI HookedShellNotifyIconW(DWORD message, PNOTIFYICONDATAW data)
{
    std::string from;
    std::string content;
    const bool capture = !g_insideShellNotifyHook &&
        (message == NIM_ADD || message == NIM_MODIFY) &&
        CaptureShellNotification(data, from, content);

    BOOL result = g_originalShellNotifyIconW != nullptr
        ? g_originalShellNotifyIconW(message, data)
        : FALSE;

    if (capture)
    {
        OutputDebugPrintf("[Hook] Shell_NotifyIconW title=[%s] content=[%s]", from.c_str(), content.c_str());
        g_insideShellNotifyHook = true;
        ShowNotification(from.empty() ? "新消息" : from.c_str(), content.c_str());
        g_insideShellNotifyHook = false;
    }
    return result;
}

static BOOL WINAPI HookedFlashWindowEx(PFLASHWINFO pfwi)
{
    const uintptr_t return_address = reinterpret_cast<uintptr_t>(_ReturnAddress());
    ObserveFlashWindowEx(return_address, pfwi);

    OutputDebugPrintf("[Hook] FlashWindowEx called hwnd=%p flags=0x%X count=%u",
        pfwi ? pfwi->hwnd : nullptr, pfwi ? pfwi->dwFlags : 0,
        pfwi ? pfwi->uCount : 0);

    return g_originalFlashWindowEx != nullptr
        ? g_originalFlashWindowEx(pfwi)
        : FALSE;
}

static BOOL WINAPI HookedFlashWindow(HWND hWnd, BOOL bInvert)
{
    OutputDebugPrintf("[Hook] FlashWindow called hwnd=%p invert=%d", hWnd, bInvert ? 1 : 0);
    return g_originalFlashWindow != nullptr
        ? g_originalFlashWindow(hWnd, bInvert)
        : FALSE;
}

bool InitNotifyIatHook()
{
    OutputDebugPrintf("[Hook] Initializing Shell_NotifyIconW IAT hook...");

    if (g_originalShellNotifyIconW == nullptr)
    {
        HMODULE shell32 = GetModuleHandleA("SHELL32.dll");
        if (shell32 != nullptr)
            g_originalShellNotifyIconW = reinterpret_cast<ShellNotifyIconWFunc>(
                GetProcAddress(shell32, "Shell_NotifyIconW"));
    }

    bool success = false;
    HMODULE modules[] = { GetModuleHandleA(nullptr), GetModuleHandleA("Weixin.dll") };
    for (HMODULE module : modules)
    {
        if (module == nullptr)
            continue;
        void *original = reinterpret_cast<void *>(g_originalShellNotifyIconW);
        bool hooked = HookIatEntry(module, "SHELL32.dll", "Shell_NotifyIconW",
            reinterpret_cast<void *>(HookedShellNotifyIconW), &original);
        if (HookDelayIatEntry(module, "SHELL32.dll", "Shell_NotifyIconW",
            reinterpret_cast<void *>(HookedShellNotifyIconW), &original))
            hooked = true;
        if (hooked)
        {
            g_originalShellNotifyIconW = reinterpret_cast<ShellNotifyIconWFunc>(original);
            OutputDebugPrintf("[Hook] Shell_NotifyIconW IAT hooked in %p", module);
            success = true;
        }
    }

    HMODULE user32 = GetModuleHandleA("USER32.dll");
    if (user32 != nullptr)
    {
        if (g_originalFlashWindowEx == nullptr)
            g_originalFlashWindowEx = reinterpret_cast<FlashWindowExFunc>(
                GetProcAddress(user32, "FlashWindowEx"));
        if (g_originalFlashWindow == nullptr)
            g_originalFlashWindow = reinterpret_cast<FlashWindowFunc>(
                GetProcAddress(user32, "FlashWindow"));
    }

    for (HMODULE module : modules)
    {
        if (module == nullptr)
            continue;

        void *originalEx = reinterpret_cast<void *>(g_originalFlashWindowEx);
        bool hookedEx = HookIatEntry(module, "USER32.dll", "FlashWindowEx",
            reinterpret_cast<void *>(HookedFlashWindowEx), &originalEx);
        if (HookDelayIatEntry(module, "USER32.dll", "FlashWindowEx",
            reinterpret_cast<void *>(HookedFlashWindowEx), &originalEx))
            hookedEx = true;
        if (hookedEx)
        {
            if (originalEx != nullptr && originalEx != reinterpret_cast<void *>(HookedFlashWindowEx))
                g_originalFlashWindowEx = reinterpret_cast<FlashWindowExFunc>(originalEx);
            OutputDebugPrintf("[Hook] FlashWindowEx IAT hooked in %p", module);
            success = true;
        }

        void *original = reinterpret_cast<void *>(g_originalFlashWindow);
        bool hooked = HookIatEntry(module, "USER32.dll", "FlashWindow",
            reinterpret_cast<void *>(HookedFlashWindow), &original);
        if (HookDelayIatEntry(module, "USER32.dll", "FlashWindow",
            reinterpret_cast<void *>(HookedFlashWindow), &original))
            hooked = true;
        if (hooked)
        {
            if (original != nullptr && original != reinterpret_cast<void *>(HookedFlashWindow))
                g_originalFlashWindow = reinterpret_cast<FlashWindowFunc>(original);
            OutputDebugPrintf("[Hook] FlashWindow IAT hooked in %p", module);
            success = true;
        }
    }

    if (!success)
        OutputDebugPrintf("[Hook] Shell_NotifyIconW IAT entry not found");
    return success;
}

// 简单的 inline hook - 5字节 JMP
static bool InstallInlineHook(void* targetFunc, void* hookFunc)
{
    if (!targetFunc || !hookFunc)
        return false;

    DWORD oldProtect;
    if (!VirtualProtect(targetFunc, 5, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        OutputDebugPrintf("[Hook] VirtualProtect failed: %d", GetLastError());
        return false;
    }

    // 写入 JMP 指令: E9 [rel32]
    uint8_t* code = (uint8_t*)targetFunc;
    code[0] = 0xE9;
    int32_t offset = (int32_t)((uint8_t*)hookFunc - (uint8_t*)targetFunc - 5);
    memcpy(code + 1, &offset, 4);

    VirtualProtect(targetFunc, 5, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), targetFunc, 5);

    return true;
}

bool InitInlineHooks()
{
    OutputDebugPrintf("[Hook] Initializing inline hooks...");

    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (!hUser32)
    {
        OutputDebugPrintf("[Hook] Failed to get user32.dll");
        return false;
    }

    OutputDebugPrintf("[Hook] user32.dll at %p", hUser32);

    bool success = false;

    // Hook FlashWindowEx
    void* pFlashWindowEx = GetProcAddress(hUser32, "FlashWindowEx");
    if (pFlashWindowEx)
    {
        OutputDebugPrintf("[Hook] FlashWindowEx at %p", pFlashWindowEx);
        if (InstallInlineHook(pFlashWindowEx, (void*)HookedFlashWindowEx))
        {
            OutputDebugPrintf("[Hook] Hooked FlashWindowEx successfully");
            success = true;
        }
    }

    // Hook FlashWindow
    void* pFlashWindow = GetProcAddress(hUser32, "FlashWindow");
    if (pFlashWindow)
    {
        OutputDebugPrintf("[Hook] FlashWindow at %p", pFlashWindow);
        if (InstallInlineHook(pFlashWindow, (void*)HookedFlashWindow))
        {
            OutputDebugPrintf("[Hook] Hooked FlashWindow successfully");
            success = true;
        }
    }

    return success;
}

// 由 dllmain.cpp 调用，传入实际的 from 和 content
extern "C" __declspec(dllexport) void SendWindowsNotification(const char* from, const char* content)
{
    ShowNotification(from, content);
}
