#include "framework.h"
#include "target_app.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <delayimp.h>
#include <objidl.h>
#include <gdiplus.h>
#include <intrin.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <propkey.h>
#include <propvarutil.h>
#include <powrprof.h>
#include <powersetting.h>
#include <string>
#include <vector>
#include <winhttp.h>
#include <TlHelp32.h>

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "propsys.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "powrprof.lib")

// 外部日志函数
extern void OutputDebugPrintf(const char* fmt, ...);
extern "C" void ObserveFlashWindowEx(uintptr_t return_address,
    const FLASHWINFO *flash_info, const CONTEXT *hook_context);

// 防止频繁通知
static DWORD g_LastNotifyTime = 0;

// NotificationParams - 传递给后台线程的参数
struct NotificationParams
{
    wchar_t from[256];
    wchar_t content[512];
    wchar_t avatarUrl[2048];
    char conversation[128];
    HWND chatWindow;
    DWORD chatThread;
    UINT id;
    DWORD queuedAt;
    UINT generation;
};

// 只保留一个待显示的通知，避免锁屏期间向 Shell 累积气泡。
static SRWLOCK g_notificationLock = SRWLOCK_INIT;
static NotificationParams g_pendingNotification = {};
static bool g_pendingNotificationValid = false;
static HANDLE g_notificationEvent = nullptr;
static volatile LONG g_notificationWorkerRunning = 0;
static UINT g_openChatMessage = 0;
static HHOOK g_openChatHook = nullptr;
static NotificationParams g_requestedChat = {};
static UINT g_notificationGeneration = 0;
static volatile LONG g_displayOff = 0;
static HPOWERNOTIFY g_displayNotification = nullptr;
static const GUID g_sessionDisplayStatus =
    { 0x2b84c20e, 0xad23, 0x4ddf, { 0x93, 0xdb, 0x05, 0xff, 0xbd, 0x7e, 0xfc, 0xa5 } };

static bool IsTargetForeground()
{
    DWORD process = 0;
    GetWindowThreadProcessId(GetForegroundWindow(), &process);
    return process == GetCurrentProcessId();
}

static ULONG CALLBACK DisplayPowerChanged(PVOID, ULONG type, PVOID setting)
{
    if (type != PBT_POWERSETTINGCHANGE || !setting)
        return ERROR_SUCCESS;
    const auto *power = static_cast<const POWERBROADCAST_SETTING *>(setting);
    if (!IsEqualGUID(power->PowerSetting, g_sessionDisplayStatus) ||
        power->DataLength != sizeof(DWORD))
        return ERROR_SUCCESS;

    DWORD state = 0;
    memcpy(&state, power->Data, sizeof(state));
    AcquireSRWLockExclusive(&g_notificationLock);
    const LONG off = state == 0;
    const LONG wasOff = InterlockedExchange(&g_displayOff, off);
    if (off || wasOff)
    {
        g_pendingNotificationValid = false;
        ++g_notificationGeneration;
    }
    HANDLE event = g_notificationEvent;
    ReleaseSRWLockExclusive(&g_notificationLock);
    if (event)
        SetEvent(event);
    OutputDebugPrintf("[Toast] Session display state=%lu", state);
    return ERROR_SUCCESS;
}

extern "C" void CancelWindowsNotifications()
{
    AcquireSRWLockExclusive(&g_notificationLock);
    g_pendingNotificationValid = false;
    ++g_notificationGeneration;
    HANDLE event = g_notificationEvent;
    ReleaseSRWLockExclusive(&g_notificationLock);
    if (event)
        SetEvent(event);
}

static void OpenNativeChat(const char *username)
{
    __try
    {
        auto *base = reinterpret_cast<BYTE *>(GetModuleHandleW(target_app::ModuleName().c_str()));
        if (!base || !username[0])
            return;
        auto *dos = reinterpret_cast<IMAGE_DOS_HEADER *>(base);
        auto *nt = reinterpret_cast<IMAGE_NT_HEADERS64 *>(base + dos->e_lfanew);
        // Native unread-popup route, verified against the supported 4.1.9.57 build.
        if (nt->FileHeader.TimeDateStamp != 0x6A0714C7 ||
            nt->OptionalHeader.SizeOfImage != 0xAD92000 ||
            memcmp(base + 0x167FB0, "\x55\x41\x57\x41\x56\x56\x57\x53\x48\x83\xEC\x78", 12) != 0)
        {
            OutputDebugPrintf("[Chat] Unsupported target module build; native navigation skipped");
            return;
        }
        void *app = *reinterpret_cast<void **>(base + 0xA6C44C0);
        if (!app)
            return;
        void *root = reinterpret_cast<void *(*)(void *)>(base + 0x16A510)(app);
        if (!root)
            return;
        void *service = reinterpret_cast<void *(*)(void *)>(base + 0x8B3140)(root);
        if (!service)
            return;
        struct NativeString
        {
            union { char inlineData[16]; char *data; } storage;
            size_t size, capacity;
        } name = {};
        name.size = strlen(username);
        name.capacity = name.size < 16 ? 15 : name.size;
        if (name.size < 16)
            memcpy(name.storage.inlineData, username, name.size + 1);
        else
            name.storage.data = const_cast<char *>(username);
        void *window = reinterpret_cast<void *(*)(void *, const NativeString *)>(
            base + 0x1EBF720)(service, &name);
        if (window)
        {
            if (reinterpret_cast<bool (*)(void *)>(base + 0x7C52F0)(window))
                reinterpret_cast<void (*)(void *)>(base + 0x4FF9C0)(window);
            reinterpret_cast<void (*)(void *)>(base + 0x4FF8B0)(window);
            reinterpret_cast<void (*)(void *)>(base + 0x50AC60)(window);
        }
        else
        {
            // The native callee consumes this MSVC string and frees its buffer.
            if (name.size >= 16)
            {
                name.storage.data = reinterpret_cast<char *(*)(size_t)>(
                    base + 0x659FDAC)(name.capacity + 1);
                if (!name.storage.data)
                    return;
                memcpy(name.storage.data, username, name.size + 1);
            }
            uintptr_t message[2] = {};
            reinterpret_cast<void (*)(void *, NativeString *, void *, bool, bool)>(
                base + 0x167FB0)(app, &name, message, true, false);
        }
        OutputDebugPrintf("[Chat] Native navigation returned: username=%s thread=%lu detached=%d",
            username, GetCurrentThreadId(), window ? 1 : 0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        OutputDebugPrintf("[Chat] Native navigation exception: 0x%X", GetExceptionCode());
    }
}

struct FindWindowOnThreadContext
{
    DWORD thread;
    HWND hwnd;
};

static BOOL CALLBACK FindWindowOnThread(HWND hwnd, LPARAM lParam)
{
    auto *ctx = reinterpret_cast<FindWindowOnThreadContext *>(lParam);
    DWORD pid = 0;
    if (GetWindowThreadProcessId(hwnd, &pid) == ctx->thread && pid == GetCurrentProcessId())
    {
        ctx->hwnd = hwnd;
        return FALSE;
    }
    return TRUE;
}

static LRESULT CALLBACK OpenChatCallWndProc(int code, WPARAM wParam, LPARAM lParam)
{
    auto *message = reinterpret_cast<CWPSTRUCT *>(lParam);
    if (code == HC_ACTION && message->message == g_openChatMessage)
    {
        char username[128] = {};
        AcquireSRWLockExclusive(&g_notificationLock);
        if (message->hwnd == g_requestedChat.chatWindow && message->wParam == g_requestedChat.id)
        {
            strcpy_s(username, g_requestedChat.conversation);
            g_requestedChat.conversation[0] = '\0';
            UnhookWindowsHookEx(g_openChatHook);
            g_openChatHook = nullptr;
        }
        ReleaseSRWLockExclusive(&g_notificationLock);
        if (username[0])
            OpenNativeChat(username);
    }
    return CallNextHookEx(nullptr, code, wParam, lParam);
}

static void RequestOpenChat(const NotificationParams &notification)
{
    HWND hwnd = notification.chatWindow;
    DWORD process = 0;
    DWORD thread = GetWindowThreadProcessId(hwnd, &process);
    if (!hwnd || !IsWindow(hwnd) || process != GetCurrentProcessId())
    {
        FindWindowOnThreadContext ctx = { notification.chatThread, nullptr };
        if (ctx.thread)
            EnumWindows(FindWindowOnThread, reinterpret_cast<LPARAM>(&ctx));
        hwnd = ctx.hwnd;
        thread = hwnd ? GetWindowThreadProcessId(hwnd, &process) : 0;
    }
    if (!hwnd || !thread || process != GetCurrentProcessId() || !notification.conversation[0])
    {
        OutputDebugPrintf("[Chat] Notification has no valid conversation target");
        ShellExecuteW(nullptr, L"open", target_app::LaunchUri().c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        return;
    }

    HMODULE module = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&OpenChatCallWndProc), &module);
    AcquireSRWLockExclusive(&g_notificationLock);
    if (!g_openChatMessage)
        g_openChatMessage = RegisterWindowMessageW(L"GreenSoftAntiRecall.OpenChat.v1");
    if (g_openChatHook)
        UnhookWindowsHookEx(g_openChatHook);
    g_requestedChat = notification;
    g_requestedChat.chatWindow = hwnd;
    g_openChatHook = SetWindowsHookExW(WH_CALLWNDPROC, OpenChatCallWndProc, module, thread);
    const UINT openMessage = g_openChatMessage;
    const HHOOK hook = g_openChatHook;
    ReleaseSRWLockExclusive(&g_notificationLock);

    DWORD_PTR result = 0;
    const BOOL sent = openMessage && hook &&
        SendMessageTimeoutW(hwnd, openMessage, notification.id, 0,
            SMTO_ABORTIFHUNG, 5000, &result);
    if (!sent)
    {
        OutputDebugPrintf("[Chat] UI-thread dispatch failed: %lu", GetLastError());
        AcquireSRWLockExclusive(&g_notificationLock);
        if (g_openChatHook == hook)
        {
            UnhookWindowsHookEx(g_openChatHook);
            g_openChatHook = nullptr;
            g_requestedChat.conversation[0] = '\0';
        }
        ReleaseSRWLockExclusive(&g_notificationLock);
        ShellExecuteW(nullptr, L"open", target_app::LaunchUri().c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    }
}

static bool DownloadAvatarBytes(const wchar_t *url, std::vector<BYTE> &bytes)
{
    bytes.clear();
    if (url == nullptr || url[0] == L'\0' || wcslen(url) >= 2048)
        return false;

    wchar_t hostName[256] = {};
    wchar_t urlPath[2048] = {};
    wchar_t extraInfo[2048] = {};
    URL_COMPONENTS parts = {};
    parts.dwStructSize = sizeof(parts);
    parts.lpszHostName = hostName;
    parts.dwHostNameLength = _countof(hostName);
    parts.lpszUrlPath = urlPath;
    parts.dwUrlPathLength = _countof(urlPath);
    parts.lpszExtraInfo = extraInfo;
    parts.dwExtraInfoLength = _countof(extraInfo);
    if (!WinHttpCrackUrl(url, 0, 0, &parts) ||
        (parts.nScheme != INTERNET_SCHEME_HTTP &&
         parts.nScheme != INTERNET_SCHEME_HTTPS) || parts.dwHostNameLength == 0)
    {
        return false;
    }

    std::wstring objectName = parts.dwUrlPathLength == 0 ? L"/" : urlPath;
    if (parts.dwExtraInfoLength != 0)
        objectName.append(parts.lpszExtraInfo, parts.dwExtraInfoLength);

    HINTERNET session = WinHttpOpen(L"GreenSoftAntiRecall/1.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (session == nullptr)
        return false;
    WinHttpSetTimeouts(session, 1500, 1500, 2500, 2500);

    HINTERNET connection = WinHttpConnect(session, hostName, parts.nPort, 0);
    HINTERNET request = connection == nullptr ? nullptr : WinHttpOpenRequest(
        connection, L"GET", objectName.c_str(), nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        parts.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);
    bool ok = false;
    const ULONGLONG started = GetTickCount64();
    if (request != nullptr && WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS,
        0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) && WinHttpReceiveResponse(request, nullptr))
    {
        DWORD status = 0;
        DWORD statusSize = sizeof(status);
        if (WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE |
            WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status,
            &statusSize, WINHTTP_NO_HEADER_INDEX) && status >= 200 && status < 300)
        {
            constexpr size_t kMaxAvatarBytes = 4 * 1024 * 1024;
            BYTE chunk[8192];
            while (GetTickCount64() - started < 5000)
            {
                DWORD read = 0;
                if (!WinHttpReadData(request, chunk, sizeof(chunk), &read) ||
                    bytes.size() + read > kMaxAvatarBytes)
                    break;
                if (read == 0)
                {
                    ok = !bytes.empty();
                    break;
                }
                bytes.insert(bytes.end(), chunk, chunk + read);
            }
        }
    }
    if (request != nullptr)
        WinHttpCloseHandle(request);
    if (connection != nullptr)
        WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    if (!ok)
        bytes.clear();
    return ok;
}

static HICON DecodeAvatarIcon(const std::vector<BYTE> &bytes)
{
    if (bytes.empty())
        return nullptr;

    HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes.size());
    if (memory == nullptr)
        return nullptr;
    void *buffer = GlobalLock(memory);
    if (buffer == nullptr)
    {
        GlobalFree(memory);
        return nullptr;
    }
    memcpy(buffer, bytes.data(), bytes.size());
    GlobalUnlock(memory);

    IStream *stream = nullptr;
    if (CreateStreamOnHGlobal(memory, TRUE, &stream) != S_OK)
    {
        GlobalFree(memory);
        return nullptr;
    }

    Gdiplus::GdiplusStartupInput startupInput;
    ULONG_PTR token = 0;
    HICON icon = nullptr;
    if (Gdiplus::GdiplusStartup(&token, &startupInput, nullptr) == Gdiplus::Ok)
    {
        {
            Gdiplus::Bitmap bitmap(stream, FALSE);
            const UINT width = bitmap.GetWidth();
            const UINT height = bitmap.GetHeight();
            if (bitmap.GetLastStatus() == Gdiplus::Ok && width > 0 && height > 0 &&
                width <= 2048 && height <= 2048)
            {
                const int size = GetSystemMetrics(SM_CXICON);
                Gdiplus::Bitmap scaled(size, size, PixelFormat32bppARGB);
                Gdiplus::Graphics graphics(&scaled);
                graphics.Clear(Gdiplus::Color(0, 0, 0, 0));
                graphics.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
                const float scale = static_cast<float>(size) / (width > height ? width : height);
                const float w = width * scale;
                const float h = height * scale;
                if (graphics.DrawImage(&bitmap, (size - w) / 2, (size - h) / 2, w, h) == Gdiplus::Ok)
                    scaled.GetHICON(&icon);
            }
        }
        Gdiplus::GdiplusShutdown(token);
    }
    stream->Release();
    return icon;
}

static HICON LoadAvatarIcon(const wchar_t *url)
{
    std::vector<BYTE> bytes;
    if (!DownloadAvatarBytes(url, bytes))
    {
        OutputDebugPrintf("[Toast] Avatar download failed");
        return nullptr;
    }
    HICON icon = DecodeAvatarIcon(bytes);
    if (icon == nullptr)
        OutputDebugPrintf("[Toast] Avatar decode failed");
    return icon;
}

static bool IsWorkstationLocked()
{
    HDESK desktop = OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
    if (!desktop)
        return true;

    wchar_t desktopName[64] = {};
    DWORD bytes = 0;
    const bool queried = GetUserObjectInformationW(
        desktop, UOI_NAME, desktopName, sizeof(desktopName), &bytes) != FALSE;
    CloseDesktop(desktop);
    return queried && _wcsicmp(desktopName, L"Default") != 0;
}

static bool TakePendingNotification(NotificationParams &params)
{
    AcquireSRWLockExclusive(&g_notificationLock);
    const bool valid = g_pendingNotificationValid;
    if (valid)
    {
        params = g_pendingNotification;
        g_pendingNotificationValid = false;
    }
    ReleaseSRWLockExclusive(&g_notificationLock);
    return valid;
}

static LRESULT CALLBACK NotificationWindowProc(HWND hWnd, UINT message,
    WPARAM wParam, LPARAM lParam)
{
    if (message == WM_APP + 1 &&
        (static_cast<UINT>(lParam) == NIN_BALLOONUSERCLICK ||
         static_cast<UINT>(LOWORD(lParam)) == NIN_BALLOONUSERCLICK))
    {
        auto *notification = reinterpret_cast<NotificationParams *>(
            GetWindowLongPtrW(hWnd, GWLP_USERDATA));
        const UINT id = HIWORD(lParam) ? HIWORD(lParam) : static_cast<UINT>(wParam);
        if (notification && notification->id == id)
        {
            CancelWindowsNotifications();
            if (notification->conversation[0])
                RequestOpenChat(*notification);
            else
                ShellExecuteW(nullptr, L"open", target_app::LaunchUri().c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        }
        return 0;
    }
    return DefWindowProcW(hWnd, message, wParam, lParam);
}

static DWORD WINAPI NotificationThread(LPVOID param)
{
    HWND hWnd = nullptr;
    HICON hIconTray = nullptr;
    HICON hIconBalloon = nullptr;
    HICON hAvatar = nullptr;
    wchar_t avatarUrl[2048] = {};
    bool ownsTrayIcon = false;
    bool ownsBalloonIcon = false;
    NOTIFYICONDATAW nid = {};
    bool iconAdded = false;
    NotificationParams displayedNotification = {};
    const HRESULT comResult = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    __try
    {
        (void)param;

        DWORD balloonEnd = 0;
        UINT generation = 0;
        bool wasForeground = false;

        for (;;)
        {
            const bool foreground = IsTargetForeground();
            if (foreground && !wasForeground)
                CancelWindowsNotifications();
            wasForeground = foreground;
            AcquireSRWLockShared(&g_notificationLock);
            const UINT currentGeneration = g_notificationGeneration;
            ReleaseSRWLockShared(&g_notificationLock);
            if (iconAdded && (foreground || generation != currentGeneration))
            {
                Shell_NotifyIconW(NIM_DELETE, &nid);
                iconAdded = false;
                displayedNotification = {};
            }
            // 锁屏时不调用 NIM_MODIFY；保留待显示的最新一条，解锁后只显示这一条。
            if (InterlockedCompareExchange(&g_displayOff, 0, 0) || IsWorkstationLocked())
            {
                if (iconAdded)
                {
                    Shell_NotifyIconW(NIM_DELETE, &nid);
                    iconAdded = false;
                }
            }
            else if (!foreground)
            {
                NotificationParams np = {};
                if (TakePendingNotification(np))
                {
                    if (GetTickCount() - np.queuedAt > 6000 ||
                        np.generation != currentGeneration)
                        continue;

                    if (!hWnd)
                    {
                        OutputDebugPrintf("[Toast] Thread started: from=[%S] content=[%S]",
                            np.from, np.content);

                        // 创建隐藏窗口
                        hWnd = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
                            L"STATIC", L"NotifyWindow", 0, 0, 0, 0, 0,
                            nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);

                        if (!hWnd)
                        {
                            OutputDebugPrintf("[Toast] CreateWindowExW failed: %lu", GetLastError());
                        }
                        else
                        {
                            const wchar_t appId[] = L"GreenSoftAntiRecall.MessageNotifications";
                            const wchar_t displayName[] = L"某绿色软件";
                            HKEY appKey = nullptr;
                            LONG registryResult = RegCreateKeyExW(HKEY_CURRENT_USER,
                                L"Software\\Classes\\AppUserModelId\\GreenSoftAntiRecall.MessageNotifications",
                                0, nullptr, 0, KEY_SET_VALUE, nullptr, &appKey, nullptr);
                            if (registryResult == ERROR_SUCCESS)
                            {
                                registryResult = RegSetValueExW(appKey, L"DisplayName", 0,
                                    REG_SZ, reinterpret_cast<const BYTE *>(displayName), sizeof(displayName));
                                RegCloseKey(appKey);
                            }
                            IPropertyStore *properties = nullptr;
                            HRESULT identityResult = SHGetPropertyStoreForWindow(hWnd,
                                IID_PPV_ARGS(&properties));
                            if (SUCCEEDED(identityResult))
                            {
                                PROPVARIANT value = {};
                                identityResult = InitPropVariantFromString(appId, &value);
                                if (SUCCEEDED(identityResult))
                                    identityResult = properties->SetValue(PKEY_AppUserModel_ID, value);
                                PropVariantClear(&value);
                                properties->Release();
                            }
                            OutputDebugPrintf("[Toast] Application identity: registry=%ld window=0x%X",
                                registryResult, static_cast<unsigned>(identityResult));
                            SetWindowLongPtrW(hWnd, GWLP_USERDATA,
                                reinterpret_cast<LONG_PTR>(&displayedNotification));
                            SetWindowLongPtrW(hWnd, GWLP_WNDPROC,
                                reinterpret_cast<LONG_PTR>(NotificationWindowProc));

                            wchar_t iconPath[MAX_PATH] = {};
                            HMODULE hModule = nullptr;
                            if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                (LPCWSTR)&NotificationThread, &hModule) && hModule)
                            {
                                DWORD length = GetModuleFileNameW(hModule, iconPath, MAX_PATH);
                                wchar_t *lastSlash = wcsrchr(iconPath, L'\\');
                                if (length > 0 && length < MAX_PATH && lastSlash &&
                                    wcscpy_s(lastSlash + 1, MAX_PATH - (lastSlash + 1 - iconPath),
                                        L"IcoE.ico") == 0)
                                {
                                    hIconTray = (HICON)LoadImageW(nullptr, iconPath,
                                        IMAGE_ICON, 16, 16, LR_LOADFROMFILE);
                                    hIconBalloon = (HICON)LoadImageW(nullptr, iconPath,
                                        IMAGE_ICON, 32, 32, LR_LOADFROMFILE);
                                }
                            }
                            ownsTrayIcon = hIconTray != nullptr;
                            ownsBalloonIcon = hIconBalloon != nullptr;
                            if (hIconTray != nullptr || hIconBalloon != nullptr)
                                OutputDebugPrintf("[Toast] Loading fallback icon from DLL directory");

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

                            nid.cbSize = sizeof(NOTIFYICONDATAW);
                            nid.hWnd = hWnd;
                            nid.uID = 1;
                            nid.uCallbackMessage = WM_APP + 1;
                            nid.hIcon = hIconTray;
                            wcsncpy_s(nid.szTip, sizeof(nid.szTip) / sizeof(nid.szTip[0]),
                                L"GreenSoft", _TRUNCATE);
                        }
                    }

                    if (hWnd && hIconTray)
                    {
                        if (wcscmp(avatarUrl, np.avatarUrl) != 0 ||
                            (hAvatar == nullptr && np.avatarUrl[0] != L'\0'))
                        {
                            if (hAvatar)
                                DestroyIcon(hAvatar);
                            hAvatar = nullptr;
                            wcscpy_s(avatarUrl, np.avatarUrl);
                            if (avatarUrl[0] != L'\0')
                                hAvatar = LoadAvatarIcon(avatarUrl);
                        }

                        // Downloading may span a lock event or a newer queued message.
                        const bool locked = IsWorkstationLocked();
                        const bool nowForeground = IsTargetForeground();
                        AcquireSRWLockExclusive(&g_notificationLock);
                        const bool superseded = g_pendingNotificationValid;
                        const bool cancelled = np.generation != g_notificationGeneration;
                        if (locked && !superseded && !cancelled && !nowForeground)
                        {
                            g_pendingNotification = np;
                            g_pendingNotificationValid = true;
                        }
                        ReleaseSRWLockExclusive(&g_notificationLock);
                        if (InterlockedCompareExchange(&g_displayOff, 0, 0) ||
                            locked || superseded || cancelled || nowForeground ||
                            GetTickCount() - np.queuedAt > 6000)
                            continue;

                        // 每次只保留同一个托盘图标，新的消息替换旧的气泡。
                        nid.hIcon = hIconTray;
                        nid.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE | NIF_STATE;
                        nid.dwState = NIS_HIDDEN;
                        nid.dwStateMask = NIS_HIDDEN;
                        const bool alreadyAdded = iconAdded;
                        if (iconAdded || Shell_NotifyIconW(NIM_ADD, &nid))
                        {
                            iconAdded = true;
                            OutputDebugPrintf("[Toast] NIM_ADD success");

                            nid.uVersion = NOTIFYICON_VERSION_4;
                            if (!alreadyAdded && !Shell_NotifyIconW(NIM_SETVERSION, &nid))
                            {
                                OutputDebugPrintf("[Toast] NIM_SETVERSION failed: %lu", GetLastError());
                            }

                            nid.uFlags = NIF_INFO | NIF_REALTIME;
                            nid.szInfo[0] = L'\0';
                            if (alreadyAdded)
                                Shell_NotifyIconW(NIM_MODIFY, &nid);
                            wcsncpy_s(nid.szInfoTitle,
                                sizeof(nid.szInfoTitle) / sizeof(nid.szInfoTitle[0]),
                                np.from[0] ? np.from : L"新消息", _TRUNCATE);
                            wcsncpy_s(nid.szInfo,
                                sizeof(nid.szInfo) / sizeof(nid.szInfo[0]),
                                np.content, _TRUNCATE);
                            nid.dwInfoFlags = NIIF_USER | NIIF_LARGE_ICON;
                            nid.hBalloonIcon = hAvatar ? hAvatar : hIconBalloon;
                            OutputDebugPrintf("[Toast] Icon source: %s", hAvatar ? "avatar" : "fallback");

                            if (!Shell_NotifyIconW(NIM_MODIFY, &nid))
                            {
                                OutputDebugPrintf("[Toast] NIM_MODIFY failed: %lu", GetLastError());
                            }
                            else
                            {
                                displayedNotification = np;
                                displayedNotification.id = nid.uID;
                                generation = np.generation;
                                OutputDebugPrintf("[Toast] Balloon tip displayed");
                            }
                            balloonEnd = GetTickCount() + 6000;
                        }
                        else
                        {
                            OutputDebugPrintf("[Toast] NIM_ADD failed: %lu", GetLastError());
                        }
                    }
                }

                if (iconAdded && static_cast<LONG>(GetTickCount() - balloonEnd) >= 0)
                {
                    Shell_NotifyIconW(NIM_DELETE, &nid);
                    iconAdded = false;
                }

            }

            MSG message = {};
            while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE))
            {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }

            HANDLE event = g_notificationEvent;
            if (event)
            {
                MsgWaitForMultipleObjects(1, &event, FALSE, 250, QS_ALLINPUT);
            }
            else
            {
                Sleep(250);
            }
        }

    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        OutputDebugPrintf("[Toast] Exception in notification thread: 0x%X", GetExceptionCode());
    }
    if (iconAdded)
        Shell_NotifyIconW(NIM_DELETE, &nid);
    if (hAvatar)
        DestroyIcon(hAvatar);
    if (ownsBalloonIcon)
        DestroyIcon(hIconBalloon);
    if (ownsTrayIcon)
        DestroyIcon(hIconTray);
    if (hWnd)
        DestroyWindow(hWnd);
    if (SUCCEEDED(comResult))
        CoUninitialize();
    InterlockedExchange(&g_notificationWorkerRunning, 0);
    return 1;
}

static void ShowNotification(const char* from, const char* content,
    const char* avatar_url = nullptr, const char* conversation = nullptr,
    HWND chat_window = nullptr)
{
    if (IsTargetForeground())
    {
        CancelWindowsNotifications();
        return;
    }
    const bool locked = IsWorkstationLocked();

    NotificationParams np = {};
    if (conversation && strlen(conversation) < sizeof(np.conversation))
        strcpy_s(np.conversation, conversation);
    np.chatWindow = chat_window;
    np.chatThread = chat_window ? GetWindowThreadProcessId(chat_window, nullptr) : 0;

    // 转换 UTF-8 到 UTF-16
    MultiByteToWideChar(CP_UTF8, 0, from ? from : "GreenSoft", -1, np.from, 256);
    MultiByteToWideChar(CP_UTF8, 0, content ? content : "New Message", -1, np.content, 512);
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        avatar_url ? avatar_url : "", -1, np.avatarUrl, _countof(np.avatarUrl)))
        np.avatarUrl[0] = L'\0';

    bool startWorker = false;
    HANDLE event = nullptr;
    AcquireSRWLockExclusive(&g_notificationLock);
    if (InterlockedCompareExchange(&g_displayOff, 0, 0))
    {
        ReleaseSRWLockExclusive(&g_notificationLock);
        return;
    }
    const DWORD now = GetTickCount();
    np.queuedAt = now;
    np.generation = g_notificationGeneration;
    if (!locked && now - g_LastNotifyTime < 3000)
    {
        ReleaseSRWLockExclusive(&g_notificationLock);
        return;
    }
    if (!locked)
        g_LastNotifyTime = now;
    g_pendingNotification = np;
    g_pendingNotificationValid = true;
    if (g_notificationEvent == nullptr)
        g_notificationEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    event = g_notificationEvent;
    if (event && InterlockedCompareExchange(&g_notificationWorkerRunning, 1, 0) == 0)
        startWorker = true;

    if (startWorker)
    {
        HANDLE hThread = CreateThread(nullptr, 0, NotificationThread, nullptr, 0, nullptr);
        if (hThread)
        {
            CloseHandle(hThread);
            OutputDebugPrintf("[Toast] Notification thread created (single worker)");
        }
        else
        {
            InterlockedExchange(&g_notificationWorkerRunning, 0);
            OutputDebugPrintf("[Toast] CreateThread failed: %lu", GetLastError());
        }
    }
    ReleaseSRWLockExclusive(&g_notificationLock);

    if (event)
        SetEvent(event);
}

using ShellNotifyIconWFunc = BOOL (WINAPI *)(DWORD, PNOTIFYICONDATAW);
static ShellNotifyIconWFunc g_originalShellNotifyIconW = nullptr;
static thread_local bool g_insideShellNotifyHook = false;

using FlashWindowExFunc = BOOL (WINAPI *)(PFLASHWINFO);
using FlashWindowFunc = BOOL (WINAPI *)(HWND, BOOL);
static FlashWindowExFunc g_originalFlashWindowEx = nullptr;
static FlashWindowFunc g_originalFlashWindow = nullptr;

using CreateProcessWFn = BOOL (WINAPI *)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
using CreateProcessAFn = BOOL (WINAPI *)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
using ShellExecuteExWFn = BOOL (WINAPI *)(SHELLEXECUTEINFOW *);
using ShellExecuteWFn = HINSTANCE (WINAPI *)(HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT);
using ShowWindowFn = BOOL (WINAPI *)(HWND, int);
using SetWindowPosFn = BOOL (WINAPI *)(HWND, HWND, int, int, int, int, UINT);
static CreateProcessWFn g_originalCreateProcessW = nullptr;
static CreateProcessAFn g_originalCreateProcessA = nullptr;
static ShellExecuteExWFn g_originalShellExecuteExW = nullptr;
static ShellExecuteWFn g_originalShellExecuteW = nullptr;
static ShowWindowFn g_originalShowWindow = nullptr;
static SetWindowPosFn g_originalSetWindowPos = nullptr;

extern "C" bool ShouldBlockUpdateWindowShow(HWND hwnd);

static bool IsWindowShowCommand(int nCmdShow)
{
    switch (nCmdShow)
    {
    case SW_HIDE:
    case SW_MINIMIZE:
    case SW_SHOWMINIMIZED:
    case SW_SHOWMINNOACTIVE:
    case SW_FORCEMINIMIZE:
        return false;
    default:
        return true;
    }
}

static void LogBlockedWindowApi(const char *api, HWND hwnd, const void *ret)
{
    HMODULE target = GetModuleHandleW(target_app::ModuleName().c_str());
    if (target != nullptr)
    {
        auto *base = reinterpret_cast<uint8_t *>(target);
        auto *dos = reinterpret_cast<IMAGE_DOS_HEADER *>(base);
        auto *nt = reinterpret_cast<IMAGE_NT_HEADERS64 *>(base + dos->e_lfanew);
        auto *end = base + nt->OptionalHeader.SizeOfImage;
        auto *p = reinterpret_cast<const uint8_t *>(ret);
        if (p >= base && p < end)
        {
            OutputDebugPrintf("[Hook] Blocked %s hwnd=%p module_rva=0x%X",
                api, hwnd, (unsigned)(p - base));
            return;
        }
    }
    OutputDebugPrintf("[Hook] Blocked %s hwnd=%p ret=%p", api, hwnd, ret);
}

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
    wchar_t *title, size_t titleCount, wchar_t *body, size_t bodyCount,
    NOTIFYICONDATAW &copy)
{
    if (data == nullptr || title == nullptr || body == nullptr)
        return false;

    __try
    {
        if (!(data->uFlags & NIF_INFO))
            return false;
        memcpy(&copy, data, (std::min)(static_cast<size_t>(data->cbSize), sizeof(copy)));
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
    std::string &from, std::string &content, NOTIFYICONDATAW &copy)
{
    wchar_t title[sizeof(data->szInfoTitle) / sizeof(wchar_t)] = {};
    wchar_t body[sizeof(data->szInfo) / sizeof(wchar_t)] = {};
    if (!CopyShellNotification(data, title, _countof(title), body, _countof(body), copy))
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
        if (descriptor->OriginalFirstThunk == 0)
            continue;
        if (dllName != nullptr && _stricmp(name, dllName) != 0)
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
        if (dllName != nullptr && _stricmp(name, dllName) != 0)
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
    NOTIFYICONDATAW copy = {};
    const bool capture = !g_insideShellNotifyHook &&
        (message == NIM_ADD || message == NIM_MODIFY) &&
        CaptureShellNotification(data, from, content, copy);
    if (capture)
        copy.uFlags &= ~(NIF_INFO | NIF_REALTIME);

    BOOL result = g_originalShellNotifyIconW != nullptr
        ? g_originalShellNotifyIconW(message, capture ? &copy : data)
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
    CONTEXT hook_context;
    RtlCaptureContext(&hook_context);
    const uintptr_t return_address = reinterpret_cast<uintptr_t>(_ReturnAddress());
    ObserveFlashWindowEx(return_address, pfwi, &hook_context);

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

    if (!g_displayNotification)
    {
        static DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS subscription = { DisplayPowerChanged, nullptr };
        const DWORD result = PowerSettingRegisterNotification(&g_sessionDisplayStatus,
            DEVICE_NOTIFY_CALLBACK, &subscription, &g_displayNotification);
        if (result != ERROR_SUCCESS)
            OutputDebugPrintf("[Toast] Display power registration failed: %lu", result);
    }

    if (g_originalShellNotifyIconW == nullptr)
    {
        HMODULE shell32 = GetModuleHandleA("SHELL32.dll");
        if (shell32 != nullptr)
            g_originalShellNotifyIconW = reinterpret_cast<ShellNotifyIconWFunc>(
                GetProcAddress(shell32, "Shell_NotifyIconW"));
    }

    bool success = false;
    bool flashExReady = false;
    HMODULE modules[] = { GetModuleHandleA(nullptr),
        GetModuleHandleW(target_app::ModuleName().c_str()) };
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
            flashExReady = g_originalFlashWindowEx != nullptr;
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
    return flashExReady;
}

static bool ContainsTextW(const wchar_t *text, const std::wstring &needle)
{
    const size_t length = needle.size();
    for (const wchar_t *cursor = text; *cursor; ++cursor)
    {
        if (_wcsnicmp(cursor, needle.c_str(), length) == 0)
            return true;
    }
    return false;
}

static bool TextLooksLikeUpdaterW(const wchar_t *text)
{
    if (text == nullptr || text[0] == L'\0')
        return false;
    return ContainsTextW(text, target_app::UpdaterProcessName()) ||
           ContainsTextW(text, target_app::LegacyUpdaterProcessName());
}

static bool ContainsTextA(const char *text, const std::string &needle)
{
    const size_t length = needle.size();
    for (const char *cursor = text; *cursor; ++cursor)
    {
        if (_strnicmp(cursor, needle.c_str(), length) == 0)
            return true;
    }
    return false;
}

static bool TextLooksLikeUpdaterA(const char *text)
{
    if (text == nullptr || text[0] == '\0')
        return false;
    return ContainsTextA(text, target_app::UpdaterProcessNameNarrow()) ||
           ContainsTextA(text, target_app::LegacyUpdaterProcessNameNarrow());
}

static BOOL WINAPI HookedCreateProcessW(
    LPCWSTR application, LPWSTR commandLine, LPSECURITY_ATTRIBUTES processAttributes,
    LPSECURITY_ATTRIBUTES threadAttributes, BOOL inheritHandles, DWORD creationFlags,
    LPVOID environment, LPCWSTR currentDirectory, LPSTARTUPINFOW startupInfo,
    LPPROCESS_INFORMATION processInformation)
{
    if (TextLooksLikeUpdaterW(application) || TextLooksLikeUpdaterW(commandLine))
    {
        if (processInformation != nullptr)
            ZeroMemory(processInformation, sizeof(*processInformation));
        SetLastError(ERROR_FILE_NOT_FOUND);
        OutputDebugPrintf("[Hook] Blocked CreateProcessW updater");
        return FALSE;
    }
    return g_originalCreateProcessW != nullptr
        ? g_originalCreateProcessW(application, commandLine, processAttributes, threadAttributes,
            inheritHandles, creationFlags, environment, currentDirectory, startupInfo, processInformation)
        : FALSE;
}

static BOOL WINAPI HookedCreateProcessA(
    LPCSTR application, LPSTR commandLine, LPSECURITY_ATTRIBUTES processAttributes,
    LPSECURITY_ATTRIBUTES threadAttributes, BOOL inheritHandles, DWORD creationFlags,
    LPVOID environment, LPCSTR currentDirectory, LPSTARTUPINFOA startupInfo,
    LPPROCESS_INFORMATION processInformation)
{
    if (TextLooksLikeUpdaterA(application) || TextLooksLikeUpdaterA(commandLine))
    {
        if (processInformation != nullptr)
            ZeroMemory(processInformation, sizeof(*processInformation));
        SetLastError(ERROR_FILE_NOT_FOUND);
        OutputDebugPrintf("[Hook] Blocked CreateProcessA updater");
        return FALSE;
    }
    return g_originalCreateProcessA != nullptr
        ? g_originalCreateProcessA(application, commandLine, processAttributes, threadAttributes,
            inheritHandles, creationFlags, environment, currentDirectory, startupInfo, processInformation)
        : FALSE;
}

static BOOL WINAPI HookedShellExecuteExW(SHELLEXECUTEINFOW *info)
{
    if (info != nullptr && (TextLooksLikeUpdaterW(info->lpFile) || TextLooksLikeUpdaterW(info->lpParameters)))
    {
        SetLastError(ERROR_FILE_NOT_FOUND);
        OutputDebugPrintf("[Hook] Blocked ShellExecuteExW updater");
        return FALSE;
    }
    return g_originalShellExecuteExW != nullptr ? g_originalShellExecuteExW(info) : FALSE;
}

static HINSTANCE WINAPI HookedShellExecuteW(
    HWND hwnd, LPCWSTR operation, LPCWSTR file, LPCWSTR parameters, LPCWSTR directory, INT show)
{
    if (TextLooksLikeUpdaterW(file) || TextLooksLikeUpdaterW(parameters))
    {
        SetLastError(ERROR_FILE_NOT_FOUND);
        OutputDebugPrintf("[Hook] Blocked ShellExecuteW updater");
        return (HINSTANCE)(ULONG_PTR)SE_ERR_FNF;
    }
    return g_originalShellExecuteW != nullptr
        ? g_originalShellExecuteW(hwnd, operation, file, parameters, directory, show)
        : (HINSTANCE)(ULONG_PTR)SE_ERR_FNF;
}

static BOOL WINAPI HookedShowWindow(HWND hwnd, int nCmdShow)
{
    if (IsWindowShowCommand(nCmdShow) && ShouldBlockUpdateWindowShow(hwnd))
    {
        LogBlockedWindowApi("ShowWindow", hwnd, _ReturnAddress());
        if (g_originalShowWindow != nullptr)
            g_originalShowWindow(hwnd, SW_HIDE);
        return TRUE;
    }
    return g_originalShowWindow != nullptr ? g_originalShowWindow(hwnd, nCmdShow) : FALSE;
}

static BOOL WINAPI HookedSetWindowPos(
    HWND hwnd, HWND insertAfter, int x, int y, int cx, int cy, UINT flags)
{
    if ((flags & SWP_SHOWWINDOW) != 0 && (flags & SWP_HIDEWINDOW) == 0
        && ShouldBlockUpdateWindowShow(hwnd))
    {
        LogBlockedWindowApi("SetWindowPos", hwnd, _ReturnAddress());
        flags = (flags & ~SWP_SHOWWINDOW) | SWP_HIDEWINDOW;
    }
    return g_originalSetWindowPos != nullptr
        ? g_originalSetWindowPos(hwnd, insertAfter, x, y, cx, cy, flags)
        : FALSE;
}

static bool HookNamedImport(HMODULE module, const char *functionName, void *replacement, void **original)
{
    bool hooked = HookIatEntry(module, nullptr, functionName, replacement, original);
    if (HookDelayIatEntry(module, nullptr, functionName, replacement, original))
        hooked = true;
    return hooked;
}

bool InitUpdateIatHook()
{
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE shell32 = GetModuleHandleA("shell32.dll");
    HMODULE user32 = GetModuleHandleA("user32.dll");
    if (g_originalCreateProcessW == nullptr && kernel32 != nullptr)
        g_originalCreateProcessW = reinterpret_cast<CreateProcessWFn>(
            GetProcAddress(kernel32, "CreateProcessW"));
    if (g_originalCreateProcessA == nullptr && kernel32 != nullptr)
        g_originalCreateProcessA = reinterpret_cast<CreateProcessAFn>(
            GetProcAddress(kernel32, "CreateProcessA"));
    if (g_originalShellExecuteExW == nullptr && shell32 != nullptr)
        g_originalShellExecuteExW = reinterpret_cast<ShellExecuteExWFn>(
            GetProcAddress(shell32, "ShellExecuteExW"));
    if (g_originalShellExecuteW == nullptr && shell32 != nullptr)
        g_originalShellExecuteW = reinterpret_cast<ShellExecuteWFn>(
            GetProcAddress(shell32, "ShellExecuteW"));
    if (g_originalShowWindow == nullptr && user32 != nullptr)
        g_originalShowWindow = reinterpret_cast<ShowWindowFn>(
            GetProcAddress(user32, "ShowWindow"));
    if (g_originalSetWindowPos == nullptr && user32 != nullptr)
        g_originalSetWindowPos = reinterpret_cast<SetWindowPosFn>(
            GetProcAddress(user32, "SetWindowPos"));

    HMODULE modules[256] = {};
    int count = 0;
    modules[count++] = GetModuleHandleA(nullptr);
    modules[count++] = GetModuleHandleW(target_app::ModuleName().c_str());

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me))
        {
            do
            {
                if (count >= 256)
                    break;
                if (_wcsicmp(me.szModule, target_app::ExecutableName().c_str()) != 0
                    && _wcsicmp(me.szModule, target_app::ModuleName().c_str()) != 0
                    && _wcsnicmp(me.szModule, L"Qt", 2) != 0)
                    continue;
                bool seen = false;
                for (int i = 0; i < count; ++i)
                {
                    if (modules[i] == me.hModule)
                    {
                        seen = true;
                        break;
                    }
                }
                if (!seen)
                    modules[count++] = me.hModule;
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
    }

    bool success = false;
    bool showReady = false;
    bool positionReady = false;
    for (int i = 0; i < count; ++i)
    {
        HMODULE module = modules[i];
        if (module == nullptr)
            continue;

        void *originalW = reinterpret_cast<void *>(g_originalCreateProcessW);
        if (HookNamedImport(module, "CreateProcessW",
            reinterpret_cast<void *>(HookedCreateProcessW), &originalW))
        {
            success = true;
            if (originalW != nullptr && originalW != reinterpret_cast<void *>(HookedCreateProcessW))
                g_originalCreateProcessW = reinterpret_cast<CreateProcessWFn>(originalW);
        }

        void *originalA = reinterpret_cast<void *>(g_originalCreateProcessA);
        if (HookNamedImport(module, "CreateProcessA",
            reinterpret_cast<void *>(HookedCreateProcessA), &originalA))
        {
            success = true;
            if (originalA != nullptr && originalA != reinterpret_cast<void *>(HookedCreateProcessA))
                g_originalCreateProcessA = reinterpret_cast<CreateProcessAFn>(originalA);
        }

        void *originalEx = reinterpret_cast<void *>(g_originalShellExecuteExW);
        if (HookNamedImport(module, "ShellExecuteExW",
            reinterpret_cast<void *>(HookedShellExecuteExW), &originalEx))
        {
            success = true;
            if (originalEx != nullptr && originalEx != reinterpret_cast<void *>(HookedShellExecuteExW))
                g_originalShellExecuteExW = reinterpret_cast<ShellExecuteExWFn>(originalEx);
        }

        void *originalSh = reinterpret_cast<void *>(g_originalShellExecuteW);
        if (HookNamedImport(module, "ShellExecuteW",
            reinterpret_cast<void *>(HookedShellExecuteW), &originalSh))
        {
            success = true;
            if (originalSh != nullptr && originalSh != reinterpret_cast<void *>(HookedShellExecuteW))
                g_originalShellExecuteW = reinterpret_cast<ShellExecuteWFn>(originalSh);
        }

        void *originalShow = reinterpret_cast<void *>(g_originalShowWindow);
        if (HookNamedImport(module, "ShowWindow",
            reinterpret_cast<void *>(HookedShowWindow), &originalShow))
        {
            showReady = true;
            if (originalShow != nullptr && originalShow != reinterpret_cast<void *>(HookedShowWindow))
                g_originalShowWindow = reinterpret_cast<ShowWindowFn>(originalShow);
        }

        void *originalPos = reinterpret_cast<void *>(g_originalSetWindowPos);
        if (HookNamedImport(module, "SetWindowPos",
            reinterpret_cast<void *>(HookedSetWindowPos), &originalPos))
        {
            positionReady = true;
            if (originalPos != nullptr && originalPos != reinterpret_cast<void *>(HookedSetWindowPos))
                g_originalSetWindowPos = reinterpret_cast<SetWindowPosFn>(originalPos);
        }
    }

    if (success)
        OutputDebugPrintf("[Hook] Update CreateProcess/ShellExecute IAT hooked");
    OutputDebugPrintf("[Hook] Update pre-show hooks: ShowWindow=%d SetWindowPos=%d", showReady, positionReady);
    return success && showReady && positionReady;
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

extern "C" __declspec(dllexport) void SendWindowsNotificationWithAvatar(
    const char* from, const char* content, const char* avatar_url)
{
    ShowNotification(from, content, avatar_url);
}

extern "C" __declspec(dllexport) void SendWindowsNotificationForChat(
    const char* from, const char* content, const char* avatar_url,
    const char* conversation, HWND chat_window)
{
    ShowNotification(from, content, avatar_url, conversation, chat_window);
}
