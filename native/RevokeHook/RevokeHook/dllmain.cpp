#include "framework.h"
#include <wincrypt.h>

#include <tchar.h>
#include <cstdint>
#include <string>
#include <vector>
#include <chrono>
#include <random>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <wchar.h>
#include <fstream>
#include "vehbp.h"
#include "revoke_tip.h"
#include <TlHelp32.h> 

//用于计算MD5
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")

//打印日志
static HANDLE g_hLogFile = INVALID_HANDLE_VALUE;

// Balloon notification bridge
extern "C" void SendWindowsNotification(const char* from_utf8, const char* content_utf8);
bool InitNotifyIatHook();
extern "C" void ObserveFlashWindowEx(uintptr_t return_address, const FLASHWINFO *flash_info);
static void SendWindowsNotification(const std::string &from, const std::string &content);

//VEH + INT3断点
static void* g_bpDelMsg = nullptr;
static void* g_bpAdd2DB = nullptr;
static void* g_bpAdd2DBTarget = nullptr;

static DWORD g_tlsThreadState = TLS_OUT_OF_INDEXES;
struct FlashCallerState
{
    uint64_t callsite;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t r8;
    uint64_t r9;
    uint64_t rax;
    uint64_t rbx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r14;
    uint64_t r15;
    uint64_t rsp;
    DWORD tick;
    uint8_t valid;
    uint8_t dumped;
};

struct ThreadState
{
    uint8_t last_org_srvid[8];      //真实的srvid 防止插入两条撤回提醒
    uint8_t anti_revoke_cur_msg;    //是否防撤回当前这条消息
    char pending_content[512];      // DelMsg.RDX+0x1A0 原文 / [图片] 等, 同线程带给 Add2DB
    FlashCallerState flash_caller;
    uint64_t pending_notify_msg;
    uint64_t pending_notify_content_arg;
    DWORD pending_notify_tick;
    uint8_t pending_notify_valid;
    uint8_t suppress_next_notify;
    char pending_notify_from[256];
    char pending_notify_content[1024];
    // 诊断转储去重：同一消息对象可能触发多次 UI 闪烁，只转储一次。
    uint64_t notify_dump_seen[32];
    uint8_t notify_dump_seen_count;
};

static constexpr int kMaxFlashCallerBreakpoints = 8;
static void *g_bpFlashCaller[kMaxFlashCallerBreakpoints] = {};
static int g_bpFlashCallerCount = 0;
static volatile LONG g_flashCallerDiscovery = 0;

static ThreadState* GetThreadState()
{
    if (g_tlsThreadState == TLS_OUT_OF_INDEXES)
        return nullptr;

    ThreadState* state = reinterpret_cast<ThreadState*>(TlsGetValue(g_tlsThreadState));
    if (state != nullptr)
        return state;

    state = reinterpret_cast<ThreadState*>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ThreadState)));
    if (state == nullptr)
        return nullptr;

    if (!TlsSetValue(g_tlsThreadState, state))
    {
        HeapFree(GetProcessHeap(), 0, state);
        return nullptr;
    }

    return state;
}

static void FreeCurrentThreadState()
{
    if (g_tlsThreadState == TLS_OUT_OF_INDEXES)
        return;

    ThreadState* state = reinterpret_cast<ThreadState*>(TlsGetValue(g_tlsThreadState));
    if (state != nullptr)
    {
        HeapFree(GetProcessHeap(), 0, state);
        TlsSetValue(g_tlsThreadState, nullptr);
    }
}

static bool InitThreadStateTls()
{
    if (g_tlsThreadState != TLS_OUT_OF_INDEXES)
        return true;

    g_tlsThreadState = TlsAlloc();
    return g_tlsThreadState != TLS_OUT_OF_INDEXES;
}

static void UninitThreadStateTls()
{
    FreeCurrentThreadState();

    if (g_tlsThreadState != TLS_OUT_OF_INDEXES)
    {
        TlsFree(g_tlsThreadState);
        g_tlsThreadState = TLS_OUT_OF_INDEXES;
    }
}

//配置信息
struct BASICINFO
{
    uint64_t imgbase;           // Weixin.dll的基址
	uint64_t add2db_offset;     // 将撤回消息添加到数据库的函数偏移
	uint64_t delmsg_offset;     // 删除要撤回消息函数的偏移
};

struct DELMSGINFO
{
    bool initialized;
    int arg_msg_index;      // 哪个参数(2/3/4)指向包含revoke_xml的结构体
    int offset_revoke_xml;  // StdString在结构体中的偏移
    int arg_notify_index;   // 哪个参数是notify标志(值为0的那个)
};

struct ADD2DBINFO
{
    bool initialized;
    int arg_msg_index;      // 消息结构体参数, 当前 4.1.9 为 3 (R8)
    int arg_bool_index;     // 允许新 srvid 的 bool, Config2 为 5 ([rsp+0x20])
    int offset_srvid;       // srvid在消息结构体中的偏移
    int offset_revoke_xml;  // revoke_xml StdString 偏移
};

struct CONFIGINFO
{
	BASICINFO basic_info;
	DELMSGINFO delmsg_info;
	ADD2DBINFO add2db_info;
}g_config_info;

//std::string的内存布局
struct StdString
{
    const char data_ptr[16];
    int64_t size;
    int64_t capability;
};

bool g_anti_revoke_self_msg = false; //是否防止自己撤回消息
bool g_output_debeug_msg = false; //是否输出调试信息
std::string g_tip_phrase = revoke_tip::kDefaultPhrase;
bool g_block_update = false;
bool g_notify_new_message = false; //是否通知新消息
// 新消息诊断：在 debug 日志中转储 Add2DB 收到的消息对象字段。
// 该开关只读内存，不会修改微信对象；用于定位不同消息类型的正文偏移。
bool g_notify_dump_all = false;
std::string g_notify_probe_text = "__WA_NOTIFY_PROBE_7F3A__";
static volatile LONG g_stopUpdateBlocker = 0;

static wchar_t g_selfDir[MAX_PATH] = {};

// 启动器 CreateFileMapping 写入，DLL 在 DllMain 里读完即可；名称与 C# Injector 约定一致。
static const wchar_t kRuntimeMapName[] = L"Local\\WeChatAntiRecall.Runtime.v1";
static const uint32_t kRuntimeMagic = 0x31524857u; // WHR1

#pragma pack(push, 1)
struct RuntimeOffsets
{
    uint32_t magic;
    int32_t del_msg_offset;
    int32_t add2db_offset;
};
#pragma pack(pop)

#define OUT_DEBUG_BUF_LEN   1024

static void LogLine(const char *text)
{
    if (text == nullptr || text[0] == '\0')
        return;
    OutputDebugStringA(text);
    if (g_hLogFile != INVALID_HANDLE_VALUE)
    {
        DWORD written = 0;
        WriteFile(g_hLogFile, text, (DWORD)strlen(text), &written, nullptr);
        WriteFile(g_hLogFile, "\n", 1, &written, nullptr);
    }
}

void OutputDebugPrintf(const char* strOutputString, ...)
{
    if (!g_output_debeug_msg) return;

    char strBuffer[OUT_DEBUG_BUF_LEN] = { 0 };
    va_list vlArgs;
    va_start(vlArgs, strOutputString);
    _vsnprintf_s(strBuffer, sizeof(strBuffer) - 1, strOutputString, vlArgs);  //_vsnprintf_s  _vsnprintf
    va_end(vlArgs);
    OutputDebugStringA(strBuffer);  //OutputDebugString    // OutputDebugStringW

	// 同时写入到文件log中
    if (g_hLogFile != INVALID_HANDLE_VALUE)
    {
        DWORD dwWritten = 0;
		strBuffer[strlen(strBuffer)] = '\n';  // 添加换行符
        WriteFile(g_hLogFile, strBuffer, (DWORD)strlen(strBuffer), &dwWritten, NULL);
    }
}

/**
 * @brief 计算字节数据的MD5值.
 * @param data 要计算的数据
 * @return MD5 16位
 */
std::vector<uint8_t> CalculateMD5(const std::vector<uint8_t>& data) {
    // 获取加密上下文
    HCRYPTPROV hCryptProv = NULL;
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return {};
    }

    // 创建MD5哈希对象
    HCRYPTPROV hHash = NULL;
    if (!CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hCryptProv, 0);
        return {};
    }

    // 输入数据
    if (!CryptHashData(hHash, data.data(), data.size(), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return {};
    }

    //获取哈希值大小
    DWORD cbHashSize = 0, dwCount = sizeof(DWORD);
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&cbHashSize, &dwCount, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return {};
    }

    // 获取哈希值
    std::vector<uint8_t> md5Hash(cbHashSize);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, reinterpret_cast<BYTE*>(&md5Hash[0]), &cbHashSize, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return {};
    }

    // 清理
    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);

    //取中间8个字节
    auto middle_start = md5Hash.begin() + 4;    //从第5个字节开始
    auto middle_end = middle_start + 8;         //取8个字节
    std::vector<uint8_t> md5Hash16(middle_start, middle_end);
    return md5Hash16;
}

/**
 * @brief 使用MD5计算出一个唯一的正数.
 * @return 字节序列
 */
std::vector<uint8_t> GetUniquePositiveValue()
{
    // 获取当前时间戳(毫秒级别)
    auto currentTime = std::chrono::high_resolution_clock::now().time_since_epoch().count();

    // 生成一个随机数(加盐)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    uint8_t randomValue = dis(gen);

    std::vector<uint8_t> uniqueData;//要MD5的数据
    uniqueData.push_back(static_cast<uint8_t>(currentTime & 0xFF));
    uniqueData.push_back(static_cast<uint8_t>((currentTime >> 8) & 0xFF));
    uniqueData.push_back(static_cast<uint8_t>((currentTime >> 16) & 0xFF));
    uniqueData.push_back(static_cast<uint8_t>((currentTime >> 24) & 0xFF));
    uniqueData.push_back(static_cast<uint8_t>((currentTime >> 32) & 0xFF));
    uniqueData.push_back(static_cast<uint8_t>((currentTime >> 40) & 0xFF));
    uniqueData.push_back(randomValue);//加盐确保唯一

    std::vector<uint8_t> md5Result = CalculateMD5(uniqueData);
    if (md5Result.size() == 0) return {};

    //将0x123456第一个字节的最高位变为0, 确保是正数, 小端序实际存储中是最后一个字节
    uint8_t littleEndByte = md5Result.back();
    md5Result.back() = littleEndByte & 0x7F;// 0111 1111
    return md5Result;
}

static bool InitSelfDir()
{
    if (g_selfDir[0] != L'\0')
        return true;

    HMODULE self = NULL;
    if (!GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)&InitSelfDir, &self))
        return false;

    wchar_t mod[MAX_PATH] = {};
    DWORD n = GetModuleFileNameW(self, mod, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return false;

    wchar_t *slash = wcsrchr(mod, L'\\');
    wchar_t *slashFwd = wcsrchr(mod, L'/');
    if (slashFwd != nullptr && (slash == nullptr || slashFwd > slash))
        slash = slashFwd;
    if (slash == nullptr)
        return false;

    *slash = L'\0';
    wcsncpy_s(g_selfDir, mod, _TRUNCATE);
    return g_selfDir[0] != L'\0';
}

static std::string TrimCopy(const std::string &s)
{
    size_t begin = s.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos)
        return std::string();
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(begin, end - begin + 1);
}

static std::string UnquoteYaml(std::string v)
{
    v = TrimCopy(v);
    if (v.size() >= 2 && ((v.front() == '"' && v.back() == '"') || (v.front() == '\'' && v.back() == '\'')))
        v = v.substr(1, v.size() - 2);
    return v;
}

static bool ParseYamlBool(const std::string &value)
{
    return value == "1" || value == "true" || value == "True" || value == "TRUE"
        || value == "yes" || value == "Yes" || value == "on" || value == "ON";
}

static bool LoadYamlSettings(const wchar_t *path)
{
    std::ifstream in(path);
    if (!in)
        return false;

    std::string line;
    while (std::getline(in, line))
    {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        std::string trimmed = TrimCopy(line);
        if (trimmed.empty() || trimmed[0] == '#' || trimmed[0] == ';')
            continue;

        size_t colon = trimmed.find(':');
        if (colon == std::string::npos || colon == 0)
            continue;

        std::string key = TrimCopy(trimmed.substr(0, colon));
        std::string val = UnquoteYaml(trimmed.substr(colon + 1));
        if (key == "tip_phrase")
        {
            if (!val.empty())
                g_tip_phrase = revoke_tip::sanitizedPhrase(val);
        }
        else if (key == "anti_revoke_self")
        {
            g_anti_revoke_self_msg = ParseYamlBool(val);
        }
        else if (key == "block_update")
        {
            g_block_update = ParseYamlBool(val);
        }
        else if (key == "debug")
        {
            g_output_debeug_msg = ParseYamlBool(val);
        }
        else if (key == "notify_new_message")
        {
            g_notify_new_message = ParseYamlBool(val);
        }
        else if (key == "notify_dump_all")
        {
            g_notify_dump_all = ParseYamlBool(val);
        }
        else if (key == "notify_probe_text")
        {
            // 诊断标记只作为查找字符串使用，空值表示关闭标记匹配。
            g_notify_probe_text = val;
        }
    }
    return true;
}

static bool LoadRuntimeOffsets()
{
    HANDLE map = OpenFileMappingW(FILE_MAP_READ, FALSE, kRuntimeMapName);
    if (map == nullptr)
        return false;

    auto *view = reinterpret_cast<RuntimeOffsets *>(
        MapViewOfFile(map, FILE_MAP_READ, 0, 0, sizeof(RuntimeOffsets)));
    bool ok = false;
    if (view != nullptr
        && view->magic == kRuntimeMagic
        && view->del_msg_offset != 0
        && view->add2db_offset != 0)
    {
        g_config_info.basic_info.delmsg_offset = (uint32_t)view->del_msg_offset;
        g_config_info.basic_info.add2db_offset = (uint32_t)view->add2db_offset;
        ok = true;
    }
    if (view != nullptr)
        UnmapViewOfFile(view);
    CloseHandle(map);
    return ok;
}

static void KillWeixinUpdateOnce()
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe))
    {
        do
        {
            if (_wcsicmp(pe.szExeFile, L"WeixinUpdate.exe") == 0)
            {
                HANDLE proc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (proc != nullptr)
                {
                    TerminateProcess(proc, 0);
                    CloseHandle(proc);
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

static DWORD WINAPI UpdateBlockerThread(LPVOID)
{
    while (InterlockedCompareExchange(&g_stopUpdateBlocker, 0, 0) == 0)
    {
        KillWeixinUpdateOnce();
        Sleep(2000);
    }
    return 0;
}

void InitLog();

/**
 * @brief 读取 DLL 同目录 config.yml，并从启动器共享内存取偏移.
 */
bool ReadExternalConfig()
{
    if (!InitSelfDir())
    {
        OutputDebugStringA("[RevokeHook] Get module directory failed");
        return false;
    }

    wchar_t yml[MAX_PATH] = {};
    _snwprintf_s(yml, _TRUNCATE, L"%s\\config.yml", g_selfDir);
    if (!LoadYamlSettings(yml))
    {
        OutputDebugStringA("[RevokeHook] Not Find config.yml!");
        return false;
    }

    if (g_output_debeug_msg)
        InitLog();

    if (!LoadRuntimeOffsets())
    {
        OutputDebugStringA("[RevokeHook] Runtime offsets mapping missing!");
        return false;
    }

    HMODULE weixin_dll_base = NULL;
    //加载当前dll的时候 Weixin.dll很可能还没有被加载
    for (int try_num = 0; try_num < 100; try_num++)
    {   //多次尝试 一共尝试100次 每次间隔300毫秒 即30秒
        weixin_dll_base = GetModuleHandle(_T("Weixin.dll"));
        if (weixin_dll_base != NULL)
            break;
        Sleep(300);
    }
    if (weixin_dll_base == NULL) {
        OutputDebugString(TEXT("[RevokeHook] Get Weixin.dll Base Failed!"));
        return false;
	}

	g_config_info.basic_info.imgbase = (uint64_t)weixin_dll_base;

    OutputDebugPrintf("[RevokeHook] Use config: %ls  DelMsg=0x%X Add2DB=0x%X",
        yml,
        (unsigned)g_config_info.basic_info.delmsg_offset,
        (unsigned)g_config_info.basic_info.add2db_offset);
    return true;
}

/**
 * @brief 获取第index个参数的值.
 * 
 * @param ctx 上下文信息
 * @param index 第几个参数, 从1开始
 * @return 寄存器/栈上的值
 */
uint64_t GetArgValue(PCONTEXT ctx, int index)
{
    uint64_t* stack_args;
    if (ctx == NULL || index <= 0)
    {
        return 0;
    }

    switch (index)
    {
    case 1:
        return ctx->Rcx;
    case 2:
        return ctx->Rdx;
    case 3:
        return ctx->R8;
    case 4:
        return ctx->R9;
    default:
        /*
         * MSVC x64 调用约定:
         * [RSP + 0x00] = shadow space slot 1
         * [RSP + 0x08] = shadow space slot 2
         * [RSP + 0x10] = shadow space slot 3
         * [RSP + 0x18] = shadow space slot 4
         * [RSP + 0x20] = 第5个参数
         */
        stack_args = (uint64_t*)(ctx->Rsp + 0x20);
        return stack_args[index - 5];
    }
}

int SetArgValue(PCONTEXT ctx, int index, uint64_t value)
{
    uint64_t* stack_args;

    if (ctx == NULL || index <= 0)
    {
        return 0;
    }

    switch (index)
    {
    case 1:
        ctx->Rcx = value;
        return 1;
    case 2:
        ctx->Rdx = value;
        return 1;
    case 3:
        ctx->R8 = value;
        return 1;
    case 4:
        ctx->R9 = value;
        return 1;
    default:
        stack_args = (uint64_t*)(ctx->Rsp + 0x20);
        stack_args[index - 5] = value;
        return 1;
    }
}

static bool IsMemoryReadable(const void* addr, size_t size)
{
    if (addr == nullptr || size == 0) return false;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0)
        return false;
    if (mbi.State != MEM_COMMIT)
        return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))
        return false;
    if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
        return false;

    uintptr_t region_end = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    return ((uintptr_t)addr + size) <= region_end;
}

static bool SafeReadBytes(const void *addr, void *dst, size_t n)
{
    if (dst == nullptr || n == 0 || !IsMemoryReadable(addr, n))
        return false;
    __try
    {
        memcpy(dst, addr, n);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static StdString* FindStdStringWithSig(uint64_t base_addr, size_t scan_range,
    const uint8_t* sig, size_t sig_len)
{
    if (base_addr == 0)
        return nullptr;

    for (size_t offset = 0; offset + sizeof(StdString) <= scan_range; offset += 8)
    {
        uint64_t addr = base_addr + offset;
        if (!IsMemoryReadable((void*)addr, sizeof(StdString)))
            break;

        StdString* ss = (StdString*)addr;

        if (ss->size <= 16 || ss->size > 0x10000 ||
            ss->capability < ss->size || ss->capability > 0x100000)
            continue;

        uint64_t str_addr = *((uint64_t*)(ss->data_ptr));
        if (str_addr == 0 || !IsMemoryReadable((void*)str_addr, (size_t)ss->size))
            continue;

        for (int64_t i = 0; i <= (int64_t)ss->size - (int64_t)sig_len; i++)
        {
            if (memcmp((void*)(str_addr + i), sig, sig_len) == 0)
                return ss;
        }
    }
    return nullptr;
}

static int FindZeroArgIndex(PCONTEXT ctx, int start_idx, int end_idx)
{
    // Pass 1: 64-bit == 0
    for (int i = start_idx; i <= end_idx; i++)
    {
        if (GetArgValue(ctx, i) == 0)
            return i;
    }
    // Pass 2: low 32 bits == 0 (upper 32 might be garbage)
    for (int i = start_idx; i <= end_idx; i++)
    {
        uint64_t val = GetArgValue(ctx, i);
        if (val != 0 && (val & 0xFFFFFFFF) == 0)
            return i;
    }
    // Pass 3: low byte == 0, not a user-mode pointer (stack bool with dirty high bits)
    for (int i = start_idx; i <= end_idx; i++)
    {
        uint64_t val = GetArgValue(ctx, i);
        if ((val & 0xFF) != 0)
            continue;
        if (val >= 0x10000 && val <= 0x00007FFFFFFFFFFF)
            continue;
        return i;
    }
    return -1;
}

static bool ReadMsStdString(const StdString *ss, std::string &out);

static const char *ClassifyDumpString(const std::string &value)
{
    if (revoke_tip::looksLikeMsgSource(value))
        return "msgsource";
    if (revoke_tip::looksLikeWxId(value))
        return "wxid";
    if (revoke_tip::looksLikeRevokePayload(value))
        return "revoke";
    if (value.find("<?xml") != std::string::npos || value.find("<sysmsg") != std::string::npos)
        return "xml";
    if (value.find('<') != std::string::npos)
        return "xml";
    return "plain";
}

static void SanitizeDumpValue(std::string &value)
{
    for (char &ch : value)
    {
        if (ch == '\n' || ch == '\r' || ch == '\t')
            ch = ' ';
    }
    if (value.size() > 300)
    {
        value.resize(300);
        value += "...";
    }
}

static bool MatchesNotifyProbe(const std::string &value)
{
    return !g_notify_probe_text.empty() &&
        value.find(g_notify_probe_text) != std::string::npos;
}

static void LogNotifyProbe(const char *tag, size_t offset, uint64_t storage,
    const std::string &value, const char *where)
{
    if (!MatchesNotifyProbe(value))
        return;

    std::string preview = value;
    SanitizeDumpValue(preview);
    OutputDebugPrintf(
        "[NotifyProbe] marker=[%s] %s object_offset=+0x%03X storage=%p where=%s value=[%s]",
        g_notify_probe_text.c_str(), tag, (unsigned)offset, (void *)storage,
        where ? where : "field", preview.c_str());
}

// 直接转储一个 MSVC std::string 参数（例如 Add2DB 目标函数的 R9）。
// 与对象扫描分开记录，便于确认“正文参数”是否就是用户发送的文本。
static void DumpNotifyStdString(const StdString *ss, const char *tag)
{
    if (!g_output_debeug_msg || ss == nullptr)
        return;

    StdString meta{};
    if (!SafeReadBytes(ss, &meta, sizeof(meta)))
        return;

    std::string value;
    if (!ReadMsStdString(ss, value))
    {
        OutputDebugPrintf("[NotifyDump] %s ptr=%p invalid std::string size=%lld cap=%lld",
            tag, (const void *)ss, (long long)meta.size, (long long)meta.capability);
        return;
    }

    uint64_t storage = (uint64_t)ss;
    if (meta.capability >= 16)
        memcpy(&storage, meta.data_ptr, sizeof(storage));

    std::string preview = value;
    SanitizeDumpValue(preview);
    OutputDebugPrintf(
        "[NotifyDump] %s ptr=%p storage=%p size=%lld cap=%lld class=%s value=[%s]",
        tag, (const void *)ss, (void *)storage, (long long)meta.size,
        (long long)meta.capability, ClassifyDumpString(value), preview.c_str());
    LogNotifyProbe(tag, 0, storage, value, "direct-string");
}

static void ScanNotifyProbeRaw(uint64_t base, size_t range, const char *tag)
{
    if (!g_output_debeug_msg || g_notify_probe_text.empty() || base == 0 || range == 0)
        return;

    // 仅扫描当前对象的已提交连续区域；字符串存储区由 DumpObjectStrings
    // 单独扫描，因此这里不会遍历整个进程地址空间。
    if (!IsMemoryReadable((void *)base, range))
        return;
    std::string bytes(range, '\0');
    if (!SafeReadBytes((void *)base, &bytes[0], range))
        return;
    const size_t found = bytes.find(g_notify_probe_text);
    if (found != std::string::npos)
    {
        OutputDebugPrintf("[NotifyProbe] marker=[%s] %s raw_offset=+0x%03X",
            g_notify_probe_text.c_str(), tag, (unsigned)found);
    }
}

static void DumpObjectStrings(uint64_t base, size_t range, const char *tag)
{
    if (!g_output_debeug_msg)
        return;
    if (base == 0 || range < sizeof(StdString) || !IsMemoryReadable((void *)base, 16))
        return;
    OutputDebugPrintf("[Dump] %s base=%p range=0x%X", tag, (void *)base, (unsigned)range);
    ScanNotifyProbeRaw(base, range, tag);

    static const uint32_t kMsgTypes[] = {1, 3, 34, 42, 43, 47, 48, 49, 50, 62, 10000, 10002};
    for (int off = 0x00; off <= 0x80; off += 4)
    {
        uint32_t value = 0;
        if (!SafeReadBytes((void *)(base + off), &value, 4))
            break;
        for (uint32_t type : kMsgTypes)
        {
            if (value == type)
            {
                OutputDebugPrintf("[Dump] %s +0x%02X u32=%u", tag, off, value);
                break;
            }
        }
    }

    for (size_t off = 0; off + sizeof(StdString) <= range; off += 8)
    {
        std::string value;
        StdString *ss = (StdString *)(base + off);
        if (!ReadMsStdString(ss, value) || value.empty())
            continue;
        StdString meta{};
        if (!SafeReadBytes(ss, &meta, sizeof(meta)))
            continue;
        const char *kind = ClassifyDumpString(value);
        int64_t cap = meta.capability;
        uint64_t storage = (uint64_t)ss;
        if (meta.capability >= 16)
            memcpy(&storage, meta.data_ptr, sizeof(storage));
        SanitizeDumpValue(value);
        char line[OUT_DEBUG_BUF_LEN];
        _snprintf_s(line, sizeof(line), _TRUNCATE,
            "[Dump] %s +0x%03X str storage=%p size=%lld cap=%lld class=%s: %s",
            tag, (unsigned)off, (void *)storage, (long long)meta.size,
            (long long)cap, kind, value.c_str());
        LogLine(line);
        LogNotifyProbe(tag, off, storage, value, "object-string");
    }
}

static bool LooksLikeHeapObject(uint64_t ptr)
{
    if (ptr < 0x10000 || ptr > 0x00007FFFFFFFFFFFULL)
        return false;
    if ((ptr & 7) != 0)
        return false;
    uint64_t img = g_config_info.basic_info.imgbase;
    if (img != 0 && ptr >= img && ptr < img + 0x5000000ULL)
        return false;
    return IsMemoryReadable((void *)ptr, 0x80);
}

static void DumpObjectDeep(uint64_t base, const char *tag)
{
    DumpObjectStrings(base, 0x500, tag);
    int nested = 0;
    for (size_t off = 0; off + 8 <= 0x200 && nested < 6; off += 8)
    {
        std::string occupied;
        if (off + sizeof(StdString) <= 0x200 &&
            ReadMsStdString((StdString *)(base + off), occupied) && !occupied.empty())
        {
            continue;
        }
        uint64_t child = 0;
        if (!SafeReadBytes((void *)(base + off), &child, 8))
            continue;
        if (child == base || !LooksLikeHeapObject(child))
            continue;
        char childTag[80];
        _snprintf_s(childTag, sizeof(childTag), _TRUNCATE, "%s+0x%03X", tag, (unsigned)off);
        DumpObjectStrings(child, 0x400, childTag);
        nested += 1;
    }
}

static void DumpOneDelMsgObj(uint64_t *seen, int *nseen, int maxSeen, uint64_t ptr, const char *name)
{
    if (ptr == 0 || !IsMemoryReadable((void *)ptr, 0x40))
        return;
    for (int i = 0; i < *nseen; i++)
    {
        if (seen[i] == ptr)
            return;
    }
    if (*nseen < maxSeen)
        seen[(*nseen)++] = ptr;
    DumpObjectDeep(ptr, name);
}

static bool RememberNotifyDump(ThreadState *state, uint64_t ptr)
{
    if (state == nullptr || ptr == 0)
        return false;
    for (uint8_t i = 0; i < state->notify_dump_seen_count; i++)
    {
        if (state->notify_dump_seen[i] == ptr)
            return false;
    }

    if (state->notify_dump_seen_count < _countof(state->notify_dump_seen))
    {
        state->notify_dump_seen[state->notify_dump_seen_count++] = ptr;
    }
    else
    {
        // 保留最近一批对象，避免长时间运行后数组无限增长；对象地址
        // 一般不会在同一会话内快速复用。
        memmove(state->notify_dump_seen,
            state->notify_dump_seen + 1,
            (state->notify_dump_seen_count - 1) * sizeof(state->notify_dump_seen[0]));
        state->notify_dump_seen[state->notify_dump_seen_count - 1] = ptr;
    }
    return true;
}

static void DumpNotifyPointer(ThreadState *state, uint64_t ptr, const char *tag)
{
    if (!g_output_debeug_msg || !g_notify_dump_all || ptr == 0 ||
        !LooksLikeHeapObject(ptr))
        return;
    if (!RememberNotifyDump(state, ptr))
        return;

    uint64_t seen[24] = {};
    int nseen = 0;
    DumpOneDelMsgObj(seen, &nseen, _countof(seen), ptr, tag);
}

static void DumpArgs(PCONTEXT ctx, const char *tag)
{
    OutputDebugPrintf("[Debug] %s RCX=%p RDX=%p R8=%p R9=%p RSP=%p",
        tag, (void *)ctx->Rcx, (void *)ctx->Rdx, (void *)ctx->R8, (void *)ctx->R9, (void *)ctx->Rsp);
    for (int i = 5; i <= 8; i++)
        OutputDebugPrintf("[Debug] %s arg%d=%p", tag, i, (void *)GetArgValue(ctx, i));
    uint8_t *sp = (uint8_t *)ctx->Rsp;
    if (IsMemoryReadable(sp + 0x20, 16))
    {
        OutputDebugPrintf("[Debug] %s [rsp+20] %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
            tag,
            sp[0x20], sp[0x21], sp[0x22], sp[0x23], sp[0x24], sp[0x25], sp[0x26], sp[0x27],
            sp[0x28], sp[0x29], sp[0x2A], sp[0x2B], sp[0x2C], sp[0x2D], sp[0x2E], sp[0x2F]);
    }
}

static void DumpNotifyContext(ThreadState *state, PCONTEXT ctx, const char *tag,
    bool target_has_content_arg)
{
    if (!g_output_debeug_msg || !g_notify_dump_all || state == nullptr || ctx == nullptr)
        return;

    OutputDebugPrintf(
        "[NotifyDump] %s tid=%lu RCX=%p RDX=%p R8=%p R9=%p RAX=%p RBX=%p RSI=%p RDI=%p R14=%p R15=%p RSP=%p",
        tag, (unsigned long)GetCurrentThreadId(),
        (void *)ctx->Rcx, (void *)ctx->Rdx, (void *)ctx->R8, (void *)ctx->R9,
        (void *)ctx->Rax, (void *)ctx->Rbx, (void *)ctx->Rsi, (void *)ctx->Rdi,
        (void *)ctx->R14, (void *)ctx->R15, (void *)ctx->Rsp);

    // 当前目标入口的 R9 是辅助 wxid std::string，不是正文；单独打印
    // 便于和消息对象字段对照。
    if (target_has_content_arg)
        DumpNotifyStdString((const StdString *)ctx->R9,
            "NotifyTarget.R9(auxiliary-wxid)");

    DumpNotifyPointer(state, ctx->Rcx, "NotifyDump.RCX");
    DumpNotifyPointer(state, ctx->Rdx, "NotifyDump.RDX");
    DumpNotifyPointer(state, ctx->R8, "NotifyDump.R8");
    if (!target_has_content_arg)
        DumpNotifyPointer(state, ctx->R9, "NotifyDump.R9");
    DumpNotifyPointer(state, ctx->Rax, "NotifyDump.RAX");
    DumpNotifyPointer(state, ctx->Rbx, "NotifyDump.RBX");
    DumpNotifyPointer(state, ctx->Rsi, "NotifyDump.RSI");
    DumpNotifyPointer(state, ctx->Rdi, "NotifyDump.RDI");
    DumpNotifyPointer(state, ctx->R14, "NotifyDump.R14");
    DumpNotifyPointer(state, ctx->R15, "NotifyDump.R15");

    // 记录前 8 个栈参数；其中可能包含由调用者暂存的消息对象或
    // std::string 地址。只对看起来像堆对象的值递归转储。
    uint8_t *sp = (uint8_t *)ctx->Rsp;
    for (int i = 0; i < 8; i++)
    {
        uint64_t value = 0;
        const size_t offset = 0x20 + (size_t)i * sizeof(uint64_t);
        if (!SafeReadBytes(sp + offset, &value, sizeof(value)))
            break;
        OutputDebugPrintf("[NotifyDump] %s stack+0x%02X=%p", tag,
            (unsigned)offset, (void *)value);
        char stackTag[96];
        _snprintf_s(stackTag, sizeof(stackTag), _TRUNCATE,
            "%s.stack+0x%02X", tag, (unsigned)offset);
        DumpNotifyPointer(state, value, stackTag);
    }
}

static void DumpDelMsgObjects(PCONTEXT ctx, uint64_t primary)
{
    if (!g_output_debeug_msg)
        return;
    DumpArgs(ctx, "DelMsg");
    uint64_t seen[8] = {};
    int nseen = 0;
    DumpOneDelMsgObj(seen, &nseen, 8, ctx->Rcx, "DelMsg.RCX");
    DumpOneDelMsgObj(seen, &nseen, 8, ctx->Rdx, "DelMsg.RDX");
    DumpOneDelMsgObj(seen, &nseen, 8, ctx->R8, "DelMsg.R8");
    DumpOneDelMsgObj(seen, &nseen, 8, ctx->R9, "DelMsg.R9");
    DumpOneDelMsgObj(seen, &nseen, 8, primary, "DelMsg.msg");
}

static void ForceAllowNewId(PCONTEXT ctx, int bool_index)
{
    if (bool_index > 0)
        SetArgValue(ctx, bool_index, 1);
    uint8_t *sp = (uint8_t *)ctx->Rsp;
    if (IsMemoryReadable(sp + 0x20, 1))
        sp[0x20] = 1;
}

static StdString *FindRevokePayload(uint64_t base, size_t scan_range)
{
    static const uint8_t kYiTiao[] = { 0xe4, 0xb8, 0x80, 0xe6, 0x9d, 0xa1 }; // 一条
    static const uint8_t kCheHui[] = { 0xe6, 0x92, 0xa4, 0xe5, 0x9b, 0x9e }; // 撤回
    static const uint8_t kRecalled[] = { 0x72, 0x65, 0x63, 0x61, 0x6c, 0x6c, 0x65, 0x64 };
    static const uint8_t kRevokeMsg[] = { 'r','e','v','o','k','e','m','s','g' };
    static const uint8_t kReplaceMsg[] = { 'r','e','p','l','a','c','e','m','s','g' };
    StdString *found = FindStdStringWithSig(base, scan_range, kYiTiao, sizeof(kYiTiao));
    if (found == nullptr)
        found = FindStdStringWithSig(base, scan_range, kCheHui, sizeof(kCheHui));
    if (found == nullptr)
        found = FindStdStringWithSig(base, scan_range, kRecalled, sizeof(kRecalled));
    if (found == nullptr)
        found = FindStdStringWithSig(base, scan_range, kRevokeMsg, sizeof(kRevokeMsg));
    if (found == nullptr)
        found = FindStdStringWithSig(base, scan_range, kReplaceMsg, sizeof(kReplaceMsg));
    return found;
}

static uint8_t *PeSection(HMODULE mod, const char *name, size_t *out_size)
{
    auto *dos = (IMAGE_DOS_HEADER *)mod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;
    auto *nt = (IMAGE_NT_HEADERS64 *)((uint8_t *)mod + dos->e_lfanew);
    auto *sec = IMAGE_FIRST_SECTION(nt);
    size_t nlen = strlen(name);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if (memcmp(sec[i].Name, name, nlen) == 0)
        {
            if (out_size)
                *out_size = sec[i].Misc.VirtualSize;
            return (uint8_t *)mod + sec[i].VirtualAddress;
        }
    }
    return nullptr;
}

static void OnTargetHit(PCONTEXT ctx, PEXCEPTION_RECORD pExc);
static bool CaptureNotifyMessage(uint64_t message_object, uint64_t content_arg,
    uint64_t auxiliary_object, std::string &from, std::string &content,
    bool flash_layout = false);

static bool IsFlashCallerBreakpoint(uint64_t rip)
{
    for (int i = 0; i < g_bpFlashCallerCount; i++)
    {
        if ((uint64_t)g_bpFlashCaller[i] == rip)
            return true;
    }
    return false;
}

static uint8_t *FindContainingFunction(uint8_t *img, uint8_t *address)
{
    if (img == nullptr || address == nullptr)
        return nullptr;

    auto *base = img;
    auto *dos = reinterpret_cast<IMAGE_DOS_HEADER *>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;
    auto *nt = reinterpret_cast<IMAGE_NT_HEADERS64 *>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;

    const auto &exception = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (exception.VirtualAddress == 0 || exception.Size < sizeof(RUNTIME_FUNCTION))
        return nullptr;

    const uint64_t addressRva = (uint64_t)(address - base);
    const size_t count = exception.Size / sizeof(RUNTIME_FUNCTION);
    auto *entries = reinterpret_cast<RUNTIME_FUNCTION *>(base + exception.VirtualAddress);
    for (size_t i = 0; i < count; i++)
    {
        const RUNTIME_FUNCTION &entry = entries[i];
        if (entry.BeginAddress <= addressRva && addressRva < entry.EndAddress)
            return base + entry.BeginAddress;
    }
    return nullptr;
}

static void DiscoverAdd2DBTargetBreakpoint()
{
    if (g_bpAdd2DBTarget != nullptr || g_bpAdd2DB == nullptr)
        return;

    uint8_t *site = reinterpret_cast<uint8_t *>(g_bpAdd2DB);
    if (!IsMemoryReadable(site, 5))
    {
        OutputDebugPrintf("[Add2DB] Cannot read target call site %p", site);
        return;
    }

    uint8_t *target = nullptr;
    if (site[0] == 0xE8)
    {
        int32_t rel = 0;
        memcpy(&rel, site + 1, sizeof(rel));
        target = site + 5 + rel;
    }
    else
    {
        OutputDebugPrintf("[Add2DB] Unexpected call opcode at %p: %02X", site, site[0]);
        return;
    }

    if (target == nullptr || !IsMemoryReadable(target, 1))
    {
        OutputDebugPrintf("[Add2DB] Invalid target resolved from %p", site);
        return;
    }

    int handle = VehBp_Set(target, OnTargetHit);
    if (handle < 0)
    {
        OutputDebugPrintf("[Add2DB] Target breakpoint install failed at %p", target);
        return;
    }

    g_bpAdd2DBTarget = target;
    OutputDebugPrintf("[Add2DB] Target entry breakpoint %p (call site %p)", target, site);
}

static void DiscoverFlashCallerBreakpoints(uint8_t *img, uint8_t *callsite)
{
    if (img == nullptr || callsite == nullptr || g_bpFlashCallerCount != 0)
        return;

    uint8_t *helper = FindContainingFunction(img, callsite);
    if (helper == nullptr)
    {
        OutputDebugPrintf("[FlashProbe] Cannot resolve FlashWindowEx containing function");
        return;
    }

    size_t text_size = 0;
    uint8_t *text = PeSection((HMODULE)img, ".text", &text_size);
    if (text == nullptr || text_size < 5)
    {
        OutputDebugPrintf("[FlashProbe] Cannot locate Weixin .text");
        return;
    }

    const uint64_t helper_addr = (uint64_t)helper;
    int found = 0;
    for (size_t i = 0; i + 5 <= text_size && found < kMaxFlashCallerBreakpoints; i++)
    {
        if (text[i] != 0xE8)
            continue;

        int32_t rel = 0;
        memcpy(&rel, text + i + 1, sizeof(rel));
        uint8_t *target = text + i + 5 + rel;
        if ((uint64_t)target != helper_addr)
            continue;

        int handle = VehBp_Set(text + i, OnTargetHit);
        if (handle < 0)
        {
            OutputDebugPrintf("[FlashProbe] VehBp_Set failed at %p", text + i);
            continue;
        }

        g_bpFlashCaller[found++] = text + i;
        OutputDebugPrintf("[FlashProbe] caller breakpoint %p -> helper %p", text + i, helper);
    }
    g_bpFlashCallerCount = found;
    OutputDebugPrintf("[FlashProbe] discovered %d caller breakpoint(s)", found);
}

static void EnsureFlashCallerBreakpoints(uintptr_t return_address)
{
    if (return_address == 0 || g_config_info.basic_info.imgbase == 0)
        return;
    if (InterlockedCompareExchange(&g_flashCallerDiscovery, 1, 0) != 0)
        return;

    uint8_t *img = reinterpret_cast<uint8_t *>(g_config_info.basic_info.imgbase);
    uint8_t *ret = reinterpret_cast<uint8_t *>(return_address);
    uint8_t *callsite = nullptr;

    // The current Weixin build emits FF 15 disp32 for the delay-IAT call.
    if (ret >= img + 6 && IsMemoryReadable(ret - 6, 6) &&
        ret[-6] == 0xFF && ret[-5] == 0x15)
    {
        callsite = ret - 6;
    }
    else if (ret >= img + 5 && IsMemoryReadable(ret - 5, 5) && ret[-5] == 0xE8)
    {
        callsite = ret - 5;
    }

    if (callsite != nullptr)
    {
        OutputDebugPrintf("[FlashProbe] return=%p callsite=%p", ret, callsite);
        DiscoverFlashCallerBreakpoints(img, callsite);
    }
    else
    {
        OutputDebugPrintf("[FlashProbe] unrecognized callsite return=%p", ret);
    }
    InterlockedExchange(&g_flashCallerDiscovery, 2);
}

static bool ReadFlashWindowInfoSafe(const FLASHWINFO *flash_info,
    HWND *hwnd, UINT *flags, UINT *count)
{
    if (hwnd == nullptr || flags == nullptr || count == nullptr ||
        flash_info == nullptr || !IsMemoryReadable(flash_info, sizeof(FLASHWINFO)))
    {
        return false;
    }

    __try
    {
        *hwnd = flash_info->hwnd;
        *flags = flash_info->dwFlags;
        *count = flash_info->uCount;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        *hwnd = nullptr;
        *flags = 0;
        *count = 0;
        return false;
    }
}

extern "C" void ObserveFlashWindowEx(uintptr_t return_address, const FLASHWINFO *flash_info)
{
    EnsureFlashCallerBreakpoints(return_address);

    ThreadState *state = GetThreadState();
    if (state == nullptr)
        return;

    uint32_t flags = 0;
    uint32_t count = 0;
    HWND hwnd = nullptr;
    ReadFlashWindowInfoSafe(flash_info, &hwnd, &flags, &count);

    OutputDebugPrintf("[FlashProbe] observed return=%p hwnd=%p flags=0x%X count=%u caller_valid=%d",
        (void *)return_address, hwnd, flags, count,
        state->flash_caller.valid ? 1 : 0);

    // 仅把任务栏闪烁作为新消息的时序锚点，避免其他窗口动画误触发。
    if ((flags & FLASHW_TRAY) == 0)
        return;

    const DWORD now = GetTickCount();
    const bool pending_fresh = state->pending_notify_valid != 0 &&
        (now - state->pending_notify_tick) <= 1500;
    const bool caller_fresh = state->flash_caller.valid != 0 &&
        (now - state->flash_caller.tick) <= 1500;

    std::string from;
    std::string content;
    bool captured = false;
    // RDI 的通知对象是当前 Flash 事件的同一份现场数据，优先级高于
    // 可能来自其它线程/上一条消息的 Add2DB 暂存候选。
    if (caller_fresh)
    {
        // FlashWindowEx 的调用者现场中 RDI 指向通知消息对象；RBX 是
        // 另一个内部对象，扫描它会得到加密串、配置项或旧对话内容。
        captured = CaptureNotifyMessage(
            state->flash_caller.rdi,
            0,
            0,
            from,
            content,
            true);
        OutputDebugPrintf("[FlashProbe] caller candidate captured=%d from=[%s] content=[%s]",
            captured ? 1 : 0, from.c_str(), content.c_str());
    }

    if (!captured && pending_fresh)
    {
        from = state->pending_notify_from;
        content = state->pending_notify_content;
        captured = !content.empty();
        if (!captured)
        {
            captured = CaptureNotifyMessage(
                state->pending_notify_msg,
                state->pending_notify_content_arg,
                0,
                from,
                content);
        }
        OutputDebugPrintf("[FlashProbe] pending candidate age=%lu captured=%d from=[%s] content=[%s]",
            (unsigned long)(now - state->pending_notify_tick), captured ? 1 : 0,
            from.c_str(), content.c_str());
    }
    else if (pending_fresh)
    {
        OutputDebugPrintf("[FlashProbe] pending candidate superseded by RDI content");
    }
    if (pending_fresh)
        state->pending_notify_valid = 0;

    if (captured && !content.empty())
    {
        OutputDebugPrintf("[FlashProbe] sending notification from=[%s] content=[%s]",
            from.c_str(), content.c_str());
        SendWindowsNotification(from, content);
    }

    if (state->flash_caller.valid)
    {
        OutputDebugPrintf("[FlashProbe] caller callsite=%p RCX=%p RDX=%p R8=%p R9=%p RAX=%p RBX=%p RSI=%p RDI=%p R14=%p R15=%p RSP=%p age=%lu",
            (void *)state->flash_caller.callsite,
            (void *)state->flash_caller.rcx,
            (void *)state->flash_caller.rdx,
            (void *)state->flash_caller.r8,
            (void *)state->flash_caller.r9,
            (void *)state->flash_caller.rax,
            (void *)state->flash_caller.rbx,
            (void *)state->flash_caller.rsi,
            (void *)state->flash_caller.rdi,
            (void *)state->flash_caller.r14,
            (void *)state->flash_caller.r15,
            (void *)state->flash_caller.rsp,
            (unsigned long)(GetTickCount() - state->flash_caller.tick));
        state->flash_caller.valid = 0;
    }
}

// Add2DBOffset 落在 wrapper 里的 call CoAddMessageToDB 上。wrapper 的唯一调用方
// 在该 call 返回后会再 call 一次 UI notify。把 notify 的 rdx 换成 tip 对象，
// 当前会话才会立刻插入提示气泡。
static void *DiscoverNotifyCall(uint8_t *img, uint64_t add2db_offset)
{
    uint8_t *inner_call = img + add2db_offset;
    if (!IsMemoryReadable(inner_call, 16) || inner_call[0] != 0xE8)
        return nullptr;

    uint8_t *wrap = nullptr;
    for (int i = 8; i < 48; i++)
    {
        uint8_t *p = inner_call - i;
        if (!IsMemoryReadable(p, 4))
            break;
        if (p[0] == 0x56 && p[1] == 0x48 && p[2] == 0x83 && p[3] == 0xEC)
        {
            wrap = p;
            break;
        }
    }
    if (wrap == nullptr)
        return nullptr;

    size_t text_size = 0;
    uint8_t *text = PeSection((HMODULE)img, ".text", &text_size);
    if (text == nullptr || text_size < 8)
        return nullptr;

    const uint64_t wrap_addr = (uint64_t)wrap;
    for (size_t i = 0; i + 5 < text_size; i++)
    {
        if (text[i] != 0xE8)
            continue;
        int32_t rel = 0;
        memcpy(&rel, text + i + 1, 4);
        uint64_t src = (uint64_t)(text + i);
        if (src + 5 + (int64_t)rel != wrap_addr)
            continue;

        uint8_t *p = text + i + 5;
        uint8_t *end = p + 32;
        while (p < end && IsMemoryReadable(p, 5))
        {
            if (*p == 0x90 || *p == 0xCC)
            {
                p++;
                continue;
            }
            if (*p == 0xE8)
                return p;
            if (p[0] == 0x48 && p[1] == 0x8D)
            {
                p += 4;
                continue;
            }
            if ((p[0] == 0x48 || p[0] == 0x4C || p[0] == 0x4D) && p[1] == 0x89)
            {
                p += 3;
                continue;
            }
            p++;
        }
        break;
    }
    return nullptr;
}


static uint8_t *FindWrapper(uint8_t *inner_call)
{
    if (!IsMemoryReadable(inner_call, 16) || inner_call[0] != 0xE8)
        return nullptr;
    for (int i = 8; i < 48; i++)
    {
        uint8_t *p = inner_call - i;
        if (!IsMemoryReadable(p, 4))
            break;
        if (p[0] == 0x56 && p[1] == 0x48 && p[2] == 0x83 && p[3] == 0xEC)
            return p;
    }
    return nullptr;
}

static uint8_t *NextDirectCall(uint8_t *p, uint8_t *end)
{
    while (p < end && IsMemoryReadable(p, 5))
    {
        if (*p == 0x90 || *p == 0xCC)
        {
            p++;
            continue;
        }
        if (*p == 0xE8)
            return p;
        if (p[0] == 0x48 && p[1] == 0x8D)
        {
            p += 4;
            continue;
        }
        if ((p[0] == 0x48 || p[0] == 0x4C || p[0] == 0x4D) && p[1] == 0x89)
        {
            p += 3;
            continue;
        }
        p++;
    }
    return nullptr;
}

// CoReplace 在 Add2DB wrapper-caller 返回后会把 [rbp+0x580] 拷回 [rbp+0x2a0]。
// 若 0x1693B30 抽取被跳过，这次拷贝会覆盖已经打好自定义 tip 的消息对象。
static int DiscoverPostAddCopies(uint8_t *img, uint64_t add2db_offset, void **out, int max_out)
{
    uint8_t *wrap = FindWrapper(img + add2db_offset);
    if (wrap == nullptr || max_out <= 0)
        return 0;

    size_t text_size = 0;
    uint8_t *text = PeSection((HMODULE)img, ".text", &text_size);
    if (text == nullptr || text_size < 16)
        return 0;

    const uint64_t wrap_addr = (uint64_t)wrap;
    uint8_t *wrap_call = nullptr;
    for (size_t i = 0; i + 5 < text_size; i++)
    {
        if (text[i] != 0xE8)
            continue;
        int32_t rel = 0;
        memcpy(&rel, text + i + 1, 4);
        if ((uint64_t)(text + i) + 5 + (int64_t)rel != wrap_addr)
            continue;
        wrap_call = text + i;
        break;
    }
    if (wrap_call == nullptr)
        return 0;

    uint8_t *fn = wrap_call;
    uint8_t *limit = text + 16;
    while (fn > limit)
    {
        if (fn[0] == 0x55 && fn[-1] == 0xCC)
            break;
        fn--;
    }
    if (fn[0] != 0x55)
        return 0;

    const uint64_t fn_addr = (uint64_t)fn;
    int n = 0;
    for (size_t i = 0; i + 5 < text_size && n < max_out; i++)
    {
        if (text[i] != 0xE8)
            continue;
        int32_t rel = 0;
        memcpy(&rel, text + i + 1, 4);
        if ((uint64_t)(text + i) + 5 + (int64_t)rel != fn_addr)
            continue;
        uint8_t *next = NextDirectCall(text + i + 5, text + i + 5 + 48);
        if (next != nullptr)
            out[n++] = next;
    }
    return n;
}


static void DiscoverInnerDbCalls(uint8_t *img, uint64_t delmsg_offset,
    void **out_del, void **out_check)
{
    *out_del = nullptr;
    *out_check = nullptr;
    uint8_t *site = img + delmsg_offset;
    if (!IsMemoryReadable(site, 5) || site[0] != 0xE8)
        return;
    int32_t rel = 0;
    memcpy(&rel, site + 1, 4);
    uint8_t *del_fn = site + 5 + rel;

    uint8_t *inner_fn = nullptr;
    for (int i = 0; i + 9 < 0x140; i++)
    {
        uint8_t *p = del_fn + i;
        if (!IsMemoryReadable(p, 9))
            break;
        if (p[0] == 0x41 && p[1] == 0x89 && p[2] == 0xD9 && p[3] == 0xE8)
        {
            memcpy(&rel, p + 4, 4);
            inner_fn = p + 8 + rel;
            break;
        }
    }
    if (inner_fn == nullptr)
        return;

    for (int i = 0; i + 12 < 0x900; i++)
    {
        uint8_t *p = inner_fn + i;
        if (!IsMemoryReadable(p, 12))
            break;
        if (!(p[0] == 0x48 && p[1] == 0x8B && p[2] == 0x8E &&
              p[3] == 0x00 && p[4] == 0x0C && p[5] == 0x00 && p[6] == 0x00))
            continue;
        uint8_t *q = p + 7;
        uint8_t *end = p + 48;
        uint8_t *first_e8 = nullptr;
        while (q < end && IsMemoryReadable(q, 5))
        {
            if (*q == 0xE8)
            {
                if (first_e8 == nullptr)
                {
                    first_e8 = q;
                    q += 5;
                    continue;
                }
                *out_del = first_e8;
                *out_check = q;
                return;
            }
            q++;
        }
        break;
    }
}

static uint64_t FindSrvId(uint64_t base_addr, size_t scan_limit)
{
    for (size_t offset = 0; offset + 16 <= scan_limit; offset += 8)
    {
        uint8_t* candidate = (uint8_t*)(base_addr + offset);
        if (!IsMemoryReadable(candidate, 16))
            break;

        if (candidate[14] != 0x00 || candidate[15] != 0x00)
            continue;
        if (candidate[12] == 0x00 && candidate[13] == 0x00)
            continue;

        int non_zero_count = 0;
        for (int i = 0; i < 14; i++)
        {
            if (candidate[i] != 0) non_zero_count++;
        }
        if (non_zero_count == 14)
            return (uint64_t)candidate;
    }
    return 0;
}

static bool ReadMsStdString(const StdString *ss, std::string &out)
{
    StdString local = {};
    if (ss == nullptr || !SafeReadBytes(ss, &local, sizeof(local)))
        return false;
    if (local.size < 0 || local.capability < local.size || local.capability > 0x100000)
        return false;

    size_t n = (size_t)local.size;
    if (n > 0x10000)
        return false;
    const void *data = nullptr;
    if (local.capability >= 16)
    {
        uint64_t ptr = 0;
        memcpy(&ptr, local.data_ptr, 8);
        if (ptr == 0)
            return false;
        data = (const void *)ptr;
    }
    else
    {
        if (n > 15)
            return false;
        data = local.data_ptr;
    }
    out.assign(n, '\0');
    if (n > 0 && !SafeReadBytes(data, &out[0], n))
        return false;
    return true;
}

static bool WriteMsStdString(StdString *ss, const std::string &value)
{
    if (ss == nullptr || !IsMemoryReadable(ss, sizeof(StdString)))
        return false;
    if (ss->capability < 0 || ss->capability > 0x100000)
        return false;

    std::string fitted = value;
    if ((int64_t)fitted.size() > ss->capability)
        fitted = revoke_tip::fitUtf8(fitted, (size_t)ss->capability);
    if ((int64_t)fitted.size() > ss->capability)
        return false;

    char *dest = nullptr;
    if (ss->capability >= 16)
    {
        uint64_t ptr = *((uint64_t *)ss->data_ptr);
        if (ptr == 0 || !IsMemoryReadable((void *)ptr, fitted.size() + 1))
            return false;
        dest = (char *)ptr;
    }
    else
    {
        dest = (char *)ss->data_ptr;
    }
    memcpy(dest, fitted.c_str(), fitted.size() + 1);
    ss->size = (int64_t)fitted.size();
    return true;
}

static void *WxMalloc(size_t n)
{
    HMODULE ucrt = GetModuleHandleA("ucrtbase.dll");
    if (ucrt != nullptr)
    {
        auto fn = (void *(__cdecl *)(size_t))GetProcAddress(ucrt, "malloc");
        if (fn != nullptr)
            return fn(n);
    }
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n);
}

static bool WriteMsStdStringGrow(StdString *ss, const std::string &value)
{
    if (ss == nullptr || !IsMemoryReadable(ss, sizeof(StdString)))
        return false;
    if (ss->capability < 0 || ss->capability > 0x100000)
        return false;

    if ((int64_t)value.size() <= ss->capability)
    {
        char *dest = nullptr;
        if (ss->capability >= 16)
        {
            uint64_t ptr = *((uint64_t *)ss->data_ptr);
            if (ptr == 0 || !IsMemoryReadable((void *)ptr, value.size() + 1))
                return false;
            dest = (char *)ptr;
        }
        else
        {
            dest = (char *)ss->data_ptr;
        }
        memcpy(dest, value.c_str(), value.size() + 1);
        ss->size = (int64_t)value.size();
        return true;
    }

    size_t cap = value.size() + 32;
    if (cap < 16)
        cap = 16;
    char *buf = (char *)WxMalloc(cap + 1);
    if (buf == nullptr)
        return false;
    memcpy(buf, value.c_str(), value.size() + 1);
    *((uint64_t *)ss->data_ptr) = (uint64_t)buf;
    ss->size = (int64_t)value.size();
    ss->capability = (int64_t)cap;
    OutputDebugPrintf("[Debug] Grew std::string to size=%llu cap=%llu",
        (unsigned long long)value.size(), (unsigned long long)cap);
    return true;
}

static uint64_t ReadUint64At(uint64_t base, int offset)
{
    uint8_t *addr = (uint8_t *)(base + offset);
    if (!IsMemoryReadable(addr, 8))
        return 0;
    uint64_t value = 0;
    memcpy(&value, addr, 8);
    if (value < 0x10000)
        return 0;
    return value;
}

static uint32_t FindLikelyMsgType(uint64_t base)
{
    static const uint32_t kTypes[] = {3, 34, 43, 47, 48, 49, 50, 62, 42, 10000, 10002, 1};
    uint32_t direct = 0;
    if (SafeReadBytes((void *)(base + 0x164), &direct, sizeof(direct)))
    {
        for (uint32_t type : kTypes)
        {
            if (direct == type)
                return direct;
        }
    }
    for (int off = 0x08; off <= 0x40; off += 4)
    {
        uint8_t *addr = (uint8_t *)(base + off);
        if (!IsMemoryReadable(addr, 4))
            break;
        uint32_t value = 0;
        memcpy(&value, addr, 4);
        for (uint32_t type : kTypes)
        {
            if (value == type)
                return value;
        }
    }
    return 0;
}

static bool ScoreContentCandidate(const std::string &value, std::string &best)
{
    if (value.empty() || value.size() > 0x8000)
        return false;
    if (revoke_tip::looksLikeWxId(value) || revoke_tip::looksLikeRevokePayload(value))
        return false;
    if (revoke_tip::looksLikeMsgSource(value))
        return false;
    if (value.find("<?xml") != std::string::npos || value.find("<sysmsg") != std::string::npos)
        return false;
    if (value.find("http://") == 0 || value.find("https://") == 0)
        return false;
    if (best.empty() || value.size() > best.size())
    {
        best = value;
        return true;
    }
    return false;
}

static void CacheContentFromObject(uint64_t base, uint64_t known_srvid)
{
    uint64_t srvid = known_srvid;
    if (srvid == 0 && g_config_info.add2db_info.initialized)
        srvid = ReadUint64At(base, g_config_info.add2db_info.offset_srvid);
    if (srvid == 0)
    {
        uint64_t addr = FindSrvId(base, 0x200);
        if (addr != 0 && IsMemoryReadable((void *)addr, 8))
            memcpy(&srvid, (void *)addr, 8);
    }
    if (srvid == 0)
    {
        static const int kOff[] = {0xF8, 0x100, 0x108, 0x110, 0x118, 0x120, 0x128, 0x130, 0x140, 0x148, 0x150};
        for (int off : kOff)
        {
            srvid = ReadUint64At(base, off);
            if (srvid != 0)
                break;
        }
    }
    if (srvid == 0)
        return;

    uint32_t msgType = FindLikelyMsgType(base);
    std::string best;
    size_t scan = 0x400;
    if (g_config_info.add2db_info.initialized)
    {
        StdString *known = (StdString *)(base + g_config_info.add2db_info.offset_revoke_xml);
        std::string knownStr;
        if (ReadMsStdString(known, knownStr))
            ScoreContentCandidate(knownStr, best);
    }
    for (size_t offset = 0x40; offset + sizeof(StdString) <= scan; offset += 8)
    {
        StdString *ss = (StdString *)(base + offset);
        std::string value;
        if (!ReadMsStdString(ss, value))
            continue;
        ScoreContentCandidate(value, best);
    }
    if (best.empty() && msgType != 0 && msgType != 1)
    {
        revoke_tip::rememberContent(srvid, revoke_tip::messageKindPlaceholder(msgType));
        return;
    }
    if (best.empty())
        return;
    revoke_tip::rememberContent(srvid, revoke_tip::contentPreviewForReceivedMessage(msgType, best));
}

static bool LooksLikePlainText(const std::string &value)
{
    if (value.empty() || value.size() > 0x8000)
        return false;
    if (revoke_tip::looksLikeWxId(value) || revoke_tip::looksLikeRevokePayload(value))
        return false;
    if (value.find('<') != std::string::npos || value.find("<?xml") != std::string::npos)
        return false;
    for (unsigned char ch : value)
    {
        if (ch < 0x20)
            return false;
    }
    return true;
}

static std::string PreviewFromField(const std::string &value, uint32_t msgType)
{
    if (value.empty() || revoke_tip::looksLikeMsgSource(value))
        return "";
    if (LooksLikePlainText(value))
        return revoke_tip::truncateUtf8(value, revoke_tip::kMaxContentPreviewBytes);
    uint32_t type = msgType;
    if (type == 0 || type == 1)
        type = revoke_tip::guessMsgTypeFromXml(value);
    if (type != 0 && type != 1)
        return revoke_tip::messageKindPlaceholder(type);
    return "";
}

struct ContentField
{
    size_t off;
    std::string preview;
    bool metadata;
};

static void CollectContentFields(uint64_t base, size_t range, uint32_t msgType,
    std::vector<ContentField> &out, size_t *msgsourceOff)
{
    if (base == 0 || !IsMemoryReadable((void *)base, 16))
        return;
    for (size_t off = 0; off + sizeof(StdString) <= range; off += 8)
    {
        std::string value;
        if (!ReadMsStdString((StdString *)(base + off), value) || value.empty())
            continue;
        ContentField field{};
        field.off = off;
        field.metadata = revoke_tip::looksLikeMsgSource(value);
        if (field.metadata)
        {
            if (msgsourceOff != nullptr && *msgsourceOff == (size_t)-1)
                *msgsourceOff = off;
            out.push_back(std::move(field));
            continue;
        }
        field.preview = PreviewFromField(value, msgType);
        if (!field.preview.empty())
            out.push_back(std::move(field));
    }
}

static std::string PickContentField(const std::vector<ContentField> &fields, size_t msgsourceOff)
{
    auto take = [&](size_t off) -> std::string
    {
        for (const auto &field : fields)
        {
            if (field.off == off && !field.metadata && !field.preview.empty())
            {
                OutputDebugPrintf("[Debug] CaptureOriginalText pick +0x%X size=%llu",
                    (unsigned)off, (unsigned long long)field.preview.size());
                return field.preview;
            }
        }
        return "";
    };

    if (msgsourceOff != (size_t)-1)
    {
        static const int kNeighbor[] = {-0x20, 0x20, -0x40, 0x40, -0x60, 0x60};
        for (int delta : kNeighbor)
        {
            if (delta < 0 && msgsourceOff < (size_t)(-delta))
                continue;
            std::string picked = take(msgsourceOff + delta);
            if (!picked.empty())
                return picked;
        }
    }

    static const size_t kPreferred[] = {
        0x1A0, 0x180, 0x1C0, 0x160, 0x1E0, 0x140, 0x200, 0x220, 0x120, 0x240
    };
    for (size_t off : kPreferred)
    {
        std::string picked = take(off);
        if (!picked.empty())
            return picked;
    }

    std::string best;
    size_t bestOff = 0;
    for (const auto &field : fields)
    {
        if (field.metadata || field.preview.empty())
            continue;
        if (best.empty() || field.preview.size() > best.size())
        {
            best = field.preview;
            bestOff = field.off;
        }
    }
    if (!best.empty())
    {
        OutputDebugPrintf("[Debug] CaptureOriginalText fallback +0x%X size=%llu",
            (unsigned)bestOff, (unsigned long long)best.size());
    }
    return best;
}

/**
 * @brief 使用 Win32 balloon tip 发送 Windows 通知
 * @param from 发送者名称
 * @param content 消息内容
 */
static void SendWindowsNotification(const std::string &from, const std::string &content)
{
    OutputDebugPrintf("[Notification] SendWindowsNotification called, g_notify_new_message=%d", g_notify_new_message);

    if (!g_notify_new_message)
    {
        OutputDebugPrintf("[Notification] Disabled by config");
        return;
    }

    std::string title = from.empty() ? "新消息" : from;
    std::string body = content.empty() ? "[消息]" : content;

    OutputDebugPrintf("[Notification] Original: from=[%s] content=[%s]", from.c_str(), content.c_str());

    // 截断过长内容
    body = revoke_tip::truncateUtf8(body, 200);

    // 调用 inline_hook.cpp 的 Toast 显示
    SendWindowsNotification(title.c_str(), body.c_str());
}

static std::string CaptureOriginalText(uint64_t base)
{
    if (base == 0)
        return "";

    const uint32_t msgType = FindLikelyMsgType(base);
    OutputDebugPrintf("[Debug] CaptureOriginalText base=%p type=%u", (void *)base, msgType);

    std::vector<ContentField> fields;
    size_t msgsourceOff = (size_t)-1;
    CollectContentFields(base, 0x500, msgType, fields, &msgsourceOff);
    std::string picked = PickContentField(fields, msgsourceOff);
    if (!picked.empty())
        return picked;

    fields.clear();
    int nested = 0;
    for (size_t off = 0; off + 8 <= 0x200 && nested < 6; off += 8)
    {
        std::string occupied;
        if (off + sizeof(StdString) <= 0x200 &&
            ReadMsStdString((StdString *)(base + off), occupied) && !occupied.empty())
        {
            continue;
        }
        uint64_t child = 0;
        if (!SafeReadBytes((void *)(base + off), &child, 8))
            continue;
        if (child == base || !LooksLikeHeapObject(child))
            continue;
        CollectContentFields(child, 0x400, msgType, fields, nullptr);
        nested += 1;
    }
    picked = PickContentField(fields, (size_t)-1);
    if (!picked.empty())
        return picked;
    if (msgType != 0 && msgType != 1)
        return revoke_tip::messageKindPlaceholder(msgType);
    return "";
}

static void CopyNotifyField(char *dst, size_t dst_size, const std::string &value)
{
    if (dst == nullptr || dst_size == 0)
        return;
    dst[0] = '\0';
    if (!value.empty())
        strncpy_s(dst, dst_size, value.c_str(), _TRUNCATE);
}

static bool CaptureNotifyMessage(uint64_t message_object, uint64_t content_arg,
    uint64_t auxiliary_object, std::string &from, std::string &content,
    bool flash_layout)
{
    from.clear();
    content.clear();
    if (message_object == 0 || !IsMemoryReadable((void *)message_object, 0x100))
        return false;

    const uint32_t msg_type = FindLikelyMsgType(message_object);
    std::vector<ContentField> fields;
    size_t msgsource_off = (size_t)-1;

    auto read_field = [&](size_t offset, std::string &value) -> bool
    {
        value.clear();
        return ReadMsStdString(
            (const StdString *)(message_object + offset), value);
    };
    auto read_preview = [&](size_t offset, std::string &value) -> bool
    {
        std::string raw;
        if (!read_field(offset, raw))
            return false;
        value = PreviewFromField(raw, msg_type);
        return !value.empty();
    };

    if (flash_layout)
    {
        // Flash caller 的 RDI 是通知对象。根据 4.1.9.57 的现场，
        // +0x48 和 +0x2D0 都保存当前正文，+0x68 是上一段无关对话，
        // 因此绝不能使用通用“最长字符串”启发式去选 +0x68。
        std::string at48;
        std::string at2d0;
        const bool have48 = read_preview(0x48, at48);
        const bool have2d0 = read_preview(0x2D0, at2d0);
        if (have48 && have2d0 && at48 != at2d0)
        {
            OutputDebugPrintf(
                "[FlashProbe] content fields differ +0x48=[%s] +0x2D0=[%s]; using +0x48",
                at48.c_str(), at2d0.c_str());
        }
        if (have48)
            content = at48;
        else if (have2d0)
            content = at2d0;
        else
            read_preview(0x1A0, content);

        OutputDebugPrintf(
            "[FlashProbe] direct fields +0x48=%d +0x2D0=%d +0x1A0 content=[%s]",
            have48 ? 1 : 0, have2d0 ? 1 : 0, content.c_str());
    }
    else
    {
        // 当前目标入口的 R9 是辅助 wxid 字符串；若未来版本传入真正
        // 的正文参数，仍先尝试它，再读取消息对象的固定正文槽。
        if (content_arg != 0 && IsMemoryReadable((void *)content_arg, sizeof(StdString)))
        {
            std::string value;
            if (ReadMsStdString((const StdString *)content_arg, value))
                content = PreviewFromField(value, msg_type);
        }

        // 消息对象中常见的正文槽，随后再用带 msgsource 过滤的扫描兜底。
        static const size_t kPreferredContent[] = {
            0x1A0, 0x18, 0x38, 0x48, 0x2D0,
            0x180, 0x1C0, 0x160, 0x1E0, 0x140, 0x200, 0x220
        };
        if (content.empty())
        {
            for (size_t offset : kPreferredContent)
            {
                std::string value;
                if (read_preview(offset, value))
                {
                    content = value;
                    break;
                }
            }
        }

        if (content.empty())
        {
            CollectContentFields(message_object, 0x500, msg_type, fields, &msgsource_off);
            content = PickContentField(fields, msgsource_off);
        }
        if (content.empty())
        {
            // 某些消息把正文放在一层嵌套对象中；复用已有的安全扫描逻辑。
            content = CaptureOriginalText(message_object);
        }
        if (content.empty() && auxiliary_object != 0 &&
            IsMemoryReadable((void *)auxiliary_object, 0x40))
        {
            content = CaptureOriginalText(auxiliary_object);
        }
    }

    // 非文本消息没有可读正文时，按真实消息类型给出类型预览（图片/文件等）。
    if (content.empty() && msg_type != 0 && msg_type != 1)
        content = revoke_tip::messageKindPlaceholder(msg_type);
    if (content.empty())
        return false;

    // Flash caller 的固定布局同时提供昵称和 wxid；昵称更适合作为
    // 气泡标题，只有昵称缺失时才回退到唯一用户名。
    size_t wxid_off = (size_t)-1;
    std::string short_name;
    if (flash_layout)
    {
        std::string nickname;
        std::string wxid;
        if (read_field(0x160, nickname) && LooksLikePlainText(nickname) &&
            !revoke_tip::looksLikeWxId(nickname))
        {
            from = nickname;
        }
        if (read_field(0x000, wxid) && revoke_tip::looksLikeWxId(wxid))
        {
            if (from.empty())
                from = wxid;
            OutputDebugPrintf("[FlashProbe] direct sender nickname=[%s] wxid=[%s] selected=[%s]",
                nickname.c_str(), wxid.c_str(), from.c_str());
        }
    }
    auto scan_sender = [&](uint64_t base, size_t range)
    {
        if (base == 0 || !IsMemoryReadable((void *)base, 0x40))
            return;
        for (size_t off = 0; off + sizeof(StdString) <= range; off += 8)
        {
            std::string value;
            if (!ReadMsStdString((const StdString *)(base + off), value) || value.empty())
                continue;
            if (revoke_tip::looksLikeWxId(value))
            {
                if (from.empty())
                    from = value;
                if (wxid_off == (size_t)-1)
                    wxid_off = off;
                continue;
            }
            if (value == content || !LooksLikePlainText(value) || value.size() > 96)
                continue;
            if (short_name.empty() || value.size() < short_name.size())
                short_name = value;
        }
    };
    if (from.empty())
        scan_sender(message_object, 0x500);
    if (from.empty())
        scan_sender(auxiliary_object, 0x300);
    if (from.empty() && !short_name.empty())
        from = short_name;

    content = revoke_tip::truncateUtf8(content, 200);
    return !content.empty();
}

static bool ApplyCustomTip(StdString *ss, uint64_t fallback_id = 0, const char *extra_content = nullptr)
{
    std::string payload;
    if (!ReadMsStdString(ss, payload) || payload.empty())
        return false;

    const std::string display = revoke_tip::displayTipFromPayload(payload);
    if (revoke_tip::tipIndicatesSelfRecall(display))
        return false;

    uint64_t newMsgId = revoke_tip::newMsgIdFromXml(payload);
    if (newMsgId == 0)
        newMsgId = fallback_id;
    std::string content;
    if (extra_content != nullptr && extra_content[0] != '\0')
        content = extra_content;
    else if (newMsgId != 0)
        revoke_tip::tryLookupContent(newMsgId, content);

    std::string rendered = revoke_tip::renderForEvent(
        display,
        g_tip_phrase,
        newMsgId,
        payload,
        revoke_tip::currentTimeText(),
        content);
    if (rendered.empty() || rendered == display)
        return false;

    std::string next = revoke_tip::applyTipToPayload(payload, rendered);
    int64_t old_cap = ss->capability;
    if (!WriteMsStdStringGrow(ss, next))
    {
        next = revoke_tip::compactRevokeXml(rendered);
        if (!WriteMsStdStringGrow(ss, next))
        {
            next = revoke_tip::fitTipToCapacity(payload, rendered, (size_t)ss->capability);
            if (!WriteMsStdString(ss, next))
                return false;
        }
    }
    OutputDebugPrintf("[Debug] ApplyCustomTip display=[%s] rendered=[%s] next=%llu cap=%lld->%lld content=[%s]",
        display.c_str(), rendered.c_str(), (unsigned long long)next.size(),
        (long long)old_cap, (long long)ss->capability, content.c_str());
    OutputDebugPrintf("[Debug] Custom tip applied (%llu chars, content=%s)",
        (unsigned long long)rendered.size(), content.empty() ? "miss" : "hit");
    return true;
}

static void OnTargetHit(PCONTEXT ctx, PEXCEPTION_RECORD /*pExc*/)
{
    uint64_t rip = ctx->Rip;
    ThreadState* thread_state = GetThreadState();
    if (thread_state == nullptr) {
        OutputDebugString(TEXT("[RevokeHook] GetThreadState Failed!"));
        return;
    }

    if (IsFlashCallerBreakpoint(rip))
    {
        FlashCallerState &flash = thread_state->flash_caller;
        flash.callsite = rip;
        flash.rcx = ctx->Rcx;
        flash.rdx = ctx->Rdx;
        flash.r8 = ctx->R8;
        flash.r9 = ctx->R9;
        flash.rax = ctx->Rax;
        flash.rbx = ctx->Rbx;
        flash.rsi = ctx->Rsi;
        flash.rdi = ctx->Rdi;
        flash.r14 = ctx->R14;
        flash.r15 = ctx->R15;
        flash.rsp = ctx->Rsp;
        flash.tick = GetTickCount();
        flash.valid = 1;

        OutputDebugPrintf("[FlashProbe] caller hit=%p RCX=%p RDX=%p R8=%p R9=%p RAX=%p RBX=%p RSI=%p RDI=%p R14=%p R15=%p RSP=%p",
            (void *)rip,
            (void *)flash.rcx,
            (void *)flash.rdx,
            (void *)flash.r8,
            (void *)flash.r9,
            (void *)flash.rax,
            (void *)flash.rbx,
            (void *)flash.rsi,
            (void *)flash.rdi,
            (void *)flash.r14,
            (void *)flash.r15,
            (void *)flash.rsp);

        // 这里的 caller 是一个“通知对象 -> HWND”的辅助函数调用点。
        // RDI 保存通知对象；诊断时仍把全部寄存器/栈候选交给
        // DumpNotifyContext，便于继续比对不同消息类型。
        DumpNotifyContext(thread_state, ctx, "FlashCaller", false);
        return;
    }

    if (g_bpAdd2DBTarget != nullptr && rip == (uint64_t)g_bpAdd2DBTarget)
    {
        // 目标函数入口的 R8/R9 分别是消息对象和正文 std::string。
        DumpNotifyContext(thread_state, ctx, "Add2DBTarget", true);
        if (thread_state->suppress_next_notify)
        {
            thread_state->suppress_next_notify = 0;
            thread_state->pending_notify_valid = 0;
            OutputDebugPrintf("[Add2DB] Suppress target entry for anti-recall path");
            return;
        }

        thread_state->pending_notify_msg = ctx->R8;
        thread_state->pending_notify_content_arg = ctx->R9;
        thread_state->pending_notify_tick = GetTickCount();
        thread_state->pending_notify_from[0] = '\0';
        thread_state->pending_notify_content[0] = '\0';
        thread_state->pending_notify_valid = 1;

        std::string from;
        std::string content;
        if (g_notify_new_message && CaptureNotifyMessage(
            ctx->R8, ctx->R9, ctx->Rdx, from, content))
        {
            CopyNotifyField(thread_state->pending_notify_from,
                sizeof(thread_state->pending_notify_from), from);
            CopyNotifyField(thread_state->pending_notify_content,
                sizeof(thread_state->pending_notify_content), content);
            OutputDebugPrintf("[Add2DB] Cached candidate from=[%s] content=[%s]",
                from.c_str(), content.c_str());
        }
        else
        {
            OutputDebugPrintf("[Add2DB] Target entry candidate msg=%p content=%p (capture deferred)",
                (void *)ctx->R8, (void *)ctx->R9);
        }
        return;
    }

    if (rip == (uint64_t)g_bpDelMsg) 
    {
        uint8_t revoke_sig[] = { 0xe6, 0x92, 0xa4, 0xe5, 0x9b, 0x9e }; //'撤回'
        uint8_t self_revoke_sig[] = { 0xe4, 0xbd, 0xa0, 0xe6, 0x92, 0xa4, 0xe5, 0x9b, 0x9e }; //'你撤回'
        uint8_t revoke_sig_english[] = { 0x72, 0x65, 0x63, 0x61, 0x6c, 0x6c, 0x65, 0x64 }; //'recalled'
		uint8_t self_revoke_sig_english[] = { 0x59, 0x6f, 0x75, 0x20, 0x72, 0x65, 0x63, 0x61, 0x6c, 0x6c, 0x65, 0x64 }; //'You recalled'

        StdString* revoke_xml = nullptr;

        if (!g_config_info.delmsg_info.initialized)
        {
            uint64_t candidates[] = { ctx->Rdx, ctx->R8, ctx->R9 };
            int candidate_indices[] = { 2, 3, 4 };

            for (int c = 0; c < 3 && revoke_xml == nullptr; c++)
            {
                revoke_xml = FindStdStringWithSig(candidates[c], 0x2000,
                    revoke_sig, sizeof(revoke_sig));
                if (revoke_xml == nullptr)
                {
                    revoke_xml = FindStdStringWithSig(candidates[c], 0x2000,
                        revoke_sig_english, sizeof(revoke_sig_english));
                }
                if (revoke_xml) {
                    g_config_info.delmsg_info.arg_msg_index = candidate_indices[c];
                    g_config_info.delmsg_info.offset_revoke_xml = (int)((uint64_t)revoke_xml - candidates[c]);
                }
            }

            if (revoke_xml == nullptr || revoke_xml->size <= 0)
            {
                OutputDebugPrintf("[Debug] DelMsg: Cannot find revoke_xml in registers");
                return;
            }

            g_config_info.delmsg_info.arg_notify_index = FindZeroArgIndex(ctx, 3, 8);
            g_config_info.delmsg_info.initialized = true;
            OutputDebugPrintf("[Debug] DelMsg cached: msg_idx=%d, xml_off=0x%X, notify_idx=%d",
                g_config_info.delmsg_info.arg_msg_index,
                g_config_info.delmsg_info.offset_revoke_xml,
                g_config_info.delmsg_info.arg_notify_index);
        }
        else
        {
            uint64_t arg_msg = GetArgValue(ctx, g_config_info.delmsg_info.arg_msg_index);
            revoke_xml = (StdString*)(arg_msg + g_config_info.delmsg_info.offset_revoke_xml);
            if (!IsMemoryReadable(revoke_xml, sizeof(StdString)) || revoke_xml->size <= 0)
            {
                OutputDebugPrintf("[Debug] DelMsg: revoke_xml invalid (cached path)");
                return;
            }
        }

        uint64_t revoke_xml_str_addr = *((uint64_t*)(revoke_xml->data_ptr));
        if (revoke_xml_str_addr == 0 || !IsMemoryReadable((void*)revoke_xml_str_addr, (size_t)revoke_xml->size))
        {
            OutputDebugPrintf("[Debug] DelMsg: revoke_xml str invalid");
            return;
        }

        bool is_self = false;
        for (int64_t i = 0; i < (int64_t)revoke_xml->size; i++)
        {
            bool matches_chinese =
                i <= (int64_t)revoke_xml->size - (int64_t)sizeof(self_revoke_sig) &&
                memcmp((void*)(revoke_xml_str_addr + i),
                    self_revoke_sig, sizeof(self_revoke_sig)) == 0;
            bool matches_english =
                i <= (int64_t)revoke_xml->size - (int64_t)sizeof(self_revoke_sig_english) &&
                memcmp((void*)(revoke_xml_str_addr + i),
                    self_revoke_sig_english, sizeof(self_revoke_sig_english)) == 0;
            if (matches_chinese || matches_english)
            {
                is_self = true;
                break;
            }
        }

        if (is_self && !g_anti_revoke_self_msg)
        {
            thread_state->anti_revoke_cur_msg = 0;
            return;
        }
        if (is_self)
            OutputDebugPrintf("[Debug] Anti Revoke SELF Msg...");

        thread_state->anti_revoke_cur_msg = 1;
        thread_state->pending_content[0] = '\0';
        {
            uint64_t original_obj = GetArgValue(ctx, g_config_info.delmsg_info.arg_msg_index);
            DumpDelMsgObjects(ctx, original_obj);
            std::string original = CaptureOriginalText(original_obj);
            std::string payload;
            uint64_t nid = 0;
            if (ReadMsStdString(revoke_xml, payload))
                nid = revoke_tip::newMsgIdFromXml(payload);
            if (original.empty() || revoke_tip::looksLikeMsgSource(original))
            {
                original.clear();
                uint64_t candidates[] = { ctx->Rcx, ctx->Rdx, ctx->R8, ctx->R9, original_obj };
                for (uint64_t candidate : candidates)
                {
                    if (candidate == 0 || !IsMemoryReadable((void *)candidate, 0x40))
                        continue;
                    CacheContentFromObject(candidate, nid);
                }
                if (nid != 0)
                    revoke_tip::tryLookupContent(nid, original);
                if (revoke_tip::looksLikeMsgSource(original))
                    original.clear();
            }
            if (!original.empty())
            {
                strncpy_s(thread_state->pending_content, original.c_str(), _TRUNCATE);
                OutputDebugPrintf("[Debug] Captured original text: [%s]", thread_state->pending_content);
                if (nid != 0)
                    revoke_tip::rememberContent(nid, original);
            }
        }
        if (ApplyCustomTip(revoke_xml, 0, thread_state->pending_content))
            OutputDebugPrintf("[Debug] Patched revoke xml before skip-delete");
        if (g_config_info.delmsg_info.arg_notify_index > 0)
        {
            SetArgValue(ctx, g_config_info.delmsg_info.arg_notify_index, 1);
            OutputDebugPrintf("[Debug] Set notify arg %d to 1", g_config_info.delmsg_info.arg_notify_index);
        }

        ctx->Rax = 1;
        ctx->Rip += 5;
        OutputDebugPrintf("[Debug] Skip Call, New RIP: %p RAX=1", ctx->Rip);
    }
    else if (rip == (uint64_t)g_bpAdd2DB)
    {
        const bool was_anti_revoke = thread_state->anti_revoke_cur_msg != 0;
        thread_state->suppress_next_notify = was_anti_revoke ? 1 : 0;
        thread_state->anti_revoke_cur_msg = 0;

        OutputDebugPrintf("[Add2DB] Hook hit, anti_revoke_cur_msg=%d, g_notify_new_message=%d",
            was_anti_revoke, g_notify_new_message);

        // 通知所有新消息（不仅仅是撤回消息）
        if (g_notify_new_message && !was_anti_revoke)
        {
            OutputDebugPrintf("[Add2DB] Processing new message notification...");

            // 0x34A68DB 是一个参数重排 wrapper：调用目标前把原始 R9
            // 放到目标 R8（消息对象），把原始 R8 放到目标 R9（正文
            // std::string）。因此在 wrapper 断点现场必须反向读取。
            const int arg_msg_index = 4;     // 原始 R9 -> 目标 R8
            uint64_t arg_msg = GetArgValue(ctx, arg_msg_index);
            uint64_t arg_content = GetArgValue(ctx, 3); // 原始 R8 -> 目标 R9

            OutputDebugPrintf("[Add2DB] arg_msg_index=%d, arg_msg=%p", arg_msg_index, (void *)arg_msg);

            if (arg_msg != 0 && IsMemoryReadable((void *)arg_msg, 0x100))
            {
                OutputDebugPrintf("[Add2DB] Message object is readable");

                std::string from_name;
                std::string content;

                const bool captured_by_helper = CaptureNotifyMessage(
                    arg_msg, arg_content, ctx->Rdx, from_name, content);
                OutputDebugPrintf("[Add2DB] unified capture=%d from=[%s] content=[%s]",
                    captured_by_helper ? 1 : 0, from_name.c_str(), content.c_str());

                // 尝试从消息对象中提取发送者和内容
                uint32_t msgType = FindLikelyMsgType(arg_msg);
                OutputDebugPrintf("[Add2DB] msgType=%u", msgType);

                // wrapper 的参数在不同调用点可能是正文或辅助 wxid；真正
                // 稳定的消息正文优先从消息对象固定字段读取。
                if (content.empty() && arg_content != 0 &&
                    ReadMsStdString((const StdString *)arg_content, content))
                {
                    content = PreviewFromField(content, msgType);
                }
                if (content.empty())
                {
                    static const size_t kContentOffsets[] = {
                        0x48, 0x2D0, 0x1A0, 0x18, 0x38
                    };
                    for (size_t offset : kContentOffsets)
                    {
                        std::string value;
                        if (ReadMsStdString((const StdString *)(arg_msg + offset), value))
                        {
                            value = PreviewFromField(value, msgType);
                            if (!value.empty())
                            {
                                content = value;
                                break;
                            }
                        }
                    }
                }

                // 扫描消息对象获取内容
                std::vector<ContentField> fields;
                size_t msgsourceOff = (size_t)-1;
                if (content.empty())
                    CollectContentFields(arg_msg, 0x500, msgType, fields, &msgsourceOff);
                OutputDebugPrintf("[Add2DB] CollectContentFields found %llu fields", (unsigned long long)fields.size());

                if (content.empty())
                {
                    content = PickContentField(fields, msgsourceOff);
                    OutputDebugPrintf("[Add2DB] PickContentField result: [%s]", content.c_str());
                }

                // 如果没有找到内容，尝试深度扫描
                if (content.empty())
                {
                    OutputDebugPrintf("[Add2DB] Content empty, trying deep scan...");
                    fields.clear();
                    int nested = 0;
                    for (size_t off = 0; off + 8 <= 0x200 && nested < 6; off += 8)
                    {
                        std::string occupied;
                        if (off + sizeof(StdString) <= 0x200 &&
                            ReadMsStdString((StdString *)(arg_msg + off), occupied) && !occupied.empty())
                        {
                            continue;
                        }
                        uint64_t child = 0;
                        if (!SafeReadBytes((void *)(arg_msg + off), &child, 8))
                            continue;
                        if (child == arg_msg || !LooksLikeHeapObject(child))
                            continue;
                        CollectContentFields(child, 0x400, msgType, fields, nullptr);
                        nested += 1;
                    }
                    content = PickContentField(fields, (size_t)-1);
                    OutputDebugPrintf("[Add2DB] Deep scan result: [%s]", content.c_str());
                }

                // 如果还是没有内容，用消息类型占位符
                if (content.empty() && msgType != 0 && msgType != 1)
                {
                    content = revoke_tip::messageKindPlaceholder(msgType);
                    OutputDebugPrintf("[Add2DB] Using placeholder: [%s]", content.c_str());
                }

                // 尝试提取发送者名称（从 wxid 字段或其他标识）
                for (size_t offset = 0; offset + sizeof(StdString) <= 0x300; offset += 8)
                {
                    StdString *ss = (StdString *)(arg_msg + offset);
                    std::string value;
                    if (ReadMsStdString(ss, value) && !value.empty())
                    {
                        // 查找看起来像 wxid 的字段作为发送者标识
                        if (revoke_tip::looksLikeWxId(value))
                        {
                            from_name = value;
                            OutputDebugPrintf("[Add2DB] Found wxid: [%s]", from_name.c_str());
                            break;
                        }
                    }
                }

                // 发送通知
                if (!content.empty())
                {
                    OutputDebugPrintf("[Add2DB] Calling SendWindowsNotification...");
                    SendWindowsNotification(from_name, content);
                }
                else
                {
                    OutputDebugPrintf("[Add2DB] Content is empty, skip notification");
                }
            }
            else
            {
                OutputDebugPrintf("[Add2DB] Message object not readable or null");
            }
        }

        if (!was_anti_revoke)
            return;

        if (!g_config_info.add2db_info.initialized)
        {
            int arg_bool_index = FindZeroArgIndex(ctx, 5, 8);
            if (arg_bool_index < 0)
                arg_bool_index = 5;

            int arg_msg_index = 3;
            uint64_t arg_msg = 0;
            StdString *found_xml = nullptr;
            int candidate_indices[] = { 3, 2, 4, 1 };
            for (int idx : candidate_indices)
            {
                uint64_t candidate = GetArgValue(ctx, idx);
                if (candidate == 0 || !IsMemoryReadable((void *)candidate, 0x100))
                    continue;
                found_xml = FindRevokePayload(candidate, 0x1000);
                if (found_xml != nullptr && found_xml->size > 0)
                {
                    arg_msg_index = idx;
                    arg_msg = candidate;
                    break;
                }
            }
            if (found_xml == nullptr || arg_msg == 0)
            {
                OutputDebugPrintf("[Debug] Add2DB: Cannot find revoke_xml, still forcing allow-new-id");
                ForceAllowNewId(ctx, arg_bool_index);
                return;
            }

            int xml_offset = (int)((uint64_t)found_xml - arg_msg);
            uint64_t mem_srvid_addr = FindSrvId(arg_msg, xml_offset > 0 ? (size_t)xml_offset : 0x200);
            if (mem_srvid_addr == 0)
            {
                static const int kSrvOff[] = { 0x148, 0x140, 0x150, 0x108, 0x100, 0x0F8, 0x110, 0x118, 0x130, 0x160 };
                for (int off : kSrvOff)
                {
                    if (IsMemoryReadable((void *)(arg_msg + off), 8) && ReadUint64At(arg_msg, off) != 0)
                    {
                        mem_srvid_addr = arg_msg + off;
                        break;
                    }
                }
            }
            if (mem_srvid_addr == 0)
            {
                OutputDebugPrintf("[Debug] Add2DB: srvid pattern miss, default +0x148");
                mem_srvid_addr = arg_msg + 0x148;
                if (!IsMemoryReadable((void *)mem_srvid_addr, 8))
                    mem_srvid_addr = 0;
            }
            if (mem_srvid_addr == 0)
            {
                OutputDebugPrintf("[Debug] Add2DB: Cannot find srvid, still applying tip");
            }

            g_config_info.add2db_info.arg_msg_index = arg_msg_index;
            g_config_info.add2db_info.arg_bool_index = arg_bool_index;
            g_config_info.add2db_info.offset_revoke_xml = xml_offset;
            g_config_info.add2db_info.offset_srvid = mem_srvid_addr
                ? (int)(mem_srvid_addr - arg_msg) : 0x148;
            g_config_info.add2db_info.initialized = true;
            OutputDebugPrintf("[Debug] Add2DB cached: msg_idx=%d, bool_idx=%d, xml_off=0x%X, srvid_off=0x%X",
                g_config_info.add2db_info.arg_msg_index,
                g_config_info.add2db_info.arg_bool_index,
                g_config_info.add2db_info.offset_revoke_xml,
                g_config_info.add2db_info.offset_srvid);
        }

        int arg_bool_index = g_config_info.add2db_info.arg_bool_index > 0
            ? g_config_info.add2db_info.arg_bool_index : 5;
        int arg_msg_index = g_config_info.add2db_info.arg_msg_index > 0
            ? g_config_info.add2db_info.arg_msg_index : 3;
        uint64_t arg_msg = GetArgValue(ctx, arg_msg_index);
        if (arg_msg == 0 || !IsMemoryReadable((void *)arg_msg, 0x100))
        {
            OutputDebugPrintf("[Debug] Add2DB: arg_msg invalid");
            ForceAllowNewId(ctx, arg_bool_index);
            return;
        }

        StdString *revoke_xml = (StdString *)(arg_msg + g_config_info.add2db_info.offset_revoke_xml);
        if (!IsMemoryReadable(revoke_xml, sizeof(StdString)) || revoke_xml->size <= 0)
        {
            OutputDebugPrintf("[Debug] Add2DB: revoke_xml invalid");
            ForceAllowNewId(ctx, arg_bool_index);
            return;
        }

        uint64_t mem_srvid_addr = arg_msg + g_config_info.add2db_info.offset_srvid;
        uint64_t revoke_xml_str_addr = *((uint64_t *)(revoke_xml->data_ptr));
        OutputDebugPrintf("[Debug] %p | Revoke XML: %s | bool_idx: %d",
            revoke_xml, (char *)revoke_xml_str_addr, arg_bool_index);

        uint8_t org_srvid[8] = { 0 };
        memcpy(org_srvid, (void *)mem_srvid_addr, 8);
        OutputDebugPrintf("[Debug] Org srvid: %p | Last srvid: %p",
            *((uint64_t *)org_srvid), *((uint64_t *)thread_state->last_org_srvid));
        if (memcmp(thread_state->last_org_srvid, org_srvid, 8) == 0)
        {
            ForceAllowNewId(ctx, arg_bool_index);
            return;
        }
        memcpy(thread_state->last_org_srvid, org_srvid, 8);

        std::vector<uint8_t> rand_srvid = GetUniquePositiveValue();
        if (rand_srvid.size() != 8)
        {
            OutputDebugString(TEXT("[RevokeHook] GetUniquePositiveValue Err!"));
            ForceAllowNewId(ctx, arg_bool_index);
            return;
        }
        memcpy((void *)mem_srvid_addr, rand_srvid.data(), rand_srvid.size());
        OutputDebugPrintf("[Debug] Replaced SrvID at %p", (void *)mem_srvid_addr);

        if (thread_state->pending_content[0] != '\0')
            revoke_tip::rememberContent(*((uint64_t *)org_srvid), thread_state->pending_content);
        if (!ApplyCustomTip(revoke_xml, *((uint64_t *)org_srvid), thread_state->pending_content))
        {
            uint8_t anchor[] = { 0xe4, 0xb8, 0x80, 0xe6, 0x9d, 0xa1 };
            uint8_t replace[] = { 0xe5, 0xa6, 0x82, 0xe4, 0xb8, 0x8a };
            uint8_t anchor_english[] = { 0x61, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65 };
            uint8_t replace_english[] = { 0x61, 0x62, 0x6f, 0x76, 0x65, 0x20, 0x6d, 0x73, 0x67 };
            for (int64_t i = 0; i < (int64_t)revoke_xml->size; i++)
            {
                if (i <= (int64_t)revoke_xml->size - (int64_t)sizeof(anchor) &&
                    memcmp((void *)(revoke_xml_str_addr + i), anchor, sizeof(anchor)) == 0)
                {
                    memcpy((void *)(revoke_xml_str_addr + i), replace, sizeof(replace));
                    OutputDebugPrintf("[Debug] Replace Revoke XML Success!");
                    break;
                }
                if (i <= (int64_t)revoke_xml->size - (int64_t)sizeof(anchor_english) &&
                    memcmp((void *)(revoke_xml_str_addr + i), anchor_english, sizeof(anchor_english)) == 0)
                {
                    memcpy((void *)(revoke_xml_str_addr + i), replace_english, sizeof(replace_english));
                    break;
                }
            }
        }

        ForceAllowNewId(ctx, arg_bool_index);
        OutputDebugPrintf("[Debug] Forced allow-new-id bool_idx=%d", arg_bool_index);
    }
}

void InitLog()
{
    if (g_hLogFile != INVALID_HANDLE_VALUE)
        return;
    if (!InitSelfDir())
    {
        OutputDebugStringA("[RevokeHook] Get module directory for log failed!");
        return;
    }

    wchar_t logPath[MAX_PATH] = {};
    _snwprintf_s(logPath, _TRUNCATE, L"%s\\RevokeHook.log", g_selfDir);

    g_hLogFile = CreateFileW(
        logPath,
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (g_hLogFile == INVALID_HANDLE_VALUE)
    {
        OutputDebugStringA("[RevokeHook] CreateFile Log Failed!");
        return;
    }

    OutputDebugPrintf("[RevokeHook] Log file: %ls", logPath);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        if (!InitThreadStateTls()) {
            OutputDebugString(TEXT("[RevokeHook] InitThreadStateTls Failed!"));
            break;
        }

        OutputDebugString(TEXT("[RevokeHook] Reading Config..."));
        if (!ReadExternalConfig()) break;
        OutputDebugString(TEXT("[RevokeHook] Begin Install VEH & Set Bp!"));

        if (g_output_debeug_msg) InitLog(); // 初始化日志文件

        if (g_block_update)
        {
            InterlockedExchange(&g_stopUpdateBlocker, 0);
            HANDLE th = CreateThread(nullptr, 0, UpdateBlockerThread, nullptr, 0, nullptr);
            if (th != nullptr)
            {
                CloseHandle(th);
                OutputDebugPrintf("[RevokeHook] Update blocker started");
            }
        }

        if (!VehBp_Init(TRUE))
        {
            OutputDebugString(_T("[RevokeHook] VEHBp Init failed!"));
            return TRUE;
        }

		g_bpDelMsg = (void*)(g_config_info.basic_info.imgbase + g_config_info.basic_info.delmsg_offset);
        g_bpAdd2DB = (void*)(g_config_info.basic_info.imgbase + g_config_info.basic_info.add2db_offset);

        if (VehBp_Set(g_bpDelMsg, OnTargetHit) == -1)
            OutputDebugPrintf("[RevokeHook] AddBp %p Error", g_bpDelMsg);
        else
            OutputDebugPrintf("[RevokeHook] AddBp %p OK", g_bpDelMsg);

        DiscoverAdd2DBTargetBreakpoint();

        if (VehBp_Set(g_bpAdd2DB, OnTargetHit) == -1)
            OutputDebugPrintf("[RevokeHook] AddBp %p Error", g_bpAdd2DB);
        else
            OutputDebugPrintf("[RevokeHook] AddBp %p OK", g_bpAdd2DB);

        // 初始化 IAT Hook 来拦截通知 API
        OutputDebugPrintf("[RevokeHook] g_notify_new_message = %d", g_notify_new_message);
        if (g_notify_new_message)
        {
            if (InitNotifyIatHook())
                OutputDebugPrintf("[RevokeHook] Shell_NotifyIconW hook enabled");
            else
                OutputDebugPrintf("[RevokeHook] Shell_NotifyIconW hook unavailable");
        }
        else
        {
            OutputDebugPrintf("[RevokeHook] Skipping inline hooks (notify_new_message is disabled)");
        }

        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        InterlockedExchange(&g_stopUpdateBlocker, 1);
        OutputDebugString(TEXT("[RevokeHook] Uninstall VEH & Cancel Bp!"));
        VehBp_Uninit();
        FreeCurrentThreadState();
        UninitThreadStateTls();
        if (g_hLogFile != INVALID_HANDLE_VALUE)
        {
            CloseHandle(g_hLogFile);
            g_hLogFile = INVALID_HANDLE_VALUE;
		}
        break;
    }
    return TRUE;
}


