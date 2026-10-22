using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Text;

namespace GreenSoftAntiRecall;

internal static class Injector
{
    // Must match native/RevokeHook/RevokeHook/dllmain.cpp
    private const string RuntimeMapName = @"Local\GreenSoftAntiRecall.Runtime.v2.";
    private const uint RuntimeMagic = 0x32524857;
    private const int RuntimePayloadSize = 20;

    public static void Inject(int pid, string dllPath, int delMsgOffset, int add2DbOffset, string expectedModulePath)
    {
        if (delMsgOffset == 0 || add2DbOffset == 0)
        {
            throw new InvalidOperationException($"无效偏移: DelMsg=0x{delMsgOffset:X} Add2DB=0x{add2DbOffset:X}");
        }

        using var mutex = new Mutex(false, RuntimeMapName + pid + ".inject");
        bool acquired;
        try { acquired = mutex.WaitOne(0); }
        catch (AbandonedMutexException) { acquired = true; }
        if (!acquired)
            throw new InvalidOperationException("另一个启动器正在注入此进程，请等待其完成。");
        try
        {
            using var target = Process.GetProcessById(pid);
            var loadedModule = target.Modules.Cast<ProcessModule>().FirstOrDefault(module =>
                string.Equals(module.ModuleName, TargetApp.ModuleName, StringComparison.OrdinalIgnoreCase));
            if (loadedModule is null || !string.Equals(Path.GetFullPath(loadedModule.FileName),
                Path.GetFullPath(expectedModulePath), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("运行中的目标主模块与偏移搜索使用的文件不一致，请彻底退出某绿色软件后重试。");
            if (target.Modules.Cast<ProcessModule>().Any(module =>
                string.Equals(module.ModuleName, "RevokeHook.dll", StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException("此进程已加载 RevokeHook.dll，无法重新校验或应用新配置。请彻底退出某绿色软件后再运行启动器。");

            using var mmf = MemoryMappedFile.CreateNew(RuntimeMapName + pid, RuntimePayloadSize);
            using var view = mmf.CreateViewAccessor(0, RuntimePayloadSize);
            view.Write(0, RuntimeMagic);
            view.Write(4, delMsgOffset);
            view.Write(8, add2DbOffset);
            view.Write(12, pid);
            view.Write(16, 0);
            view.Flush();

            InjectProcess(pid, dllPath);
            var timer = Stopwatch.StartNew();
            while (timer.Elapsed < TimeSpan.FromSeconds(60))
            {
                if (target.HasExited)
                    throw new InvalidOperationException("初始化期间某绿色软件已退出。");
                var status = view.ReadInt32(16);
                if (status == 1)
                    return;
                if (status < 0)
                {
                    var reason = status switch
                    {
                        -1 => "线程状态初始化失败",
                        -2 => "配置或运行时偏移读取失败",
                        -3 => "VEH 异常处理器安装失败",
                        -4 => "偏移不在可执行区域或不是预期的 CALL 指令",
                        -5 => "防撤回断点安装失败",
                        -6 => "消息目标入口断点安装失败",
                        -7 => "消息入库断点安装失败",
                        -8 => "新消息通知 FlashWindowEx 拦截安装失败",
                        -9 => "更新拦截安装或工作线程创建失败",
                        -10 => "DLL 初始化发生异常",
                        _ => $"未知初始化错误 {status}",
                    };
                    throw new InvalidOperationException(reason + "。可能已有部分 Hook 生效，请彻底退出某绿色软件后重试。");
                }
                Thread.Sleep(100);
            }
            throw new TimeoutException("DLL 已加载，但 60 秒内未收到初始化成功确认。请彻底退出某绿色软件后重试。");
        }
        finally
        {
            mutex.ReleaseMutex();
        }
    }

    private static void InjectProcess(int pid, string dllPath)
    {
        if (!File.Exists(dllPath))
        {
            throw new FileNotFoundException("找不到 RevokeHook.dll", dllPath);
        }

        EnableDebugPrivilege();
        var process = OpenProcess(
            ProcessAccessFlags.CreateThread | ProcessAccessFlags.QueryInformation |
            ProcessAccessFlags.VirtualMemoryOperation | ProcessAccessFlags.VirtualMemoryWrite |
            ProcessAccessFlags.VirtualMemoryRead, false, pid);
        if (process == nint.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"OpenProcess({pid}) 失败");
        }

        try
        {
            var fullPath = Path.GetFullPath(dllPath);
            var bytes = Encoding.Unicode.GetBytes(fullPath + "\0");
            var remote = VirtualAllocEx(process, nint.Zero, (nuint)bytes.Length, 0x3000, 0x04);
            if (remote == nint.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualAllocEx 失败");
            }

            bool threadCompleted = true;
            try
            {
                if (!WriteProcessMemory(process, remote, bytes, (nuint)bytes.Length, out var written) || written != (nuint)bytes.Length)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "WriteProcessMemory 失败");
                }

                var kernel = GetModuleHandle("kernel32.dll");
                var loadLibrary = GetProcAddress(kernel, "LoadLibraryW");
                if (loadLibrary == nint.Zero)
                {
                    throw new InvalidOperationException("GetProcAddress(LoadLibraryW) 失败");
                }

                var thread = CreateRemoteThread(process, nint.Zero, 0, loadLibrary, remote, 0, nint.Zero);
                if (thread == nint.Zero)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateRemoteThread 失败");
                }

                try
                {
                    threadCompleted = false;
                    var wait = WaitForSingleObject(thread, 15000);
                    if (wait == 0xFFFFFFFF)
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "等待 DLL 加载失败");
                    if (wait != 0)
                        throw new TimeoutException("DLL 加载超时，未确认注入成功。请彻底退出某绿色软件后重试。");
                    threadCompleted = true;
                    if (!GetExitCodeThread(thread, out var exitCode))
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "读取 DLL 加载结果失败");
                    using var target = Process.GetProcessById(pid);
                    if (!target.Modules.Cast<ProcessModule>().Any(module =>
                        string.Equals(module.FileName, fullPath, StringComparison.OrdinalIgnoreCase)))
                        throw new InvalidOperationException($"LoadLibraryW 未加载目标 DLL（线程结果 0x{exitCode:X8}）。");
                }
                finally
                {
                    CloseHandle(thread);
                }
            }
            finally
            {
                if (threadCompleted)
                    VirtualFreeEx(process, remote, 0, 0x8000);
            }
        }
        finally
        {
            CloseHandle(process);
        }
    }

    private static void EnableDebugPrivilege()
    {
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, 0x28, out var token))
        {
            return;
        }

        try
        {
            if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out var luid))
            {
                return;
            }

            var tp = new TokenPrivileges
            {
                PrivilegeCount = 1,
                Luid = luid,
                Attributes = 2,
            };
            AdjustTokenPrivileges(token, false, ref tp, 0, nint.Zero, nint.Zero);
        }
        finally
        {
            CloseHandle(token);
        }
    }

    [Flags]
    private enum ProcessAccessFlags : uint
    {
        CreateThread = 0x0002,
        VirtualMemoryOperation = 0x0008,
        VirtualMemoryRead = 0x0010,
        VirtualMemoryWrite = 0x0020,
        QueryInformation = 0x0400,
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        public int PrivilegeCount;
        public long Luid;
        public int Attributes;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint VirtualAllocEx(nint hProcess, nint lpAddress, nuint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(nint hProcess, nint lpBaseAddress, byte[] lpBuffer, nuint nSize, out nuint lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern nint GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
    private static extern nint GetProcAddress(nint hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint CreateRemoteThread(nint hProcess, nint lpThreadAttributes, nuint dwStackSize, nint lpStartAddress, nint lpParameter, uint dwCreationFlags, nint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(nint hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeThread(nint hThread, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualFreeEx(nint hProcess, nint address, nuint size, uint freeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(nint processHandle, uint desiredAccess, out nint tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, out long lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(nint tokenHandle, bool disableAllPrivileges, ref TokenPrivileges newState, int bufferLength, nint previousState, nint returnLength);
}
