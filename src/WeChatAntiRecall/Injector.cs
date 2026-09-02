using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Text;

namespace WeChatAntiRecall;

internal static class Injector
{
    // Must match native/RevokeHook/RevokeHook/dllmain.cpp
    private const string RuntimeMapName = @"Local\WeChatAntiRecall.Runtime.v1";
    private const uint RuntimeMagic = 0x31524857; // WHR1
    private const int RuntimePayloadSize = 12;

    public static void Inject(int pid, string dllPath, int delMsgOffset, int add2DbOffset)
    {
        if (delMsgOffset == 0 || add2DbOffset == 0)
        {
            throw new InvalidOperationException($"无效偏移: DelMsg=0x{delMsgOffset:X} Add2DB=0x{add2DbOffset:X}");
        }

        using var mmf = MemoryMappedFile.CreateOrOpen(RuntimeMapName, RuntimePayloadSize);
        using var view = mmf.CreateViewAccessor(0, RuntimePayloadSize);
        view.Write(0, RuntimeMagic);
        view.Write(4, delMsgOffset);
        view.Write(8, add2DbOffset);
        view.Flush();

        InjectProcess(pid, dllPath);
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

            if (!WriteProcessMemory(process, remote, bytes, (nuint)bytes.Length, out _))
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
                WaitForSingleObject(thread, 15000);
            }
            finally
            {
                CloseHandle(thread);
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
    private static extern bool CloseHandle(nint hObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(nint processHandle, uint desiredAccess, out nint tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, out long lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(nint tokenHandle, bool disableAllPrivileges, ref TokenPrivileges newState, int bufferLength, nint previousState, nint returnLength);
}
