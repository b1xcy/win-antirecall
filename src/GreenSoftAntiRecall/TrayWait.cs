using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace GreenSoftAntiRecall;

internal static class TrayWait
{
    private static readonly string TrayClassHint = TargetApp.TrayWindowClass;

    public static string? GetInstallPath()
    {
        using var key = Registry.CurrentUser.OpenSubKey(TargetApp.InstallRegistryKey);
        return key?.GetValue("InstallPath") as string;
    }

    public static string? GetExecutablePath()
    {
        var install = GetInstallPath();
        if (string.IsNullOrWhiteSpace(install))
        {
            return null;
        }

        var exe = Path.Combine(install, TargetApp.ExecutableName);
        return File.Exists(exe) ? exe : null;
    }

    public static void StartTarget()
    {
        var exe = GetExecutablePath() ?? throw new InvalidOperationException("找不到目标程序主文件，请确认已安装某绿色软件 4.x。");
        if (Process.GetProcessesByName(TargetApp.ProcessName).Length > 0)
        {
            return;
        }

        var start = new ProcessStartInfo
        {
            FileName = exe,
            WorkingDirectory = Path.GetDirectoryName(exe) ?? "",
            UseShellExecute = true,
        };
        Process.Start(start);
    }

    public static int WaitForLoginPid(Action<string>? log = null)
    {
        if (!WaitUntilTargetRunning(TimeSpan.FromSeconds(30), log))
        {
            throw new InvalidOperationException("某绿色软件未能启动。");
        }

        var lastLog = DateTime.MinValue;
        while (true)
        {
            var hwnd = FindTrayHwnd();
            if (hwnd != nint.Zero)
            {
                GetWindowThreadProcessId(hwnd, out var pid);
                if (pid != 0)
                {
                    return pid;
                }
            }

            if (!IsTargetRunning())
            {
                throw new GreenSoftExitedException("某绿色软件已退出（未登录）。");
            }

            if (DateTime.UtcNow - lastLog > TimeSpan.FromSeconds(5))
            {
                lastLog = DateTime.UtcNow;
                log?.Invoke("等待登录托盘...");
            }

            Thread.Sleep(400);
        }
    }

    public static bool IsTargetRunning()
    {
        return Process.GetProcessesByName(TargetApp.ProcessName).Length > 0;
    }

    private static bool WaitUntilTargetRunning(TimeSpan timeout, Action<string>? log)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (IsTargetRunning())
            {
                return true;
            }

            Thread.Sleep(200);
        }

        log?.Invoke("等待目标程序进程超时。");
        return IsTargetRunning();
    }

    private static nint FindTrayHwnd()
    {
        nint found = nint.Zero;
        EnumWindows((hwnd, _) =>
        {
            var cls = new StringBuilder(256);
            if (GetClassName(hwnd, cls, cls.Capacity) > 0 &&
                cls.ToString().Contains(TrayClassHint, StringComparison.OrdinalIgnoreCase))
            {
                found = hwnd;
                return false;
            }

            var title = new StringBuilder(256);
            if (GetWindowText(hwnd, title, title.Capacity) > 0 &&
                string.Equals(title.ToString(), TrayClassHint, StringComparison.OrdinalIgnoreCase))
            {
                found = hwnd;
                return false;
            }

            return true;
        }, nint.Zero);

        if (found == nint.Zero)
        {
            found = FindWindow(null, TrayClassHint);
        }

        return found;
    }

    private delegate bool EnumWindowsProc(nint hWnd, nint lParam);

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, nint lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassName(nint hWnd, StringBuilder lpClassName, int nMaxCount);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(nint hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern nint FindWindow(string? lpClassName, string? lpWindowName);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(nint hWnd, out int lpdwProcessId);
}

internal sealed class GreenSoftExitedException : Exception
{
    public GreenSoftExitedException(string message) : base(message)
    {
    }
}
