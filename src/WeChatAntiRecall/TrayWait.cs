using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace WeChatAntiRecall;

internal static class TrayWait
{
    private const string TrayClassHint = "WxTrayIconMessageWindow";

    public static string? GetInstallPath()
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Tencent\Weixin");
        return key?.GetValue("InstallPath") as string;
    }

    public static string? GetWeixinExePath()
    {
        var install = GetInstallPath();
        if (string.IsNullOrWhiteSpace(install))
        {
            return null;
        }

        var exe = Path.Combine(install, "Weixin.exe");
        return File.Exists(exe) ? exe : null;
    }

    public static void StartWeChat()
    {
        var exe = GetWeixinExePath() ?? throw new InvalidOperationException("找不到 Weixin.exe，请确认已安装微信 4.x。");
        if (Process.GetProcessesByName("Weixin").Length > 0)
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
        if (!WaitUntilWeixinRunning(TimeSpan.FromSeconds(30), log))
        {
            throw new InvalidOperationException("微信未能启动。");
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

            if (!IsWeixinRunning())
            {
                throw new WeChatExitedException("微信已退出（未登录）。");
            }

            if (DateTime.UtcNow - lastLog > TimeSpan.FromSeconds(5))
            {
                lastLog = DateTime.UtcNow;
                log?.Invoke("等待登录托盘...");
            }

            Thread.Sleep(400);
        }
    }

    public static bool IsWeixinRunning()
    {
        return Process.GetProcessesByName("Weixin").Length > 0;
    }

    private static bool WaitUntilWeixinRunning(TimeSpan timeout, Action<string>? log)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (IsWeixinRunning())
            {
                return true;
            }

            Thread.Sleep(200);
        }

        log?.Invoke("等待 Weixin.exe 进程超时。");
        return IsWeixinRunning();
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

internal sealed class WeChatExitedException : Exception
{
    public WeChatExitedException(string message) : base(message)
    {
    }
}
