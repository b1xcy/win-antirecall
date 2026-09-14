using System.Diagnostics;
using System.IO;
using WeChatAntiRecall.Services;

namespace WeChatAntiRecall;

internal static class UpdateBlocker
{
    private const string UsersSid = "*S-1-5-32-545";
    private const int ScanDepth = 2;

    private static readonly string[] KnownUpdaterProcessNames =
    [
        "WeixinUpdate",
        "WeChatUpdate",
    ];

    private static readonly string[] XWeChatProtectRel =
    [
        @"XPlugin\Plugins\WeixinUpdate",
        "update",
    ];

    private static readonly string[] UpdateTaskNames =
    [
        @"\Tencent\WeChatUpdate",
        @"\Tencent\WeixinUpdate",
        @"\WeChatUpdate",
        @"\WeixinUpdate",
    ];

    public static void Apply(Action<string>? log = null)
    {
        var updaters = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var protectedDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var install = WindowsSystemService.TryGetWeChatInstallPath();
        if (!string.IsNullOrWhiteSpace(install) && Directory.Exists(install))
        {
            FindUpdaters(install, 0, updaters);
        }

        PrepareXWeChatDirs(protectedDirs);
        foreach (var dir in protectedDirs)
        {
            FindUpdaters(dir, 0, updaters);
        }

        KillUpdaters(updaters, log);

        foreach (var exe in updaters)
        {
            if (string.Equals(Path.GetFileName(exe), "WeixinUpdate.exe", StringComparison.OrdinalIgnoreCase))
            {
                TryDisableUpdater(exe, log);
            }

            SetAclDeny(exe, log);
            SetAclDeny(exe + ".bak", log);
        }

        foreach (var dir in protectedDirs)
        {
            SetDirAclDeny(dir, log);
        }

        DisableScheduledTasks(log);
    }

    public static void KillUpdater(Action<string>? log = null)
    {
        KillUpdaters(null, log);
    }

    private static void KillUpdaters(IEnumerable<string>? updaterPaths, Action<string>? log)
    {
        var names = new HashSet<string>(KnownUpdaterProcessNames, StringComparer.OrdinalIgnoreCase);
        if (updaterPaths is not null)
        {
            foreach (var path in updaterPaths)
            {
                names.Add(Path.GetFileNameWithoutExtension(path));
            }
        }

        foreach (var name in names)
        {
            foreach (var proc in Process.GetProcessesByName(name))
            {
                try
                {
                    proc.Kill(entireProcessTree: true);
                    log?.Invoke($"已结束 {name}.exe pid={proc.Id}");
                }
                catch (Exception ex)
                {
                    log?.Invoke($"结束 {name}.exe 失败: {ex.Message}");
                }
            }
        }
    }

    private static void TryDisableUpdater(string exePath, Action<string>? log)
    {
        try
        {
            var bak = exePath + ".bak";
            if (!File.Exists(bak))
            {
                File.Move(exePath, bak);
                log?.Invoke($"已禁用 {exePath}");
            }
            else if (File.Exists(exePath))
            {
                File.Delete(exePath);
                log?.Invoke($"已删除重新出现的 {exePath}");
            }

            var stub = Path.Combine(AppContext.BaseDirectory, "update_stub.exe");
            if (File.Exists(stub) && !File.Exists(exePath))
            {
                File.Copy(stub, exePath, overwrite: false);
            }
        }
        catch (Exception ex)
        {
            log?.Invoke($"无法改写 {exePath}（可能需要管理员）: {ex.Message}");
        }
    }

    private static void FindUpdaters(string dir, int depth, ISet<string> hits)
    {
        try
        {
            foreach (var exe in Directory.EnumerateFiles(dir, "*.exe"))
            {
                if (Path.GetFileName(exe).Contains("update", StringComparison.OrdinalIgnoreCase))
                {
                    hits.Add(exe);
                }
            }
        }
        catch
        {
        }

        if (depth >= ScanDepth)
        {
            return;
        }

        try
        {
            foreach (var sub in Directory.EnumerateDirectories(dir))
            {
                FindUpdaters(sub, depth + 1, hits);
            }
        }
        catch
        {
        }
    }

    private static void PrepareXWeChatDirs(ISet<string> protectedDirs)
    {
        var root = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"Tencent\xwechat");
        if (!Directory.Exists(root))
        {
            return;
        }

        foreach (var rel in XWeChatProtectRel)
        {
            var dir = Path.Combine(root, rel);
            if (!Directory.Exists(dir))
            {
                try
                {
                    Directory.CreateDirectory(dir);
                }
                catch
                {
                    continue;
                }
            }

            if (Directory.Exists(dir))
            {
                protectedDirs.Add(dir);
            }
        }
    }

    private static void SetAclDeny(string path, Action<string>? log)
    {
        if (!File.Exists(path))
        {
            return;
        }

        var icacls = Path.Combine(Environment.SystemDirectory, "icacls.exe");
        RunTool(icacls, $"\"{path}\" /remove:d {UsersSid}");
        if (RunTool(icacls, $"\"{path}\" /deny {UsersSid}:(RX)") == 0)
        {
            log?.Invoke($"已拒绝执行 {path}");
        }
        else
        {
            log?.Invoke($"拒绝执行失败（可能需要管理员）: {path}");
        }
    }

    private static void SetDirAclDeny(string path, Action<string>? log)
    {
        if (!Directory.Exists(path))
        {
            return;
        }

        var icacls = Path.Combine(Environment.SystemDirectory, "icacls.exe");
        RunTool(icacls, $"\"{path}\" /remove:d {UsersSid} /t /c");
        if (RunTool(icacls, $"\"{path}\" /deny {UsersSid}:(OI)(CI)(RX,WD,AD,DC,WA,WEA) /c") == 0)
        {
            log?.Invoke($"已锁定目录 {path}");
        }
        else
        {
            log?.Invoke($"锁定目录失败（可能需要管理员）: {path}");
        }
    }

    private static void DisableScheduledTasks(Action<string>? log)
    {
        var schtasks = Path.Combine(Environment.SystemDirectory, "schtasks.exe");
        var found = false;
        foreach (var name in UpdateTaskNames)
        {
            if (RunTool(schtasks, $"/query /tn \"{name}\"") != 0)
            {
                continue;
            }

            found = true;
            if (RunTool(schtasks, $"/change /tn \"{name}\" /disable") == 0)
            {
                log?.Invoke($"已禁用计划任务 {name}");
            }
            else
            {
                log?.Invoke($"禁用计划任务失败（可能需要管理员）: {name}");
            }
        }

        if (!found)
        {
            log?.Invoke("未发现微信更新计划任务（已跳过）");
        }
    }

    private static int RunTool(string fileName, string arguments)
    {
        try
        {
            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            if (proc is null)
            {
                return -1;
            }

            return proc.WaitForExit(20000) ? proc.ExitCode : -1;
        }
        catch
        {
            return -1;
        }
    }
}
