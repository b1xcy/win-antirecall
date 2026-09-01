using System.Diagnostics;
using System.IO;
using WeChatAntiRecall.Services;

namespace WeChatAntiRecall;

internal static class UpdateBlocker
{
    public static void Apply(Action<string>? log = null)
    {
        KillUpdater(log);

        var install = WindowsSystemService.TryGetWeChatInstallPath();
        if (string.IsNullOrWhiteSpace(install) || !Directory.Exists(install))
        {
            return;
        }

        foreach (var exe in Directory.EnumerateFiles(install, "WeixinUpdate.exe", SearchOption.AllDirectories))
        {
            TryDisableUpdater(exe, log);
        }
    }

    public static void KillUpdater(Action<string>? log = null)
    {
        foreach (var proc in Process.GetProcessesByName("WeixinUpdate"))
        {
            try
            {
                proc.Kill(entireProcessTree: true);
                log?.Invoke($"已结束 WeixinUpdate.exe pid={proc.Id}");
            }
            catch (Exception ex)
            {
                log?.Invoke($"结束 WeixinUpdate.exe 失败: {ex.Message}");
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
}
