using System.IO;
using Microsoft.Win32;

namespace WeChatAntiRecall.Services;

public static class WindowsSystemService
{
    public static string? TryGetWeChatInstallPath()
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Tencent\Weixin");
        var installPath = key?.GetValue("InstallPath") as string;
        return string.IsNullOrWhiteSpace(installPath) ? null : installPath;
    }

    public static string? TryGetWeChatVersion()
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Tencent\Weixin");
        if (key is null)
        {
            return null;
        }

        if (key.GetValue("Version") is int versionValue && versionValue != 0)
        {
            var main = (versionValue >> 16) & 0xF;
            var sub = (versionValue >> 12) & 0xF;
            var third = (versionValue >> 8) & 0xF;
            var build = versionValue & 0xFF;
            return $"{main}.{sub}.{third}.{build}";
        }

        var installPath = key.GetValue("InstallPath") as string;
        if (string.IsNullOrWhiteSpace(installPath) || !Directory.Exists(installPath))
        {
            return null;
        }

        var versionDir = Directory.GetDirectories(installPath)
            .Select(Path.GetFileName)
            .Where(name => !string.IsNullOrWhiteSpace(name) && name.Contains('.'))
            .OrderByDescending(BuildVersionSortKey)
            .FirstOrDefault();

        return versionDir;
    }

    public static string? TryGetWeChatDllPath()
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Tencent\Weixin");
        var installPath = key?.GetValue("InstallPath") as string;
        var version = TryGetWeChatVersion();

        if (string.IsNullOrWhiteSpace(installPath) || string.IsNullOrWhiteSpace(version))
        {
            return null;
        }

        var dllPath = Path.Combine(installPath, version, "Weixin.dll");
        if (File.Exists(dllPath))
        {
            return dllPath;
        }

        return Directory.GetDirectories(installPath)
            .Select(dir => Path.Combine(dir, "Weixin.dll"))
            .Where(File.Exists)
            .OrderByDescending(path => BuildVersionSortKey(Path.GetFileName(Path.GetDirectoryName(path))))
            .FirstOrDefault();
    }

    private static string BuildVersionSortKey(string? version)
    {
        if (string.IsNullOrWhiteSpace(version))
        {
            return string.Empty;
        }

        return string.Join(
            '.',
            version.Split('.', StringSplitOptions.RemoveEmptyEntries)
                .Select(part => int.TryParse(part, out var value) ? value.ToString("D5") : part));
    }
}
