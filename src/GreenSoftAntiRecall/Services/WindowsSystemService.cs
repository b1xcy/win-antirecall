using System.IO;
using Microsoft.Win32;

namespace GreenSoftAntiRecall.Services;

public static class WindowsSystemService
{
    public static string? TryGetInstallPath()
    {
        using var key = Registry.CurrentUser.OpenSubKey(TargetApp.InstallRegistryKey);
        var installPath = key?.GetValue("InstallPath") as string;
        return string.IsNullOrWhiteSpace(installPath) ? null : installPath;
    }

    public static string? TryGetVersion()
    {
        using var key = Registry.CurrentUser.OpenSubKey(TargetApp.InstallRegistryKey);
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

    public static string? TryGetModulePath()
    {
        using var key = Registry.CurrentUser.OpenSubKey(TargetApp.InstallRegistryKey);
        var installPath = key?.GetValue("InstallPath") as string;
        var version = TryGetVersion();

        if (string.IsNullOrWhiteSpace(installPath) || string.IsNullOrWhiteSpace(version))
        {
            return null;
        }

        var modulePath = Path.Combine(installPath, version, TargetApp.ModuleName);
        if (File.Exists(modulePath))
        {
            return modulePath;
        }

        return Directory.GetDirectories(installPath)
            .Select(dir => Path.Combine(dir, TargetApp.ModuleName))
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
