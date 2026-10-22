using System.Diagnostics;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;
using GreenSoftAntiRecall.Services;

namespace GreenSoftAntiRecall;

internal static class UpdateBlocker
{
    private const string UsersSid = "*S-1-5-32-545";
    private const int ScanDepth = 2;
    private static readonly string StatePath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "GreenSoftAntiRecall", "update-blocker-state.json");
    private static readonly string LegacyStatePath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            TargetApp.LegacyStateDirectory, "update-blocker-state.json");

    private static Dictionary<string, string> LoadState()
    {
        MigrateLegacyState();
        return File.Exists(StatePath)
            ? JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(StatePath))
                ?? throw new InvalidDataException("更新恢复记录为空，停止修改。")
            : new(StringComparer.OrdinalIgnoreCase);
    }

    private static void MigrateLegacyState()
    {
        if (File.Exists(StatePath) || !File.Exists(LegacyStatePath))
            return;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(StatePath)!);
            File.Copy(LegacyStatePath, StatePath, overwrite: false);
        }
        catch
        {
            // 迁移失败时退回旧版恢复路径，不影响后续操作。
        }
    }

    private static void SaveState(Dictionary<string, string> state)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(StatePath)!);
        File.WriteAllText(StatePath + ".tmp", JsonSerializer.Serialize(state));
        File.Move(StatePath + ".tmp", StatePath, overwrite: true);
    }

    private static FileSystemSecurity ReadAcl(string path) => Directory.Exists(path)
        ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access)
        : new FileInfo(path).GetAccessControl(AccessControlSections.Access);

    private static void WriteAcl(string path, FileSystemSecurity acl)
    {
        if (acl is DirectorySecurity directoryAcl)
            new DirectoryInfo(path).SetAccessControl(directoryAcl);
        else
            new FileInfo(path).SetAccessControl((FileSecurity)acl);
    }

    private static void RememberAcl(string path)
    {
        var state = LoadState();
        var key = "acl:" + path;
        if (state.ContainsKey(key))
            return;
        state[key] = ReadAcl(path).GetSecurityDescriptorSddlForm(AccessControlSections.Access);
        SaveState(state);
    }

    public static void Restore(Action<string>? log = null)
    {
        var state = LoadState();
        if (state.Count == 1 && state.ContainsKey("legacy-restored"))
        {
            log?.Invoke("更新限制已恢复，无待恢复记录。");
            return;
        }
        if (Process.GetProcessesByName(TargetApp.ProcessName).Length != 0)
            throw new InvalidOperationException("恢复更新前请彻底退出某绿色软件，避免已注入的 DLL 继续拦截更新；随后重新运行启动器。");

        var legacy = !state.ContainsKey("legacy-restored");
        var recordedTasks = state.Keys.Where(key => key.StartsWith("task:", StringComparison.Ordinal)).ToHashSet();
        state["restore-pending"] = "true";
        SaveState(state);
        foreach (var item in state.ToArray())
        {
            if (item.Key.StartsWith("acl:", StringComparison.Ordinal))
            {
                var path = item.Key[4..];
                if (File.Exists(path) || Directory.Exists(path))
                {
                    var acl = ReadAcl(path);
                    acl.SetSecurityDescriptorSddlForm(item.Value, AccessControlSections.Access);
                    WriteAcl(path, acl);
                    log?.Invoke($"已恢复原权限 {path}");
                }
            }
            else if (item.Key.StartsWith("task:", StringComparison.Ordinal))
            {
                var name = item.Key[5..];
                var option = item.Value == "true" ? "/enable" : "/disable";
                if (RunTool(Path.Combine(Environment.SystemDirectory, "schtasks.exe"),
                    $"/change /tn \"{name}\" {option}") != 0)
                    throw new IOException($"恢复计划任务失败: {name}（可能需要管理员权限）");
                log?.Invoke($"已恢复计划任务原状态 {name}");
            }
            else
                continue;
        }

        var roots = new List<string>();
        var install = WindowsSystemService.TryGetInstallPath();
        if (!string.IsNullOrWhiteSpace(install) && Directory.Exists(install))
            roots.Add(install);
        var appData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), TargetApp.AppDataRelativeRoot);
        roots.AddRange(TargetApp.ProtectedRelativeDirectories.Select(rel => Path.Combine(appData, rel)).Where(Directory.Exists));
        foreach (var root in roots)
            RestoreLegacyTree(root, 0, legacy, root != install, log);
        if (legacy)
        {
            var schtasks = Path.Combine(Environment.SystemDirectory, "schtasks.exe");
            foreach (var name in TargetApp.UpdateTaskNames)
            {
                if (recordedTasks.Contains("task:" + name) || RunTool(schtasks, $"/query /tn \"{name}\"") != 0)
                    continue;
                if (RunTool(schtasks, $"/change /tn \"{name}\" /enable") != 0)
                    throw new IOException($"恢复旧版更新计划任务失败: {name}（可能需要管理员权限）");
                log?.Invoke($"旧版无原始状态记录，已启用已知更新任务 {name}");
            }
        }
        state.Clear();
        state["legacy-restored"] = "true";
        SaveState(state);
        log?.Invoke("更新器、目录权限和计划任务恢复完成；旧版曾删除的 UpdateNotify 文件无法还原。");
    }

    private static void RestoreLegacyTree(string path, int depth, bool legacy, bool protectedDir, Action<string>? log)
    {
        if (legacy && protectedDir)
            RemoveLegacyDeny(path);
        foreach (var file in Directory.EnumerateFiles(path))
        {
            var name = Path.GetFileName(file);
            if (!name.Contains("update", StringComparison.OrdinalIgnoreCase) ||
                !(name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".exe.bak", StringComparison.OrdinalIgnoreCase)))
                continue;
            if (legacy)
                RemoveLegacyDeny(file);
            if (!name.Equals(TargetApp.UpdaterExecutableName + ".bak", StringComparison.OrdinalIgnoreCase))
                continue;
            var exe = file[..^4];
            var stub = Path.Combine(AppContext.BaseDirectory, "update_stub.exe");
            if (legacy && File.Exists(exe))
                RemoveLegacyDeny(exe);
            if (File.Exists(exe))
            {
                var state = LoadState();
                var expected = state.GetValueOrDefault("stub:" + exe);
                if (expected is null && File.Exists(stub))
                    expected = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(stub)));
                if (expected is null || expected != Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(exe))))
                    throw new IOException($"更新器已被其他版本替换或旧版 stub 无法确认，保留备份，未覆盖: {exe}");
            }
            File.Move(file, exe, overwrite: true);
            log?.Invoke($"已恢复更新器 {exe}");
        }
        if (depth < ScanDepth)
            foreach (var child in Directory.EnumerateDirectories(path))
                RestoreLegacyTree(child, depth + 1, legacy, protectedDir, log);
    }

    private static void RemoveLegacyDeny(string path)
    {
        var acl = ReadAcl(path);
        bool changed = false;
        var rights = FileSystemRights.ReadAndExecute;
        if (Directory.Exists(path))
            rights |= FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.DeleteSubdirectoriesAndFiles |
                FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes;
        var descriptor = new RawSecurityDescriptor(acl.GetSecurityDescriptorBinaryForm(), 0);
        var rules = descriptor.DiscretionaryAcl!;
        var expectedFlags = Directory.Exists(path) ? AceFlags.ContainerInherit | AceFlags.ObjectInherit : AceFlags.None;
        for (var index = rules.Count - 1; index >= 0; index--)
        {
            if (rules[index] is not CommonAce rule || rule.IsCallback || rule.AceQualifier != AceQualifier.AccessDenied ||
                rule.SecurityIdentifier.Value != "S-1-5-32-545" || rule.AceFlags != expectedFlags ||
                ((rule.AccessMask & (int)rights) != (int)rights && rule.AccessMask != (int)FileSystemRights.Synchronize))
                continue;
            rule.AccessMask &= ~(int)(rights | FileSystemRights.Synchronize);
            if (rule.AccessMask == 0)
                rules.RemoveAce(index);
            changed = true;
        }
        if (changed)
        {
            var bytes = new byte[descriptor.BinaryLength];
            descriptor.GetBinaryForm(bytes, 0);
            acl.SetSecurityDescriptorBinaryForm(bytes, AccessControlSections.Access);
            WriteAcl(path, acl);
        }
    }

    public static void Apply(Action<string>? log = null)
    {
        var stub = Path.Combine(AppContext.BaseDirectory, "update_stub.exe");
        if (File.Exists(stub))
            RemoveLegacyDeny(stub);
        var updaters = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var protectedDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var install = WindowsSystemService.TryGetInstallPath();
        if (!string.IsNullOrWhiteSpace(install) && Directory.Exists(install))
        {
            FindUpdaters(install, 0, updaters);
        }

        PrepareProtectedDirectories(protectedDirs);
        foreach (var dir in protectedDirs)
        {
            FindUpdaters(dir, 0, updaters);
        }

        KillUpdaters(updaters, log);

        foreach (var exe in updaters)
        {
            if (string.Equals(Path.GetFileName(exe), TargetApp.UpdaterExecutableName, StringComparison.OrdinalIgnoreCase))
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
        var names = new HashSet<string>(TargetApp.UpdaterProcessNames, StringComparer.OrdinalIgnoreCase);
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
                var state = LoadState();
                state["stub:" + exePath] = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(stub)));
                SaveState(state);
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
                if (Path.GetFileName(exe).Contains("update", StringComparison.OrdinalIgnoreCase) &&
                    !Path.GetFileName(exe).Equals("update_stub.exe", StringComparison.OrdinalIgnoreCase))
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

    private static void PrepareProtectedDirectories(ISet<string> protectedDirs)
    {
        var root = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            TargetApp.AppDataRelativeRoot);
        if (!Directory.Exists(root))
        {
            return;
        }

        foreach (var rel in TargetApp.ProtectedRelativeDirectories)
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
        RememberAcl(path);
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
        RememberAcl(path);
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
        foreach (var name in TargetApp.UpdateTaskNames)
        {
            if (RunTool(schtasks, $"/query /tn \"{name}\"") != 0)
            {
                continue;
            }

            found = true;
            var state = LoadState();
            var key = "task:" + name;
            if (!state.ContainsKey(key))
            {
                using var query = Process.Start(new ProcessStartInfo(schtasks, $"/query /tn \"{name}\" /xml")
                { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true });
                if (query is null)
                    throw new IOException($"无法读取计划任务原状态: {name}");
                var xml = query.StandardOutput.ReadToEnd();
                query.WaitForExit();
                if (query.ExitCode != 0)
                    throw new IOException($"无法读取计划任务原状态: {name}");
                var doc = XDocument.Parse(xml);
                XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
                state[key] = doc.Root?.Element(ns + "Settings")?.Element(ns + "Enabled")?.Value ?? "true";
                SaveState(state);
            }
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
            log?.Invoke("未发现某绿色软件更新计划任务（已跳过）");
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
