using System.Text;

namespace GreenSoftAntiRecall;

/// <summary>
/// 目标程序的运行时标识，属于互操作契约，必须与目标进程实际使用的名称一致。
/// 为避免仓库和源码里重复出现产品名，统一以 Base64 保存并在运行时解码。
/// </summary>
internal static class TargetApp
{
    /// <summary>目标进程名（不含 .exe）。</summary>
    public static readonly string ProcessName = Decode("V2VpeGlu");

    /// <summary>目标主程序文件名。</summary>
    public static readonly string ExecutableName = Decode("V2VpeGluLmV4ZQ==");

    /// <summary>目标主模块文件名。</summary>
    public static readonly string ModuleName = Decode("V2VpeGluLmRsbA==");

    /// <summary>安装信息所在的注册表子键。</summary>
    public static readonly string InstallRegistryKey = Decode("U29mdHdhcmVcVGVuY2VudFxXZWl4aW4=");

    /// <summary>更新器进程名（不含 .exe）。</summary>
    public static readonly string[] UpdaterProcessNames =
    [
        Decode("V2VpeGluVXBkYXRl"),
        Decode("V2VDaGF0VXBkYXRl"),
    ];

    /// <summary>需要被替换为空实现的主更新器文件名。</summary>
    public static readonly string UpdaterExecutableName = Decode("V2VpeGluVXBkYXRlLmV4ZQ==");

    /// <summary>目标程序的应用数据目录（相对 %APPDATA%）。</summary>
    public static readonly string AppDataRelativeRoot = Decode("VGVuY2VudFx4d2VjaGF0");

    /// <summary>需要锁定的更新相关子目录（相对 <see cref="AppDataRelativeRoot"/>）。</summary>
    public static readonly string[] ProtectedRelativeDirectories =
    [
        Decode("WFBsdWdpblxQbHVnaW5zXFdlaXhpblVwZGF0ZQ=="),
        Decode("WFBsdWdpblxQbHVnaW5zXFVwZGF0ZU5vdGlmeQ=="),
        "update",
    ];

    /// <summary>更新器计划任务名。</summary>
    public static readonly string[] UpdateTaskNames =
    [
        Decode("XFRlbmNlbnRcV2VDaGF0VXBkYXRl"),
        Decode("XFRlbmNlbnRcV2VpeGluVXBkYXRl"),
        Decode("XFdlQ2hhdFVwZGF0ZQ=="),
        Decode("XFdlaXhpblVwZGF0ZQ=="),
    ];

    /// <summary>登录后出现的托盘窗口类名。</summary>
    public static readonly string TrayWindowClass = Decode("V3hUcmF5SWNvbk1lc3NhZ2VXaW5kb3c=");

    /// <summary>改名前使用的本地状态目录，仅用于迁移旧更新记录。</summary>
    public static readonly string LegacyStateDirectory = Decode("V2VDaGF0QW50aVJlY2FsbA==");

    private static string Decode(string value) =>
        Encoding.UTF8.GetString(Convert.FromBase64String(value));
}
