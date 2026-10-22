using System.Windows;
using System.IO;
using System.Windows.Threading;

namespace GreenSoftAntiRecall;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            WriteStartupError(args.ExceptionObject?.ToString() ?? "未知的未处理异常");
        base.OnStartup(e);
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        WriteStartupError(e.Exception.ToString());
        MessageBox.Show(e.Exception.ToString(), "GreenSoft AntiRecall 启动错误", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }

    private static void WriteStartupError(string message)
    {
        try
        {
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "GreenSoftAntiRecall");
            Directory.CreateDirectory(dir);
            File.AppendAllText(Path.Combine(dir, "startup-error.log"), $"[{DateTime.Now:O}] {message}{Environment.NewLine}");
        }
        catch
        {
        }
    }
}
