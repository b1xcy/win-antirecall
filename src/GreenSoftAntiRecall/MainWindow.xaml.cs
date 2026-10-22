using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace GreenSoftAntiRecall;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        Loaded += async (_, _) => await RunAsync();
    }

    private async Task RunAsync()
    {
        try
        {
            var config = AppConfig.Load();
            Log($"配置: {AppConfig.DefaultPath}");
            Log($"  block_update={config.BlockUpdate}  notify={config.Notify}  debug={config.Debug}");

            if (!config.BlockUpdate)
            {
                SetStatus("恢复自动更新...");
                await Task.Run(() => UpdateBlocker.Restore(Log));
            }

            SetStatus("搜索偏移...");
            var offsets = await Task.Run(() => OffsetSearch.Run(Log));

            if (config.BlockUpdate)
            {
                SetStatus("禁用自动更新...");
                await Task.Run(() => UpdateBlocker.Apply(Log));
            }

            SetStatus("启动某绿色软件...");
            TrayWait.StartTarget();
            Log("已请求启动目标程序（若尚未运行）");

            SetStatus("等待登录（托盘图标）...");
            Log("请在某绿色软件窗口中登录。检测到托盘后会自动注入；未登录就关闭某绿色软件时本程序会一起退出。");
            var pid = await Task.Run(() => TrayWait.WaitForLoginPid(Log));
            Log($"登录完成 pid={pid}");
            await Task.Delay(800);

            var dllPath = Path.Combine(AppContext.BaseDirectory, "RevokeHook.dll");
            SetStatus("注入 Hook...");
            await Task.Run(() => Injector.Inject(pid, dllPath, offsets.DelMsgOffset, offsets.Add2DbOffset, offsets.DllPath));
            Log("DLL 已加载，防撤回、消息入库及已启用的通知/更新拦截均已完成初始化校验。");

            SetStatus("就绪");
            if (config.Notify)
            {
                var tip = new NotificationWindow("GreenSoft AntiRecall", "已注入防撤回。打开聊天即可测试撤回。");
                tip.Show();
                await Task.Delay(1800);
            }
            else
            {
                await Task.Delay(400);
            }
            Application.Current.Shutdown();
        }
        catch (GreenSoftExitedException ex)
        {
            SetStatus("已退出");
            Log(ex.Message);
            await Task.Delay(300);
            Application.Current.Shutdown();
        }
        catch (Exception ex)
        {
            SetStatus("失败");
            Log("错误: " + ex.Message);
            Log(ex.ToString());
            MessageBox.Show(this, ex.Message, "GreenSoft AntiRecall", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void SetStatus(string text)
    {
        Dispatcher.Invoke(() => StatusText.Text = text);
    }

    private void Log(string text)
    {
        var line = $"[{DateTime.Now:HH:mm:ss}] {text}\r\n";
        Dispatcher.Invoke(() =>
        {
            LogBox.AppendText(line);
            LogBox.CaretIndex = LogBox.Text.Length;
            LogBox.ScrollToEnd();
        });
    }
}
