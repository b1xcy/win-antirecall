using System.Windows;
using System.Windows.Threading;

namespace WeChatAntiRecall;

public partial class NotificationWindow : Window
{
    private readonly DispatcherTimer _closeTimer = new() { Interval = TimeSpan.FromSeconds(4) };

    public NotificationWindow(string title, string content)
    {
        InitializeComponent();
        TitleTextBlock.Text = title;
        ContentTextBlock.Text = content;
        Loaded += (_, _) =>
        {
            var workArea = SystemParameters.WorkArea;
            Left = workArea.Right - Width - 16;
            Top = workArea.Bottom - Height - 16;
            _closeTimer.Tick += (_, _) =>
            {
                _closeTimer.Stop();
                Close();
            };
            _closeTimer.Start();
        };
    }
}
