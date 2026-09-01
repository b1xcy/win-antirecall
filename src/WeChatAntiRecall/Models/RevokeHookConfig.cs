namespace WeChatAntiRecall.Models;

public class RevokeHookConfig
{
    public KeyFuncSection KeyFunc { get; set; } = new();

    public SettingSection Setting { get; set; } = new();
}

public class KeyFuncSection
{
    public int DelMsgOffset { get; set; }

    public int Add2DBOffset { get; set; }
}

public class SettingSection
{
    public bool AntiRevokeSelf { get; set; }

    public bool OutputDebugMsg { get; set; }

    public bool BlockUpdate { get; set; }

    public string TipPhrase { get; set; } = "已拦截 {from} 于 {time} 撤回：{content}";

    public string Ver { get; set; } = string.Empty;
}
