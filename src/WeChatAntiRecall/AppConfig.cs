using System.IO;
using System.Text;

namespace WeChatAntiRecall;

public sealed class AppConfig
{
    public string TipPhrase { get; set; } = "已拦截 {from} 于 {time} 撤回：{content}";
    public bool AntiRevokeSelf { get; set; }
    public bool BlockUpdate { get; set; }
    public bool Notify { get; set; }
    public bool Debug { get; set; } = true;

    public static string DefaultPath => Path.Combine(AppContext.BaseDirectory, "config.yml");

    public static AppConfig Load(string? path = null)
    {
        var config = new AppConfig();
        var file = path ?? DefaultPath;
        if (!File.Exists(file))
        {
            return config;
        }

        foreach (var raw in File.ReadAllLines(file, Encoding.UTF8))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith(';'))
            {
                continue;
            }

            var idx = line.IndexOf(':');
            if (idx <= 0)
            {
                continue;
            }

            var key = line[..idx].Trim();
            var value = line[(idx + 1)..].Trim().Trim('"').Trim('\'');
            switch (key)
            {
                case "tip_phrase":
                    config.TipPhrase = string.IsNullOrWhiteSpace(value) ? config.TipPhrase : value;
                    break;
                case "anti_revoke_self":
                    config.AntiRevokeSelf = ParseBool(value);
                    break;
                case "block_update":
                    config.BlockUpdate = ParseBool(value);
                    break;
                case "notify":
                    config.Notify = ParseBool(value);
                    break;
                case "debug":
                    config.Debug = ParseBool(value);
                    break;
            }
        }

        return config;
    }

    private static bool ParseBool(string value)
    {
        value = value.Trim();
        return value is "1" or "true" or "True" or "TRUE" or "yes" or "Yes" or "on" or "ON";
    }
}
