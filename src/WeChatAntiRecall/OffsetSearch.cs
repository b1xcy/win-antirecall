using System.IO;
using WeChatAntiRecall.Services;

namespace WeChatAntiRecall;

internal sealed record OffsetSearchResult(int DelMsgOffset, int Add2DbOffset, string Version);

internal static class OffsetSearch
{
    public static OffsetSearchResult Run(Action<string>? log = null)
    {
        var baseDir = AppContext.BaseDirectory;
        var config3Path = Path.Combine(baseDir, "Config3.json");

        log?.Invoke("搜索 Weixin.dll ...");
        var dllPath = WindowsSystemService.TryGetWeChatDllPath();
        if (string.IsNullOrWhiteSpace(dllPath) || !File.Exists(dllPath))
        {
            throw new FileNotFoundException("找不到 Weixin.dll。请确认已安装微信 4.x。");
        }

        var version = Path.GetFileName(Path.GetDirectoryName(dllPath)) ?? string.Empty;
        log?.Invoke("Weixin.dll: " + dllPath);
        log?.Invoke("版本: " + version);

        CloudConfigService.Ensure(config3Path, log);
        var config3 = Config3Service.Load(config3Path);
        if (!Config3Service.TryGet(config3, version, out var configVersion, out var entry))
        {
            throw new InvalidOperationException("Config3.json 中没有匹配当前微信版本的特征码。");
        }

        log?.Invoke("使用特征版本: " + configVersion);
        var request = new CallChainSearchRequest(
            entry.Sig1 ?? string.Empty,
            entry.Sig2 ?? string.Empty,
            entry.Sig3 ?? string.Empty);
        var progress = new Progress<CallChainSearchProgress>(p =>
            log?.Invoke($"[{p.Percent,3}%] {p.Message}"));
        var result = CallChainSearchService.Search(dllPath!, request, progress);

        var delOffset = result.DeleteMessagesChain?.RootCallRva ?? 0;
        var addOffset = result.AddMessageToDbChain?.TargetCallRva ?? 0;
        if (delOffset == 0 || addOffset == 0)
        {
            throw new InvalidOperationException($"搜索失败: DelMsg=0x{delOffset:X} Add2DB=0x{addOffset:X}");
        }

        log?.Invoke($"DelMsgOffset=0x{delOffset:X}  Add2DBOffset=0x{addOffset:X}");
        return new OffsetSearchResult(unchecked((int)delOffset), unchecked((int)addOffset), version);
    }
}
