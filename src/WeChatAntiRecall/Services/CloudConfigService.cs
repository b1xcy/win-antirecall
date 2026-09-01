using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;

namespace WeChatAntiRecall.Services;

/// <summary>
/// Config3.json 优先从上游 RevokeHook 云端拉取，失败回退随包附带的本地副本。
/// 云端: https://github.com/EEEEhex/RevokeHook
/// </summary>
public static class CloudConfigService
{
    private static readonly string[] CandidateUrls =
    {
        "https://raw.githubusercontent.com/EEEEhex/RevokeHook/main/Config3.json",
        "http://47.109.182.110:8123/api/get_config3"
    };

    public static void Ensure(string destinationPath, Action<string>? log = null)
    {
        log?.Invoke("正在从上游拉取 Config3.json...");
        if (TryDownload(destinationPath, log))
        {
            return;
        }

        if (File.Exists(destinationPath))
        {
            log?.Invoke("云端不可用，回退本地 Config3.json");
            return;
        }

        throw new FileNotFoundException(
            "缺少 Config3.json，且无法从云端获取。",
            destinationPath);
    }

    public static async Task DownloadLatestConfigAsync(
        string destinationPath,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(destinationPath) ?? AppContext.BaseDirectory);

        using var client = CreateHttpClient();
        Exception? lastException = null;

        foreach (var candidateUrl in EnumerateCandidateUrls())
        {
            try
            {
                progress?.Report("正在连接 " + candidateUrl);
                await DownloadAndValidateAsync(client, candidateUrl, destinationPath, progress, cancellationToken);
                return;
            }
            catch (HttpRequestException ex)
            {
                lastException = ex;
            }
            catch (TaskCanceledException ex)
            {
                lastException = ex;
            }
            catch (InvalidDataException ex)
            {
                lastException = ex;
            }
        }

        throw new InvalidOperationException("无法从云端下载 Config3.json。", lastException);
    }

    private static bool TryDownload(string destinationPath, Action<string>? log)
    {
        try
        {
            var progress = log is null ? null : new Progress<string>(log);
            DownloadLatestConfigAsync(destinationPath, progress).GetAwaiter().GetResult();
            log?.Invoke("已从云端更新 Config3.json");
            return true;
        }
        catch (Exception ex)
        {
            log?.Invoke("云端下载失败: " + ex.Message);
            return false;
        }
    }

    private static IEnumerable<string> EnumerateCandidateUrls()
    {
        var overrideUrl = Environment.GetEnvironmentVariable("REVOKEHOOK_CONFIG3_URL");
        if (!string.IsNullOrWhiteSpace(overrideUrl))
        {
            yield return overrideUrl;
        }

        foreach (var candidateUrl in CandidateUrls)
        {
            yield return candidateUrl;
        }
    }

    private static async Task DownloadAndValidateAsync(
        HttpClient client,
        string url,
        string destinationPath,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromSeconds(8));
        using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cts.Token);
        response.EnsureSuccessStatusCode();

        var tempPath = destinationPath + ".download";
        await using (var source = await response.Content.ReadAsStreamAsync(cancellationToken))
        await using (var target = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            await source.CopyToAsync(target, cancellationToken);
        }

        var content = await File.ReadAllTextAsync(tempPath, cancellationToken);
        var parsed = Config3Service.Parse(content);
        if (parsed.Versions.Count == 0)
        {
            File.Delete(tempPath);
            throw new InvalidDataException("下载内容不是有效的 Config3.json。");
        }

        File.Copy(tempPath, destinationPath, true);
        File.Delete(tempPath);
        progress?.Report($"Config3.json 已保存（{parsed.Versions.Count} 个版本）");
    }

    private static HttpClient CreateHttpClient()
    {
        var proxy = WebRequest.GetSystemWebProxy();
        proxy.Credentials = CredentialCache.DefaultCredentials;

        var handler = new HttpClientHandler
        {
            Proxy = proxy,
            UseProxy = true,
            DefaultProxyCredentials = CredentialCache.DefaultCredentials
        };

        var client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(20)
        };

        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("WeChatAntiRecall", "1.0"));
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        return client;
    }
}
