using System.Net;
using GithubProxy.Configuration;

namespace GithubProxy.DNS;

public class DnsResolver : IDisposable
{
    private static readonly SemaphoreSlim CacheLock = new(1, 1);
    private static readonly Dictionary<string, CachedDnsEntry> Cache = new();
    private readonly Timer _cleanupTimer;
    private readonly bool _enableIPv6;
    private readonly HttpClient _httpClient;
    private readonly List<IDnsResolver> _resolvers = [];
    private readonly Rules _rules;

    public DnsResolver(Rules rules, bool enableIPv6)
    {
        _rules = rules;
        _enableIPv6 = enableIPv6;
        _httpClient = new HttpClient
        {
            DefaultRequestVersion = new Version(2, 0),
            Timeout = TimeSpan.FromSeconds(10)
        };

        InitializeResolvers();

        // 添加缓存清理定时器
        _cleanupTimer = new Timer(CleanupCache, null,
            TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
    }

    public void Dispose()
    {
        _cleanupTimer.Dispose();
        foreach (var resolver in _resolvers) (resolver as IDisposable)?.Dispose();
        _httpClient.Dispose();
    }

    private void InitializeResolvers()
    {
        var initializationErrors = new List<string>();

        foreach (var nameserver in _rules.Dns.Nameservers)
            try
            {
                var uri = ParseNameserverUri(nameserver);
                var resolver = CreateResolver(uri);
                _resolvers.Add(resolver);
                Console.WriteLine($"成功初始化DNS解析器: {nameserver}");
            }
            catch (Exception ex)
            {
                initializationErrors.Add($"初始化DNS解析器失败 {nameserver}: {ex.Message}");
            }

        if (_resolvers.Count != 0) return;
        foreach (var error in initializationErrors) Console.WriteLine(error);

        Console.WriteLine("没有可用的DNS解析器，回退到系统DNS");
        _resolvers.Add(new SystemDnsResolver());
    }

    private static Uri ParseNameserverUri(string nameserver)
    {
        if (nameserver.StartsWith("http") || nameserver.StartsWith("tls") || nameserver.StartsWith("quic"))
            return new Uri(nameserver);

        // 对于传统UDP DNS，添加udp://前缀
        return new Uri($"udp://{nameserver}");
    }

    private static IDnsResolver CreateResolver(Uri uri)
    {
        return uri.Scheme.ToLower() switch
        {
            "https" => new DohResolver(),
            "tls" => new DotResolver(uri),
            "udp" => new UdpResolver(uri),
            _ => throw new ArgumentException($"不支持的DNS协议: {uri.Scheme}")
        };
    }

    public async Task<IPAddress?> ResolveAsync(string domain)
    {
        // 检查hosts文件
        if (TryGetHostsEntry(domain, out var hostIp))
        {
            Console.WriteLine($"从hosts找到记录: {domain} -> {hostIp}");
            return hostIp;
        }

        // 检查缓存
        await CacheLock.WaitAsync();
        try
        {
            lock (CacheLock)
            {
                if (Cache.TryGetValue(domain, out var cached) && cached.Expiry > DateTime.UtcNow)
                {
                    Console.WriteLine($"从缓存获取DNS记录: {domain} -> {cached.Address}");
                    return cached.Address;
                }
            }
        }
        finally
        {
            CacheLock.Release();
        }

        // 查询DNS
        var exceptions = new List<Exception>();
        foreach (var resolver in _resolvers)
            try
            {
                var result = await resolver.ResolveAsync(domain, _enableIPv6);
                if (result == null) continue;
                Console.WriteLine($"DNS解析成功: {domain} -> {result} (使用 {resolver.GetType().Name})");

                // 更新缓存
                await CacheLock.WaitAsync();
                try
                {
                    lock (CacheLock)
                    {
                        Cache[domain] = new CachedDnsEntry(result)
                        {
                            Address = result,
                            Expiry = DateTime.UtcNow.AddMinutes(5) // 5分钟缓存
                        };
                    }
                }
                finally
                {
                    CacheLock.Release();
                }

                return result;
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
                Console.WriteLine($"DNS解析器 {resolver.GetType().Name} 失败: {ex.Message}");
            }

        var errorMessage = $"解析 {domain} 失败。尝试了 {_resolvers.Count} 个解析器，但都失败了。";
        throw new DnsResolutionException(errorMessage);
    }

    private bool TryGetHostsEntry(string domain, out IPAddress? address)
    {
        address = null;

        // 检查完整域名匹配
        if (_rules.Hosts.TryGetValue(domain, out var hostEntry))
            return IPAddress.TryParse(hostEntry, out address) ||
                   // 如果hosts中配置的是另一个域名，递归解析
                   TryGetHostsEntry(hostEntry, out address);

        // 检查通配符匹配
        var wildcardMatch = _rules.Hosts
            .Where(h => h.Key.StartsWith(".") && domain.EndsWith(h.Key))
            .OrderByDescending(h => h.Key.Length)
            .FirstOrDefault();

        if (default(KeyValuePair<string, string>).Equals(wildcardMatch)) return false;
        return IPAddress.TryParse(wildcardMatch.Value, out address) ||
               // 如果hosts中配置的是另一个域名，递归解析
               TryGetHostsEntry(wildcardMatch.Value, out address);
    }

    private static void CleanupCache(object state)
    {
        var now = DateTime.UtcNow;
        lock (CacheLock)
        {
            var expiredKeys = Cache
                .Where(kvp => kvp.Value.Expiry <= now)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var key in expiredKeys) Cache.Remove(key);
        }
    }

    private class CachedDnsEntry(IPAddress? address)
    {
        public IPAddress? Address { get; init; } = address;
        public DateTime Expiry { get; init; }
    }
}

public class DnsResolutionException(string message) : Exception(message);