namespace GithubProxy.Configuration;

public class DnsConfig
{
    public string[] Nameservers { get; set; }
}

public class Rules
{
    // GitHub相关域名及其备用IP配置
    public Dictionary<string, string> GithubHosts { get; } = new()
    {
        { "github.com", "20.205.243.166" },
        { "raw.githubusercontent.com", "185.199.108.133" },
        { "gist.githubusercontent.com", "185.199.108.133" },
        { "cloud.githubusercontent.com", "185.199.108.133" },
        { "camo.githubusercontent.com", "185.199.108.133" },
        { "avatars.githubusercontent.com", "185.199.108.133" },
        { "objects.githubusercontent.com", "185.199.108.133" }
    };

    public DnsConfig Dns { get; } = new()
    {
        Nameservers =
        [
            "https://185.222.222.222/dns-query", // DNS-over-HTTPS (DoH)
            "https://45.11.45.11/dns-query",
            "https://149.112.112.112/dns-query",
            "https://149.112.112.10/dns-query",
            "tls://149.112.112.112", // DNS-over-TLS (DoT)
            "tls://149.112.112.10",
            "tls://dot.sb",
            "8.8.8.8", // 传统 UDP DNS
            "8.8.4.4"
        ]
    };

    public Dictionary<string, string> Hosts { get; } = new();
}