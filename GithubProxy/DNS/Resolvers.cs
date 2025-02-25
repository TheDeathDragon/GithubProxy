using System.Net;
using System.Net.Sockets;
using DnsClient;
using DnsClient.Protocol;

namespace GithubProxy.DNS;

public interface IDnsResolver
{
    Task<IPAddress?> ResolveAsync(string domain, bool ipv6);
}

public class DohResolver : IDnsResolver
{
    private readonly LookupClient _dnsClient;

    public DohResolver()
    {
        var options = new LookupClientOptions(new NameServer(IPAddress.Parse("8.8.8.8")))
        {
            UseCache = false,
            UseTcpOnly = true,
            UseTcpFallback = true
        };
        _dnsClient = new LookupClient(options);
    }

    public async Task<IPAddress?> ResolveAsync(string domain, bool ipv6)
    {
        try
        {
            var response = await _dnsClient.QueryAsync(domain, ipv6 ? QueryType.AAAA : QueryType.A);
            return response.Answers
                .OfType<AddressRecord>()
                .Select(r => r.Address)
                .FirstOrDefault();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"DoH resolver failed: {ex.Message}");
            return null;
        }
    }
}

public class DotResolver : IDnsResolver
{
    private readonly LookupClient _dnsClient;

    public DotResolver(Uri serverUri)
    {
        var hostname = serverUri.Host;
        var port = serverUri.Port > 0 ? serverUri.Port : 853;

        var options = new LookupClientOptions(new NameServer(IPAddress.Parse(hostname), port))
        {
            UseCache = false,
            UseTcpOnly = true,
            UseTcpFallback = true,
            EnableAuditTrail = true
        };
        _dnsClient = new LookupClient(options);
    }

    public async Task<IPAddress?> ResolveAsync(string domain, bool ipv6)
    {
        try
        {
            var response = await _dnsClient.QueryAsync(domain, ipv6 ? QueryType.AAAA : QueryType.A);
            return response.Answers
                .OfType<AddressRecord>()
                .Select(r => r.Address)
                .FirstOrDefault();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"DoT resolver failed: {ex.Message}");
            return null;
        }
    }
}

public class UdpResolver : IDnsResolver
{
    private readonly LookupClient _dnsClient;

    public UdpResolver(Uri serverUri)
    {
        var options = new LookupClientOptions(new NameServer(IPAddress.Parse(serverUri.Host)))
        {
            UseCache = false,
            Timeout = TimeSpan.FromSeconds(5),
            Retries = 3,
            EnableAuditTrail = true
        };
        _dnsClient = new LookupClient(options);
    }

    public async Task<IPAddress?> ResolveAsync(string domain, bool ipv6)
    {
        try
        {
            var response = await _dnsClient.QueryAsync(domain, ipv6 ? QueryType.AAAA : QueryType.A);
            return response.Answers
                .OfType<AddressRecord>()
                .Select(r => r.Address)
                .FirstOrDefault();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"UDP resolver failed: {ex.Message}");
            return null;
        }
    }
}

public class SystemDnsResolver : IDnsResolver
{
    public async Task<IPAddress?> ResolveAsync(string domain, bool ipv6)
    {
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(domain);
            return addresses
                .FirstOrDefault(a => ipv6
                    ? a.AddressFamily == AddressFamily.InterNetworkV6
                    : a.AddressFamily == AddressFamily.InterNetwork);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"System resolver failed: {ex.Message}");
            return null;
        }
    }
}