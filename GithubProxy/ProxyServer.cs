using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using GithubProxy.Configuration;
using GithubProxy.DNS;

namespace GithubProxy;

public class ProxyServer : IDisposable
{
    private readonly object _certificateLock = new();
    private readonly DnsResolver _dnsResolver;
    private readonly int _port;
    private readonly X509Certificate2 _rootCertificate;
    private readonly Rules _rules;
    private readonly Dictionary<string, X509Certificate2> _serverCertificates = new();

    public ProxyServer(X509Certificate2 rootCertificate, int port = 12345)
    {
        _rootCertificate = rootCertificate;
        _port = port;
        _rules = new Rules();
        _dnsResolver = new DnsResolver(_rules, false); // 不启用 IPv6
    }

    public void Dispose()
    {
        _dnsResolver.Dispose();
    }

    public async Task StartAsync()
    {
        var listener = new TcpListener(IPAddress.Loopback, _port);
        listener.Start();
        Console.WriteLine($"代理服务器启动在: localhost:{_port}");
        Console.WriteLine("支持的GitHub域名:");
        foreach (var host in _rules.GithubHosts) Console.WriteLine($"  {host.Key} -> {host.Value}");

        while (true)
        {
            var client = await listener.AcceptTcpClientAsync();
            _ = HandleClientAsync(client);
        }
    }

    private async Task HandleClientAsync(TcpClient client)
    {
        try
        {
            await using var clientStream = client.GetStream();
            var buffer = new byte[8192];
            var bytesRead = await clientStream.ReadAsync(buffer);

            if (bytesRead == 0)
                // 没有数据直接退出
                return;

            var request = Encoding.ASCII.GetString(buffer, 0, bytesRead);
            var requestLines = request.Split('\n', StringSplitOptions.RemoveEmptyEntries);

            // 检查是否有解析到请求行
            if (requestLines.Length == 0)
            {
                Console.WriteLine("无法解析请求：请求行为空");
                return;
            }

            // 按空格分割请求行，避免索引越界
            var firstLineParts = requestLines[0].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (firstLineParts.Length < 2)
            {
                Console.WriteLine("无法解析请求：请求行格式不正确");
                return;
            }

            var method = firstLineParts[0];
            var path = firstLineParts[1];

            if (method == "CONNECT")
                await HandleHttpsConnection(client, path);
            else
                await HandleHttpRequest(client);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"处理客户端请求时出错: {ex.Message}");
        }
        finally
        {
            client.Close();
        }
    }

    private async Task HandleHttpsConnection(TcpClient client, string path)
    {
        var hostParts = path.Split(':');
        if (hostParts.Length != 2)
        {
            Console.WriteLine($"无效的CONNECT请求格式: {path}");
            return;
        }

        var targetHost = hostParts[0].ToLower();
        if (!int.TryParse(hostParts[1], out var targetPort))
        {
            Console.WriteLine($"无效的端口号: {hostParts[1]}");
            return;
        }

        try
        {
            // 发送连接成功响应
            var response = "HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray();
            await client.GetStream().WriteAsync(response);

            // 获取或创建服务器证书
            var serverCert = GetOrCreateServerCertificate(targetHost);

            // 建立与客户端的SSL连接
            await using var sslStream = new SslStream(client.GetStream(), false);
            await sslStream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = serverCert,
                ClientCertificateRequired = false,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            });

            // 解析目标主机的IP地址
            IPAddress? targetIp;
            try
            {
                // 尝试DNS解析
                targetIp = await _dnsResolver.ResolveAsync(targetHost);
                if (targetIp != null)
                {
                    Console.WriteLine($"DNS解析结果: {targetHost} -> {targetIp}");
                }
                else if (_rules.GithubHosts.TryGetValue(targetHost, out var ip))
                {
                    // DNS解析失败，使用内置IP
                    targetIp = IPAddress.Parse(ip);
                    Console.WriteLine($"使用GitHub内置IP: {targetHost} -> {ip}");
                }
                else
                {
                    throw new Exception($"无法解析域名: {targetHost}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"域名解析失败 ({targetHost}): {ex.Message}");
                if (_rules.GithubHosts.TryGetValue(targetHost, out var ip))
                {
                    targetIp = IPAddress.Parse(ip);
                    Console.WriteLine($"使用GitHub内置IP: {targetHost} -> {ip}");
                }
                else
                {
                    throw;
                }
            }

            // 连接到目标服务器
            using var targetClient = new TcpClient();
            targetClient.ReceiveTimeout = 60000; // 60秒超时
            targetClient.SendTimeout = 60000;
            await targetClient.ConnectAsync(targetIp, targetPort);
            await using var targetStream = targetClient.GetStream();

            if (targetPort == 443)
            {
                var isGitHubDomain = targetHost.EndsWith(".githubusercontent.com") ||
                                     targetHost.EndsWith(".github.com") ||
                                     targetHost == "github.com";
                await using var targetSslStream = new SslStream(
                    targetStream,
                    false,
                    (sender, certificate, chain, errors) =>
                    {
                        if (errors != SslPolicyErrors.None) Console.WriteLine($"证书验证错误 ({targetHost}): {errors}");
                        return isGitHubDomain || errors == SslPolicyErrors.None;
                    });

                await targetSslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = targetHost,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                });

                // 双向转发数据
                await Task.WhenAll(
                    ForwardDataAsync(sslStream, targetSslStream),
                    ForwardDataAsync(targetSslStream, sslStream)
                );
            }
            else
            {
                // 双向转发数据
                await Task.WhenAll(
                    ForwardDataAsync(sslStream, targetStream),
                    ForwardDataAsync(targetStream, sslStream)
                );
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"处理HTTPS连接时出错 ({targetHost}): {ex.Message}");
            if (ex.InnerException != null) Console.WriteLine($"内部错误: {ex.InnerException.Message}");
        }
    }

    private X509Certificate2 GetOrCreateServerCertificate(string serverName)
    {
        lock (_certificateLock)
        {
            if (_serverCertificates.TryGetValue(serverName, out var cert)) return cert;
            cert = CertificateManager.CreateServerCertificate(serverName, _rootCertificate);
            _serverCertificates[serverName] = cert;
            return cert;
        }
    }

    private static async Task HandleHttpRequest(TcpClient client)
    {
        // 实现HTTP请求处理，这个无所谓
        var response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"u8.ToArray();
        await client.GetStream().WriteAsync(response);
    }

    private static async Task ForwardDataAsync(Stream source, Stream destination)
    {
        var buffer = new byte[8192];
        try
        {
            while (true)
            {
                var bytesRead = await source.ReadAsync(buffer);
                if (bytesRead == 0) break;
                await destination.WriteAsync(buffer.AsMemory(0, bytesRead));
                await destination.FlushAsync();
            }
        }
        catch (Exception ex)
        {
            // 正常的，不用管
            Console.WriteLine($"数据转发结束: {ex.Message}");
        }
    }
}