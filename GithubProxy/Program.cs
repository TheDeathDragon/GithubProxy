using GithubProxy;

Console.WriteLine("正在启动GitHub代理服务器...");

try
{
    var rootCertificate = CertificateManager.CreateRootCertificate();
    CertificateManager.InstallCertificate(rootCertificate);

    Console.WriteLine("根证书已创建并安装到系统中");

    var proxyServer = new ProxyServer(rootCertificate);
    await proxyServer.StartAsync();
}
catch (Exception ex)
{
    Console.WriteLine($"错误: {ex.Message}");
    Console.WriteLine("请确保以管理员权限运行程序");
    Console.WriteLine("按任意键退出...");
    Console.ReadKey();
}