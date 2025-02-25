using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace GithubProxy;

public static class CertificateManager
{
    private const string RootCertName = "GitHub Proxy Root CA";

    public static X509Certificate2 CreateRootCertificate()
    {
        using var rsa = RSA.Create(4096);
        var distinguishedName = new X500DistinguishedName($"CN={RootCertName}");

        var certificateRequest = new CertificateRequest(
            distinguishedName,
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // 添加增强型密钥用法扩展
        certificateRequest.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection
                {
                    new Oid("1.3.6.1.5.5.7.3.1"), // 服务器身份验证
                    new Oid("1.3.6.1.5.5.7.3.2") // 客户端身份验证
                }, true));

        // 添加基本约束扩展
        certificateRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, true, 12, true));

        // 添加密钥用法扩展
        certificateRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature |
                X509KeyUsageFlags.KeyEncipherment |
                X509KeyUsageFlags.KeyCertSign |
                X509KeyUsageFlags.CrlSign,
                true));

        // 生成并添加主题密钥标识符
        var subjectKeyIdentifier = SHA1.HashData(rsa.ExportSubjectPublicKeyInfo());

        certificateRequest.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(subjectKeyIdentifier, false));

        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = notBefore.AddYears(10);

        var certificate = certificateRequest.CreateSelfSigned(notBefore, notAfter);

        // 导出带私钥的PFX格式证书并重新导入
        var pfxBytes = certificate.Export(X509ContentType.Pfx, "temp");
        return new X509Certificate2(
            pfxBytes,
            "temp",
            X509KeyStorageFlags.Exportable |
            X509KeyStorageFlags.PersistKeySet |
            X509KeyStorageFlags.MachineKeySet);
    }

    public static void InstallCertificate(X509Certificate2 certificate)
    {
        var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);

        // 检查并删除同名的旧证书
        var oldCerts = store.Certificates.Find(
            X509FindType.FindBySubjectDistinguishedName,
            certificate.SubjectName.Name,
            false);

        foreach (var oldCert in oldCerts) store.Remove(oldCert);

        store.Add(certificate);
        store.Close();
    }

    public static X509Certificate2 CreateServerCertificate(string serverName, X509Certificate2 rootCertificate)
    {
        using var rsa = RSA.Create(2048);
        var distinguishedName = new X500DistinguishedName($"CN={serverName}");

        var certificateRequest = new CertificateRequest(
            distinguishedName,
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // 添加基本约束扩展
        certificateRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, true));

        // 添加增强型密钥用法扩展
        certificateRequest.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection
                {
                    new Oid("1.3.6.1.5.5.7.3.1") // 服务器身份验证
                }, true));

        // 添加密钥用法扩展
        certificateRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature |
                X509KeyUsageFlags.KeyEncipherment,
                true));

        // 添加主题备用名称扩展
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName(serverName);
        if (serverName.StartsWith("www."))
            sanBuilder.AddDnsName(serverName[4..]);
        else
            sanBuilder.AddDnsName("www." + serverName);

        certificateRequest.CertificateExtensions.Add(sanBuilder.Build());

        // 生成并添加主题密钥标识符
        var subjectKeyIdentifier = SHA1.HashData(rsa.ExportSubjectPublicKeyInfo());

        certificateRequest.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(subjectKeyIdentifier, false));

        // 获取根证书的主题密钥标识符并添加为颁发者密钥标识符
        if (rootCertificate.Extensions
                .FirstOrDefault(ext => ext.Oid?.Value == "2.5.29.14") is X509SubjectKeyIdentifierExtension
            rootSubjectKeyId)
        {
            var aki = new byte[rootSubjectKeyId.RawData.Length - 2];
            Buffer.BlockCopy(rootSubjectKeyId.RawData, 2, aki, 0, aki.Length);

            var asnWriter = new AsnWriter(AsnEncodingRules.DER);

            using (asnWriter.PushSequence())
            {
                asnWriter.WriteOctetString([0x80]); // Context-specific tag 0
                asnWriter.WriteOctetString(aki);
            }

            certificateRequest.CertificateExtensions.Add(
                new X509Extension("2.5.29.35", asnWriter.Encode(), false));
        }

        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = notBefore.AddYears(1);

        var serialNumber = new byte[20];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(serialNumber);
        }

        using var rootCertificatePrivateKey = rootCertificate.GetRSAPrivateKey();
        var certificate = certificateRequest.Create(
            rootCertificate,
            notBefore,
            notAfter,
            serialNumber);

        var serverCert = certificate.CopyWithPrivateKey(rsa);

        // 导出带私钥的PFX格式证书并重新导入
        var pfxBytes = serverCert.Export(X509ContentType.Pfx, "temp");
        return new X509Certificate2(
            pfxBytes,
            "temp",
            X509KeyStorageFlags.Exportable |
            X509KeyStorageFlags.PersistKeySet |
            X509KeyStorageFlags.MachineKeySet);
    }
}