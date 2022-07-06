using System;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CreateSelfSignedCertificate
{
    class Program
    {
        static void Main()
        {
            CreateCertificateForServerAuthentication();

            // CreateCertificateForClientAuthentication();
        }

        private static void CreateCertificateForServerAuthentication()
        {
            var rsaKey = RSA.Create(2048);

            var subject_domain = Console.ReadLine();
            string subject = "CN=" + subject_domain;
            Console.WriteLine($"Subject = '{subject}");

            var certRequest = new CertificateRequest(subject, rsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            certRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
            certRequest.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsages: X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: false));
            certRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(key: certRequest.PublicKey, critical: false));
            certRequest.CertificateExtensions.Add(new X509Extension(new AsnEncodedData(subject_domain, new byte[] { 48, 11, 130, 9, 108, 111, 99, 97, 108, 104, 111, 115, 116 }), false));

            var expireAt = DateTimeOffset.Now.AddYears(5);
            var certificate = certRequest.CreateSelfSigned(DateTimeOffset.Now, expireAt);

            var exportableCert = new X509Certificate2(certificate.Export(X509ContentType.Cert), (string)null, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet).CopyWithPrivateKey(rsaKey);
            exportableCert.FriendlyName = "My Self Certificate For Server Authorization";

            var sch = new SecureString();
            foreach (var @char in "123456") { sch.AppendChar(@char); }

            File.WriteAllBytes($"{subject}_ServerCert.pfx", exportableCert.Export(X509ContentType.Pfx, sch));

            var loadedCertificate = new X509Certificate2($"{subject}_ServerCert.pfx", sch);
            Console.WriteLine(loadedCertificate.FriendlyName);
        }

        private static void CreateCertificateForClientAuthentication()
        {
            var rsaKey = RSA.Create(2048);

            var subject_domain = Console.ReadLine();
            string subject = "CN=" + subject_domain;
            Console.WriteLine($"Subject = '{subject}");

            var certRequest = new CertificateRequest(subject, rsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            certRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
            certRequest.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsages: X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: false));
            certRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(key: certRequest.PublicKey, critical: false));

            var expireAt = DateTimeOffset.Now.AddYears(5);

            var certificate = certRequest.CreateSelfSigned(DateTimeOffset.Now, expireAt);
            var exportableCertificate = new X509Certificate2(certificate.Export(X509ContentType.Cert), (string)null, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet).CopyWithPrivateKey(rsaKey);

            exportableCertificate.FriendlyName = "My Self Certificate For Server Authorization";

            var sch = new SecureString();
            foreach (var @char in "123456") { sch.AppendChar(@char); }

            File.WriteAllBytes($"{subject}_ClientCert.pfx", exportableCertificate.Export(X509ContentType.Pfx, sch));

            var loadedCertificate = new X509Certificate2($"{subject}_ClientCert.pfx", sch);

            Console.WriteLine(loadedCertificate.FriendlyName);
        }
    }
}
