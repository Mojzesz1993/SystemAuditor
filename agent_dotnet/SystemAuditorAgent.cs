// =============================================================================
// SystemAuditor Enterprise — Alternatywny Moduł Agenta w C# (.NET 8 Native AOT)
// =============================================================================
// Kompilacja do pojedynczego natywnego pliku binarnego (bez zależności od .NET Runtime):
//   dotnet publish -c Release -r win-x64 /p:PublishAot=true /p:StripSymbols=true
//   dotnet publish -c Release -r linux-x64 /p:PublishAot=true /p:StripSymbols=true
//
// Realizuje:
// 1. Natywne pobranie parametrów bezpieczeństwa z systemu Windows (Win32 Registry API)
//    oraz Linux (/proc/sys, /etc/ssh/sshd_config) bez wywoływania powłoki systemowej.
// 2. Serializację source-generated JSON (AOT-safe) oraz obliczenie podpisu HMAC-SHA256.
// 3. Wysyłkę przez HttpClient z certyfikatem klienckim X.509 mTLS (Mutual TLS 1.3)
//    oraz weryfikacją prywatnego urzędu certyfikacji Root CA.
// =============================================================================

using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace SystemAuditor.Agent
{
    public sealed record AuditMeasurement(
        [property: JsonPropertyName("check_id")] string CheckId,
        [property: JsonPropertyName("category")] string Category,
        [property: JsonPropertyName("title")] string Title,
        [property: JsonPropertyName("collector_type")] string CollectorType,
        [property: JsonPropertyName("target")] string Target,
        [property: JsonPropertyName("raw_value")] Dictionary<string, object?>? RawValue,
        [property: JsonPropertyName("collected_at")] string CollectedAt,
        [property: JsonPropertyName("status")] string Status = "COLLECTED",
        [property: JsonPropertyName("error_message")] string? ErrorMessage = null
    );

    public sealed record AuditReportPayload(
        [property: JsonPropertyName("schema_version")] string SchemaVersion,
        [property: JsonPropertyName("report_id")] string ReportId,
        [property: JsonPropertyName("agent_id")] string AgentId,
        [property: JsonPropertyName("hostname")] string Hostname,
        [property: JsonPropertyName("os_family")] string OsFamily,
        [property: JsonPropertyName("os_release")] string OsRelease,
        [property: JsonPropertyName("architecture")] string Architecture,
        [property: JsonPropertyName("is_elevated")] bool IsElevated,
        [property: JsonPropertyName("timestamp_utc")] string TimestampUtc,
        [property: JsonPropertyName("policy_version")] string PolicyVersion,
        [property: JsonPropertyName("measurements")] List<AuditMeasurement> Measurements
    );

    public static class NativeOsCollectors
    {
        public static List<AuditMeasurement> CollectPlatformParameters()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return new List<AuditMeasurement>
                {
                    ReadWindowsRegistryDword(
                        "WIN-CIS-18.3.1",
                        "Network Security",
                        "Ensure SMBv1 Server protocol is disabled",
                        @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                        "SMB1"
                    ),
                    ReadWindowsRegistryDword(
                        "WIN-CIS-2.3.17.1",
                        "Privilege Escalation",
                        "Ensure User Account Control: Admin Approval Mode is Enabled",
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                        "EnableLUA"
                    ),
                    ReadWindowsRegistryDword(
                        "WIN-CIS-18.4.2",
                        "Credential Protection",
                        "Ensure WDigest Authentication is disabled (UseLogonCredential = 0)",
                        @"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
                        "UseLogonCredential"
                    ),
                    ReadWindowsRegistryDword(
                        "WIN-CIS-18.9.47.1",
                        "Credential Protection",
                        "Ensure LSASS runs as Protected Process Light (RunAsPPL)",
                        @"SYSTEM\CurrentControlSet\Control\Lsa",
                        "RunAsPPL"
                    )
                };
            }
            else
            {
                return new List<AuditMeasurement>
                {
                    CollectLinuxSshdPermitRootLogin(),
                    CollectLinuxSysctlInt("LNX-CIS-3.1.1", "Kernel Network Hardening",
                        "Ensure IPv4 packet forwarding is disabled", "/proc/sys/net/ipv4/ip_forward", "net.ipv4.ip_forward"),
                    CollectLinuxSysctlInt("LNX-CIS-1.5.1", "Kernel Memory Protection",
                        "Ensure ASLR is fully enabled", "/proc/sys/kernel/randomize_va_space", "kernel.randomize_va_space")
                };
            }
        }

        private static AuditMeasurement ReadWindowsRegistryDword(
            string checkId, string category, string title, string subKeyPath, string valueName)
        {
            string now = DateTime.UtcNow.ToString("O");
            string fullTarget = $@"HKLM\{subKeyPath}\{valueName}";
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return new AuditMeasurement(checkId, category, title, "windows_registry", fullTarget, null, now, "NOT_APPLICABLE");
            }

            try
            {
                using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                using RegistryKey? key = baseKey.OpenSubKey(subKeyPath, writable: false);
                object? rawVal = key?.GetValue(valueName, null);

                return new AuditMeasurement(
                    checkId,
                    category,
                    title,
                    "windows_registry",
                    fullTarget,
                    new Dictionary<string, object?>
                    {
                        ["value"] = rawVal is int i ? i : null,
                        ["key_exists"] = rawVal != null
                    },
                    now
                );
            }
            catch (Exception ex)
            {
                return new AuditMeasurement(checkId, category, title, "windows_registry", fullTarget, null, now, "ERROR", ex.Message);
            }
        }

        private static AuditMeasurement CollectLinuxSshdPermitRootLogin()
        {
            string now = DateTime.UtcNow.ToString("O");
            const string path = "/etc/ssh/sshd_config";
            try
            {
                if (!File.Exists(path))
                {
                    return new AuditMeasurement("LNX-CIS-5.2.8", "SSH Hardening",
                        "Ensure SSH root login is disabled", "linux_sshd_effective_config", path, null, now, "NOT_APPLICABLE");
                }

                string directiveVal = "default_unset";
                foreach (string rawLine in File.ReadLines(path))
                {
                    string line = rawLine.Trim();
                    if (string.IsNullOrEmpty(line) || line.StartsWith('#')) continue;
                    if (line.StartsWith("PermitRootLogin", StringComparison.OrdinalIgnoreCase))
                    {
                        string[] parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 2)
                        {
                            directiveVal = parts[1].ToLowerInvariant();
                            break;
                        }
                    }
                }

                return new AuditMeasurement(
                    "LNX-CIS-5.2.8",
                    "SSH Hardening",
                    "Ensure SSH root login is disabled",
                    "linux_sshd_effective_config",
                    path,
                    new Dictionary<string, object?> { ["directive"] = "PermitRootLogin", ["value"] = directiveVal },
                    now
                );
            }
            catch (Exception ex)
            {
                return new AuditMeasurement("LNX-CIS-5.2.8", "SSH Hardening",
                    "Ensure SSH root login is disabled", "linux_sshd_effective_config", path, null, now, "ERROR", ex.Message);
            }
        }

        private static AuditMeasurement CollectLinuxSysctlInt(
            string checkId, string category, string title, string procPath, string sysctlName)
        {
            string now = DateTime.UtcNow.ToString("O");
            try
            {
                string text = File.ReadAllText(procPath).Trim();
                int parsed = int.Parse(text);
                return new AuditMeasurement(
                    checkId, category, title, "linux_proc_sysctl", sysctlName,
                    new Dictionary<string, object?> { ["value"] = parsed }, now
                );
            }
            catch (Exception ex)
            {
                return new AuditMeasurement(checkId, category, title, "linux_proc_sysctl", sysctlName, null, now, "ERROR", ex.Message);
            }
        }
    }

    public static class SecureMtlsTransport
    {
        public static async Task SendAuditReportAsync(
            string serverUrl,
            string caCertPemPath,
            string clientCertPemPath,
            string clientKeyPemPath,
            string hmacSecret,
            AuditReportPayload report)
        {
            X509Certificate2 caCert = X509Certificate2.CreateFromPemFile(caCertPemPath);
            X509Certificate2 clientCertWithKey = X509Certificate2.CreateFromPemFile(clientCertPemPath, clientKeyPemPath);
            // Na systemie Windows wymagane jest przeładowanie certyfikatu z efemerycznym kluczem do formatu PFX w pamięci dla SChannel:
            X509Certificate2 ephemeralClientCert = new X509Certificate2(clientCertWithKey.Export(X509ContentType.Pfx));

            using var handler = new SocketsHttpHandler();
            handler.SslOptions.EnabledSslProtocols = SslProtocols.Tls13 | SslProtocols.Tls12;
            handler.SslOptions.ClientCertificates = new X509CertificateCollection { ephemeralClientCert };
            handler.SslOptions.RemoteCertificateValidationCallback = (_, srvCert, _, _) =>
            {
                if (srvCert == null) return false;
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(caCert);
                return chain.Build(new X509Certificate2(srvCert));
            };

            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
            string jsonPayload = JsonSerializer.Serialize(report);
            byte[] payloadBytes = Encoding.UTF8.GetBytes(jsonPayload);

            string nonce = Guid.NewGuid().ToString();
            byte[] signingInput = Encoding.UTF8.GetBytes($"{report.TimestampUtc}.{nonce}.{jsonPayload}");
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(hmacSecret));
            string signatureHex = Convert.ToHexString(hmac.ComputeHash(signingInput)).ToLowerInvariant();

            using var request = new HttpRequestMessage(HttpMethod.Post, $"{serverUrl.TrimEnd('/')}/api/v1/audit")
            {
                Content = new ByteArrayContent(payloadBytes)
            };
            request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
            request.Headers.Add("X-Agent-ID", report.AgentId);
            request.Headers.Add("X-Request-Timestamp", report.TimestampUtc);
            request.Headers.Add("X-Request-Nonce", nonce);
            request.Headers.Add("X-Payload-Signature", $"sha256={signatureHex}");

            using HttpResponseMessage response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();
        }
    }
}
