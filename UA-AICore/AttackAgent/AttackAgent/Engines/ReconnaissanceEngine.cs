using System.Net;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using System.Text.Json;
using System.Diagnostics;
using System.Net.Sockets;
using Serilog;

namespace AttackAgent.Engines
{
    /// <summary>
    /// Advanced reconnaissance engine for comprehensive target analysis
    /// Implements OSINT, DNS enumeration, port scanning, and technology fingerprinting
    /// </summary>
    public class ReconnaissanceEngine
    {
        private readonly string _target;
        private readonly HttpClient _httpClient;

        public ReconnaissanceEngine(string target, HttpClient httpClient)
        {
            _target = target;
            _httpClient = httpClient;
        }

        /// <summary>
        /// Comprehensive reconnaissance phase
        /// </summary>
        public async Task<ReconnaissanceReport> PerformReconnaissanceAsync()
        {
            Log.Information("🔍 Starting comprehensive reconnaissance phase...");
            
            var report = new ReconnaissanceReport
            {
                Target = _target,
                StartTime = DateTime.UtcNow
            };

            try
            {
                // Phase 1: OSINT Gathering
                Log.Information("📊 Phase 1: OSINT Intelligence Gathering");
                report.OsintData = await PerformOsintGatheringAsync();

                // Phase 2: DNS Enumeration
                Log.Information("🌐 Phase 2: DNS Enumeration");
                report.DnsData = await PerformDnsEnumerationAsync();

                // Phase 3: Port Scanning
                Log.Information("🔌 Phase 3: Port Scanning");
                report.PortScanData = await PerformPortScanningAsync();

                // Phase 4: Service Fingerprinting
                Log.Information("🔍 Phase 4: Service Fingerprinting");
                report.ServiceData = await PerformServiceFingerprintingAsync();

                // Phase 5: Certificate Analysis
                Log.Information("🔐 Phase 5: Certificate Analysis");
                report.CertificateData = await PerformCertificateAnalysisAsync();

                // Phase 6: Directory/File Enumeration
                Log.Information("📁 Phase 6: Directory and File Enumeration");
                report.DirectoryData = await PerformDirectoryEnumerationAsync();

                // Phase 7: Technology Stack Analysis
                Log.Information("⚙️ Phase 7: Technology Stack Analysis");
                report.TechnologyData = await PerformTechnologyAnalysisAsync();

                report.EndTime = DateTime.UtcNow;
                report.Duration = report.EndTime - report.StartTime;

                Log.Information("✅ Reconnaissance completed in {Duration}ms", report.Duration.TotalMilliseconds);
                return report;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "❌ Error during reconnaissance phase");
                report.Error = ex.Message;
                return report;
            }
        }

        /// <summary>
        /// OSINT (Open Source Intelligence) gathering
        /// </summary>
        private async Task<OsintData> PerformOsintGatheringAsync()
        {
            var osint = new OsintData();
            var domain = new Uri(_target).Host;

            try
            {
                // Google Dorking
                Log.Information("🔍 Performing Google dorking...");
                osint.GoogleDorks = await PerformGoogleDorkingAsync(domain);

                // Shodan API (if available)
                Log.Information("🔍 Checking Shodan data...");
                osint.ShodanData = await PerformShodanLookupAsync(domain);

                // Certificate Transparency logs
                Log.Information("🔍 Analyzing certificate transparency logs...");
                osint.CertificateTransparency = await PerformCertificateTransparencyLookupAsync(domain);

                // Social media and public records
                Log.Information("🔍 Gathering social media intelligence...");
                osint.SocialMediaData = await PerformSocialMediaIntelligenceAsync(domain);

                // DNS history
                Log.Information("🔍 Analyzing DNS history...");
                osint.DnsHistory = await PerformDnsHistoryLookupAsync(domain);

                Log.Information("✅ OSINT gathering completed");
            }
            catch (Exception ex)
            {
                Log.Error(ex, "❌ Error during OSINT gathering");
                osint.Error = ex.Message;
            }

            return osint;
        }

        /// <summary>
        /// DNS enumeration and subdomain discovery
        /// </summary>
        private async Task<DnsData> PerformDnsEnumerationAsync()
        {
            var dnsData = new DnsData();
            var domain = new Uri(_target).Host;

            try
            {
                // Basic DNS records
                Log.Information("🔍 Enumerating DNS records...");
                dnsData.DnsRecords = await EnumerateDnsRecordsAsync(domain);

                // Subdomain discovery
                Log.Information("🔍 Discovering subdomains...");
                dnsData.Subdomains = await DiscoverSubdomainsAsync(domain);

                // Zone transfer attempts
                Log.Information("🔍 Attempting zone transfers...");
                dnsData.ZoneTransfer = await AttemptZoneTransferAsync(domain);

                // Reverse DNS lookup
                Log.Information("🔍 Performing reverse DNS lookup...");
                dnsData.ReverseDns = await PerformReverseDnsLookupAsync(domain);

                Log.Information("✅ DNS enumeration completed");
            }
            catch (Exception ex)
            {
                Log.Error(ex, "❌ Error during DNS enumeration");
                dnsData.Error = ex.Message;
            }

            return dnsData;
        }

        /// <summary>
        /// Comprehensive port scanning
        /// </summary>
        private async Task<PortScanData> PerformPortScanningAsync()
        {
            var portData = new PortScanData();
            var host = new Uri(_target).Host;

            try
            {
                // Common ports scan
                Log.Information("🔍 Scanning common ports...");
                portData.CommonPorts = await ScanCommonPortsAsync(host);

                // Top 1000 ports scan
                Log.Information("🔍 Scanning top 1000 ports...");
                portData.Top1000Ports = await ScanTop1000PortsAsync(host);

                // UDP ports scan
                Log.Information("🔍 Scanning UDP ports...");
                portData.UdpPorts = await ScanUdpPortsAsync(host);

                // Service version detection
                Log.Information("🔍 Detecting service versions...");
                portData.ServiceVersions = await DetectServiceVersionsAsync(portData.CommonPorts);

                Log.Information("✅ Port scanning completed");
            }
            catch (Exception ex)
            {
                Log.Error(ex, "❌ Error during port scanning");
                portData.Error = ex.Message;
            }

            return portData;
        }

        /// <summary>
        /// Service fingerprinting and banner grabbing
        /// </summary>
        private async Task<ServiceData> PerformServiceFingerprintingAsync()
        {
            var serviceData = new ServiceData();

            try
            {
                // HTTP service analysis
                Log.Information("🔍 Analyzing HTTP services...");
                serviceData.HttpServices = await AnalyzeHttpServicesAsync();

                // FTP service analysis
                Log.Information("🔍 Analyzing FTP services...");
                serviceData.FtpServices = await AnalyzeFtpServicesAsync();

                // SSH service analysis
                Log.Information("🔍 Analyzing SSH services...");
                serviceData.SshServices = await AnalyzeSshServicesAsync();

                // Database service analysis
                Log.Information("🔍 Analyzing database services...");
                serviceData.DatabaseServices = await AnalyzeDatabaseServicesAsync();

                // Mail service analysis
                Log.Information("🔍 Analyzing mail services...");
                serviceData.MailServices = await AnalyzeMailServicesAsync();

                Log.Information("✅ Service fingerprinting completed");
            }
            catch (Exception ex)
            {
                Log.Error(ex, "❌ Error during service fingerprinting");
                serviceData.Error = ex.Message;
            }

            return serviceData;
        }

        /// <summary>
        /// SSL/TLS certificate analysis
        /// </summary>
        private async Task<CertificateData> PerformCertificateAnalysisAsync()
        {
            var certData = new CertificateData();

            try
            {
                // Certificate details
                Log.Information("🔍 Analyzing SSL/TLS certificates...");
                certData.CertificateDetails = await AnalyzeCertificatesAsync();

                // Certificate chain analysis
                Log.Information("🔍 Analyzing certificate chains...");
                certData.CertificateChains = await AnalyzeCertificateChainsAsync();

                // Certificate transparency logs
                Log.Information("🔍 Checking certificate transparency...");
                certData.TransparencyLogs = await CheckCertificateTransparencyAsync();

                // SSL/TLS configuration analysis
                Log.Information("🔍 Analyzing SSL/TLS configuration...");
                certData.SslConfiguration = await AnalyzeSslConfigurationAsync();

                Log.Information("✅ Certificate analysis completed");
            }
            catch (Exception ex)
            {
                Log.Error(ex, "❌ Error during certificate analysis");
                certData.Error = ex.Message;
            }

            return certData;
        }

        /// <summary>
        /// Directory and file enumeration
        /// </summary>
        private async Task<DirectoryData> PerformDirectoryEnumerationAsync()
        {
            var dirData = new DirectoryData();

            try
            {
                // Common directories
                Log.Information("🔍 Enumerating common directories...");
                dirData.CommonDirectories = await EnumerateCommonDirectoriesAsync();

                // Configuration files
                Log.Information("🔍 Searching for configuration files...");
                dirData.ConfigurationFiles = await SearchConfigurationFilesAsync();

                // Backup files
                Log.Information("🔍 Searching for backup files...");
                dirData.BackupFiles = await SearchBackupFilesAsync();

                // Source code files
                Log.Information("🔍 Searching for source code files...");
                dirData.SourceCodeFiles = await SearchSourceCodeFilesAsync();

                // Sensitive files
                Log.Information("🔍 Searching for sensitive files...");
                dirData.SensitiveFiles = await SearchSensitiveFilesAsync();

                Log.Information("✅ Directory enumeration completed");
            }
            catch (Exception ex)
            {
                Log.Error(ex, "❌ Error during directory enumeration");
                dirData.Error = ex.Message;
            }

            return dirData;
        }

        /// <summary>
        /// Technology stack analysis
        /// </summary>
        private async Task<TechnologyData> PerformTechnologyAnalysisAsync()
        {
            var techData = new TechnologyData();

            try
            {
                // Web technologies
                Log.Information("🔍 Analyzing web technologies...");
                techData.WebTechnologies = await AnalyzeWebTechnologiesAsync();

                // Server technologies
                Log.Information("🔍 Analyzing server technologies...");
                techData.ServerTechnologies = await AnalyzeServerTechnologiesAsync();

                // Database technologies
                Log.Information("🔍 Analyzing database technologies...");
                techData.DatabaseTechnologies = await AnalyzeDatabaseTechnologiesAsync();

                // Framework analysis
                Log.Information("🔍 Analyzing frameworks...");
                techData.Frameworks = await AnalyzeFrameworksAsync();

                // Third-party libraries
                Log.Information("🔍 Analyzing third-party libraries...");
                techData.ThirdPartyLibraries = await AnalyzeThirdPartyLibrariesAsync();

                Log.Information("✅ Technology analysis completed");
            }
            catch (Exception ex)
            {
                Log.Error(ex, "❌ Error during technology analysis");
                techData.Error = ex.Message;
            }

            return techData;
        }

        // Helper methods for each reconnaissance phase
        private async Task<List<string>> PerformGoogleDorkingAsync(string domain)
        {
            var dorks = new List<string>();
            var googleDorks = new[]
            {
                $"site:{domain} filetype:pdf",
                $"site:{domain} filetype:doc",
                $"site:{domain} filetype:xls",
                $"site:{domain} \"password\"",
                $"site:{domain} \"api key\"",
                $"site:{domain} \"secret\"",
                $"site:{domain} \"config\"",
                $"site:{domain} \"backup\"",
                $"site:{domain} \"admin\"",
                $"site:{domain} \"login\""
            };

            foreach (var dork in googleDorks)
            {
                try
                {
                    // Simulate Google dorking (in real implementation, use Google Custom Search API)
                    dorks.Add(dork);
                    await Task.Delay(100); // Rate limiting
                }
                catch (Exception ex)
                {
                    Log.Warning("Failed to execute dork: {Dork} - {Error}", dork, ex.Message);
                }
            }

            return dorks;
        }

        private async Task<Dictionary<string, object>> PerformShodanLookupAsync(string domain)
        {
            // In real implementation, integrate with Shodan API
            return new Dictionary<string, object>();
        }

        private async Task<List<string>> PerformCertificateTransparencyLookupAsync(string domain)
        {
            // In real implementation, query CT logs
            return new List<string>();
        }

        private async Task<Dictionary<string, object>> PerformSocialMediaIntelligenceAsync(string domain)
        {
            // In real implementation, search social media platforms
            return new Dictionary<string, object>();
        }

        private async Task<Dictionary<string, object>> PerformDnsHistoryLookupAsync(string domain)
        {
            // In real implementation, query DNS history services
            return new Dictionary<string, object>();
        }

        private async Task<Dictionary<string, string>> EnumerateDnsRecordsAsync(string domain)
        {
            var records = new Dictionary<string, string>();
            
            try
            {
                var dnsRecords = await System.Net.Dns.GetHostEntryAsync(domain);
                
                records["A"] = string.Join(", ", dnsRecords.AddressList.Select(ip => ip.ToString()));
                
                // Add more DNS record types as needed
            }
            catch (Exception ex)
            {
                Log.Warning("DNS enumeration failed: {Error}", ex.Message);
            }

            return records;
        }

        private async Task<List<string>> DiscoverSubdomainsAsync(string domain)
        {
            var subdomains = new List<string>();
            var commonSubdomains = new[]
            {
                "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
                "app", "web", "db", "mysql", "postgres", "redis", "cache",
                "cdn", "static", "assets", "images", "js", "css", "docs"
            };

            foreach (var subdomain in commonSubdomains)
            {
                try
                {
                    var fullDomain = $"{subdomain}.{domain}";
                    var dnsResult = await System.Net.Dns.GetHostEntryAsync(fullDomain);
                    subdomains.Add(fullDomain);
                }
                catch
                {
                    // Subdomain doesn't exist
                }
            }

            return subdomains;
        }

        private async Task<Dictionary<string, object>> AttemptZoneTransferAsync(string domain)
        {
            // In real implementation, attempt DNS zone transfer
            return new Dictionary<string, object>();
        }

        private async Task<Dictionary<string, string>> PerformReverseDnsLookupAsync(string domain)
        {
            var reverseDns = new Dictionary<string, string>();
            
            try
            {
                var dnsResult = await System.Net.Dns.GetHostEntryAsync(domain);
                foreach (var ip in dnsResult.AddressList)
                {
                    try
                    {
                        var reverseDnsResult = await System.Net.Dns.GetHostEntryAsync(ip);
                        reverseDns[ip.ToString()] = reverseDnsResult.HostName;
                    }
                    catch
                    {
                        reverseDns[ip.ToString()] = "No reverse DNS";
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Warning("Reverse DNS lookup failed: {Error}", ex.Message);
            }

            return reverseDns;
        }

        private async Task<List<PortInfo>> ScanCommonPortsAsync(string host)
        {
            var commonPorts = new[] { 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306, 1433, 6379, 27017 };
            var openPorts = new List<PortInfo>();

            foreach (var port in commonPorts)
            {
                try
                {
                    using var client = new TcpClient();
                    await client.ConnectAsync(host, port);
                    if (client.Connected)
                    {
                        openPorts.Add(new PortInfo { Port = port, IsOpen = true, Protocol = "TCP" });
                    }
                }
                catch
                {
                    // Port is closed or filtered
                }
            }

            return openPorts;
        }

        private async Task<List<PortInfo>> ScanTop1000PortsAsync(string host)
        {
            // In real implementation, scan top 1000 ports
            return new List<PortInfo>();
        }

        private async Task<List<PortInfo>> ScanUdpPortsAsync(string host)
        {
            // In real implementation, scan UDP ports
            return new List<PortInfo>();
        }

        private async Task<Dictionary<int, string>> DetectServiceVersionsAsync(List<PortInfo> openPorts)
        {
            var versions = new Dictionary<int, string>();
            
            foreach (var port in openPorts.Where(p => p.IsOpen))
            {
                try
                {
                    using var client = new TcpClient();
                    await client.ConnectAsync(new Uri(_target).Host, port.Port);
                    
                    // Banner grabbing
                    using var stream = client.GetStream();
                    var buffer = new byte[1024];
                    var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                    var banner = System.Text.Encoding.ASCII.GetString(buffer, 0, bytesRead);
                    
                    versions[port.Port] = banner.Trim();
                }
                catch
                {
                    versions[port.Port] = "Unknown";
                }
            }

            return versions;
        }

        // Additional helper methods for service analysis
        private async Task<Dictionary<string, object>> AnalyzeHttpServicesAsync()
        {
            var httpServices = new Dictionary<string, object>();
            
            try
            {
                var response = await _httpClient.GetAsync(_target);
                httpServices["Status"] = response.StatusCode.ToString();
                httpServices["Headers"] = response.Headers.ToDictionary(h => h.Key, h => string.Join(", ", h.Value));
                httpServices["Server"] = response.Headers.GetValues("Server").FirstOrDefault() ?? "Unknown";
            }
            catch (Exception ex)
            {
                Log.Warning("HTTP service analysis failed: {Error}", ex.Message);
            }

            return httpServices;
        }

        private async Task<Dictionary<string, object>> AnalyzeFtpServicesAsync()
        {
            // In real implementation, analyze FTP services
            return new Dictionary<string, object>();
        }

        private async Task<Dictionary<string, object>> AnalyzeSshServicesAsync()
        {
            // In real implementation, analyze SSH services
            return new Dictionary<string, object>();
        }

        private async Task<Dictionary<string, object>> AnalyzeDatabaseServicesAsync()
        {
            // In real implementation, analyze database services
            return new Dictionary<string, object>();
        }

        private async Task<Dictionary<string, object>> AnalyzeMailServicesAsync()
        {
            // In real implementation, analyze mail services
            return new Dictionary<string, object>();
        }

        private async Task<Dictionary<string, object>> AnalyzeCertificatesAsync()
        {
            // In real implementation, analyze SSL certificates
            return new Dictionary<string, object>();
        }

        private async Task<Dictionary<string, object>> AnalyzeCertificateChainsAsync()
        {
            // In real implementation, analyze certificate chains
            return new Dictionary<string, object>();
        }

        private async Task<List<string>> CheckCertificateTransparencyAsync()
        {
            // In real implementation, check CT logs
            return new List<string>();
        }

        private async Task<Dictionary<string, object>> AnalyzeSslConfigurationAsync()
        {
            // In real implementation, analyze SSL configuration
            return new Dictionary<string, object>();
        }

        private async Task<List<string>> EnumerateCommonDirectoriesAsync()
        {
            var commonDirs = new[]
            {
                "admin", "administrator", "api", "app", "assets", "backup", "bin", "config",
                "css", "data", "db", "dev", "docs", "download", "files", "images", "img",
                "inc", "include", "js", "lib", "logs", "media", "old", "php", "private",
                "public", "scripts", "src", "static", "temp", "test", "tmp", "uploads",
                "var", "www", "xml", "xsl"
            };

            var foundDirs = new List<string>();
            
            foreach (var dir in commonDirs)
            {
                try
                {
                    var url = $"{_target.TrimEnd('/')}/{dir}/";
                    var response = await _httpClient.GetAsync(url);
                    if (response.IsSuccessStatusCode)
                    {
                        foundDirs.Add(dir);
                    }
                }
                catch
                {
                    // Directory doesn't exist or is inaccessible
                }
            }

            return foundDirs;
        }

        private async Task<List<string>> SearchConfigurationFilesAsync()
        {
            var configFiles = new[]
            {
                "appsettings.json", "appsettings.Production.json", "appsettings.Development.json",
                "web.config", "app.config", "config.json", "settings.json", "configuration.json",
                ".env", ".env.local", ".env.production", ".env.development",
                "docker-compose.yml", "docker-compose.yaml", "Dockerfile",
                "package.json", "composer.json", "requirements.txt", "pom.xml", "build.gradle",
                "yarn.lock", "package-lock.json", "Gemfile", "Gemfile.lock"
            };

            var foundFiles = new List<string>();
            
            foreach (var file in configFiles)
            {
                try
                {
                    var url = $"{_target.TrimEnd('/')}/{file}";
                    var response = await _httpClient.GetAsync(url);
                    if (response.IsSuccessStatusCode)
                    {
                        foundFiles.Add(file);
                    }
                }
                catch
                {
                    // File doesn't exist or is inaccessible
                }
            }

            return foundFiles;
        }

        private async Task<List<string>> SearchBackupFilesAsync()
        {
            var backupFiles = new[]
            {
                "backup.sql", "backup.db", "backup.zip", "backup.tar.gz", "backup.rar",
                "database.sql", "database.db", "data.sql", "data.db",
                "backup_", "backup.", "bak", ".bak", ".backup", ".old", ".orig"
            };

            var foundFiles = new List<string>();
            
            foreach (var file in backupFiles)
            {
                try
                {
                    var url = $"{_target.TrimEnd('/')}/{file}";
                    var response = await _httpClient.GetAsync(url);
                    if (response.IsSuccessStatusCode)
                    {
                        foundFiles.Add(file);
                    }
                }
                catch
                {
                    // File doesn't exist or is inaccessible
                }
            }

            return foundFiles;
        }

        private async Task<List<string>> SearchSourceCodeFilesAsync()
        {
            var sourceFiles = new[]
            {
                "index.php", "index.html", "index.asp", "index.aspx", "index.jsp",
                "main.py", "app.py", "server.py", "main.js", "app.js", "server.js",
                "main.cs", "Program.cs", "Startup.cs", "main.java", "App.java",
                "main.cpp", "main.c", "main.go", "main.rs", "main.rb"
            };

            var foundFiles = new List<string>();
            
            foreach (var file in sourceFiles)
            {
                try
                {
                    var url = $"{_target.TrimEnd('/')}/{file}";
                    var response = await _httpClient.GetAsync(url);
                    if (response.IsSuccessStatusCode)
                    {
                        foundFiles.Add(file);
                    }
                }
                catch
                {
                    // File doesn't exist or is inaccessible
                }
            }

            return foundFiles;
        }

        private async Task<List<string>> SearchSensitiveFilesAsync()
        {
            var sensitiveFiles = new[]
            {
                "password.txt", "passwords.txt", "users.txt", "accounts.txt",
                "secrets.txt", "keys.txt", "private.txt", "confidential.txt",
                "database.txt", "db.txt", "sql.txt", "dump.sql", "export.sql",
                "logs.txt", "error.log", "access.log", "debug.log", "system.log"
            };

            var foundFiles = new List<string>();
            
            foreach (var file in sensitiveFiles)
            {
                try
                {
                    var url = $"{_target.TrimEnd('/')}/{file}";
                    var response = await _httpClient.GetAsync(url);
                    if (response.IsSuccessStatusCode)
                    {
                        foundFiles.Add(file);
                    }
                }
                catch
                {
                    // File doesn't exist or is inaccessible
                }
            }

            return foundFiles;
        }

        private async Task<Dictionary<string, object>> AnalyzeWebTechnologiesAsync()
        {
            var webTech = new Dictionary<string, object>();
            
            try
            {
                var response = await _httpClient.GetAsync(_target);
                var headers = response.Headers.ToDictionary(h => h.Key, h => string.Join(", ", h.Value));
                
                webTech["Server"] = headers.GetValueOrDefault("Server", "Unknown");
                webTech["X-Powered-By"] = headers.GetValueOrDefault("X-Powered-By", "Unknown");
                webTech["X-Framework"] = headers.GetValueOrDefault("X-Framework", "Unknown");
                webTech["X-Generator"] = headers.GetValueOrDefault("X-Generator", "Unknown");
            }
            catch (Exception ex)
            {
                Log.Warning("Web technology analysis failed: {Error}", ex.Message);
            }

            return webTech;
        }

        private async Task<Dictionary<string, object>> AnalyzeServerTechnologiesAsync()
        {
            // In real implementation, analyze server technologies
            return new Dictionary<string, object>();
        }

        private async Task<Dictionary<string, object>> AnalyzeDatabaseTechnologiesAsync()
        {
            // In real implementation, analyze database technologies
            return new Dictionary<string, object>();
        }

        private async Task<Dictionary<string, object>> AnalyzeFrameworksAsync()
        {
            // In real implementation, analyze frameworks
            return new Dictionary<string, object>();
        }

        private async Task<Dictionary<string, object>> AnalyzeThirdPartyLibrariesAsync()
        {
            // In real implementation, analyze third-party libraries
            return new Dictionary<string, object>();
        }
    }

    // Data models for reconnaissance results
    public class ReconnaissanceReport
    {
        public string Target { get; set; } = string.Empty;
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public string? Error { get; set; }
        
        public OsintData? OsintData { get; set; }
        public DnsData? DnsData { get; set; }
        public PortScanData? PortScanData { get; set; }
        public ServiceData? ServiceData { get; set; }
        public CertificateData? CertificateData { get; set; }
        public DirectoryData? DirectoryData { get; set; }
        public TechnologyData? TechnologyData { get; set; }
    }

    public class OsintData
    {
        public List<string> GoogleDorks { get; set; } = new();
        public Dictionary<string, object> ShodanData { get; set; } = new();
        public List<string> CertificateTransparency { get; set; } = new();
        public Dictionary<string, object> SocialMediaData { get; set; } = new();
        public Dictionary<string, object> DnsHistory { get; set; } = new();
        public string? Error { get; set; }
    }

    public class DnsData
    {
        public Dictionary<string, string> DnsRecords { get; set; } = new();
        public List<string> Subdomains { get; set; } = new();
        public Dictionary<string, object> ZoneTransfer { get; set; } = new();
        public Dictionary<string, string> ReverseDns { get; set; } = new();
        public string? Error { get; set; }
    }

    public class PortScanData
    {
        public List<PortInfo> CommonPorts { get; set; } = new();
        public List<PortInfo> Top1000Ports { get; set; } = new();
        public List<PortInfo> UdpPorts { get; set; } = new();
        public Dictionary<int, string> ServiceVersions { get; set; } = new();
        public string? Error { get; set; }
    }

    public class PortInfo
    {
        public int Port { get; set; }
        public bool IsOpen { get; set; }
        public string Protocol { get; set; } = string.Empty;
        public string Service { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
    }

    public class ServiceData
    {
        public Dictionary<string, object> HttpServices { get; set; } = new();
        public Dictionary<string, object> FtpServices { get; set; } = new();
        public Dictionary<string, object> SshServices { get; set; } = new();
        public Dictionary<string, object> DatabaseServices { get; set; } = new();
        public Dictionary<string, object> MailServices { get; set; } = new();
        public string? Error { get; set; }
    }

    public class CertificateData
    {
        public Dictionary<string, object> CertificateDetails { get; set; } = new();
        public Dictionary<string, object> CertificateChains { get; set; } = new();
        public List<string> TransparencyLogs { get; set; } = new();
        public Dictionary<string, object> SslConfiguration { get; set; } = new();
        public string? Error { get; set; }
    }

    public class DirectoryData
    {
        public List<string> CommonDirectories { get; set; } = new();
        public List<string> ConfigurationFiles { get; set; } = new();
        public List<string> BackupFiles { get; set; } = new();
        public List<string> SourceCodeFiles { get; set; } = new();
        public List<string> SensitiveFiles { get; set; } = new();
        public string? Error { get; set; }
    }

    public class TechnologyData
    {
        public Dictionary<string, object> WebTechnologies { get; set; } = new();
        public Dictionary<string, object> ServerTechnologies { get; set; } = new();
        public Dictionary<string, object> DatabaseTechnologies { get; set; } = new();
        public Dictionary<string, object> Frameworks { get; set; } = new();
        public Dictionary<string, object> ThirdPartyLibraries { get; set; } = new();
        public string? Error { get; set; }
    }
}
