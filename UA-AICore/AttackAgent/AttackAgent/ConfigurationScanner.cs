using System.Text.RegularExpressions;
using AttackAgent.Models;
using Serilog;

namespace AttackAgent
{
    /// <summary>
    /// Scans for exposed configuration files and sensitive credentials
    /// </summary>
    public class ConfigurationScanner
    {
        private readonly SecurityHttpClient _httpClient;
        private readonly ILogger _logger;
        
        private readonly List<string> _configPatterns = new()
        {
            // Standard config files
            "appsettings.json", "appsettings.*.json", "web.config", 
            ".env", "config.json", "settings.json", "appsettings.Development.json",
            "appsettings.Production.json", "appsettings.Staging.json",
            "appsettings.Test.json", "configuration.json", "config.xml",
            "secrets.json", "credentials.json", "keys.json",
            
            // Case variations
            "AppSettings.json", "AppSettings.Development.json", "AppSettings.Production.json",
            "appsettings.development.json", "appsettings.production.json",
            
            // Backup files
            "appsettings.json.bak", "appsettings.json.old", "appsettings.json.backup",
            "appsettings.Development.json.bak", "appsettings.Development.json.old",
            "web.config.bak", "web.config.old", "web.config.backup",
            
            // Path traversal attempts
            "../appsettings.Development.json", "../../appsettings.Development.json",
            "../web.config", "../../web.config",
            
            // Directory-based configs
            "config/appsettings.json", "app/appsettings.json", "settings/appsettings.json",
            "config/database.json", "app/config.json", "settings/config.json"
        };
        
        private readonly List<CredentialPattern> _credentialPatterns = new()
        {
            new CredentialPattern
            {
                Name = "Database Connection String",
                Pattern = @"ConnectionString.*=.*Server=([^;]+);.*Password=([^;]+)",
                Severity = SeverityLevel.Critical,
                Description = "Database connection string with password exposed"
            },
            new CredentialPattern
            {
                Name = "Database Connection String (Enhanced)",
                Pattern = @"Server=([^;]+);Database=([^;]+);User Id=([^;]+);Password=([^;]+)",
                Severity = SeverityLevel.Critical,
                Description = "Complete database connection string with credentials exposed"
            },
            new CredentialPattern
            {
                Name = "OpenAI API Key",
                Pattern = @"ApiKey.*=.*(sk-[a-zA-Z0-9]+)",
                Severity = SeverityLevel.Critical,
                Description = "OpenAI API key exposed"
            },
            new CredentialPattern
            {
                Name = "OpenAI API Key (Direct)",
                Pattern = @"(sk-proj-[a-zA-Z0-9_-]+)",
                Severity = SeverityLevel.Critical,
                Description = "OpenAI API key directly exposed"
            },
            new CredentialPattern
            {
                Name = "Generic API Key",
                Pattern = @"ApiKey.*=.*([a-zA-Z0-9]{20,})",
                Severity = SeverityLevel.High,
                Description = "API key exposed"
            },
            new CredentialPattern
            {
                Name = "Password Field",
                Pattern = @"Password.*=.*([^\s]+)",
                Severity = SeverityLevel.Critical,
                Description = "Password field exposed"
            },
            new CredentialPattern
            {
                Name = "Secret Field",
                Pattern = @"Secret.*=.*([^\s]+)",
                Severity = SeverityLevel.High,
                Description = "Secret field exposed"
            },
            new CredentialPattern
            {
                Name = "Token Field",
                Pattern = @"Token.*=.*([^\s]+)",
                Severity = SeverityLevel.High,
                Description = "Token field exposed"
            },
            new CredentialPattern
            {
                Name = "Key Field",
                Pattern = @"Key.*=.*([^\s]+)",
                Severity = SeverityLevel.High,
                Description = "Key field exposed"
            },
            new CredentialPattern
            {
                Name = "JWT Secret",
                Pattern = @"JwtSecret.*=.*([^\s]+)",
                Severity = SeverityLevel.Critical,
                Description = "JWT secret exposed"
            },
            new CredentialPattern
            {
                Name = "Database Password",
                Pattern = @"Password.*=.*([^\s]+).*Database",
                Severity = SeverityLevel.Critical,
                Description = "Database password exposed"
            },
            new CredentialPattern
            {
                Name = "AWS Access Key",
                Pattern = @"AWS_ACCESS_KEY.*=.*([A-Z0-9]{20})",
                Severity = SeverityLevel.Critical,
                Description = "AWS access key exposed"
            },
            new CredentialPattern
            {
                Name = "AWS Secret Key",
                Pattern = @"AWS_SECRET_KEY.*=.*([A-Za-z0-9/+=]{40})",
                Severity = SeverityLevel.Critical,
                Description = "AWS secret key exposed"
            }
        };

        public ConfigurationScanner(string baseUrl = "")
        {
            _httpClient = new SecurityHttpClient(baseUrl);
            _logger = Log.ForContext<ConfigurationScanner>();
        }

        /// <summary>
        /// Scans for configuration files and extracts sensitive credentials
        /// </summary>
        public async Task<List<Vulnerability>> ScanConfigurationFilesAsync(string baseUrl)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            _logger.Information("🔍 Starting configuration file scanning...");
            _logger.Information("🔍 Testing {Count} configuration file patterns...", _configPatterns.Count);

            foreach (var configFile in _configPatterns)
            {
                try
                {
                    var url = baseUrl.TrimEnd('/') + "/" + configFile.TrimStart('/');
                    var response = await _httpClient.GetAsync(url);
                    
                    if (response.Success)
                    {
                        _logger.Warning("🚨 Configuration file found: {ConfigFile}", configFile);
                        vulnerabilities.AddRange(ScanContentForCredentials(response.Content, configFile, url));
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Error testing configuration file {ConfigFile}", configFile);
                }
            }

            // Also test common configuration directories
            // Enhanced directory enumeration
            var configDirectories = new[] { 
                "/config", "/settings", "/secrets", "/.config", "/app", 
                "/backup", "/backups", "/old", "/archive", "/temp", "/tmp",
                "/.git", "/.svn", "/.hg", "/.bzr", "/admin", "/administrator",
                "/debug", "/test", "/dev", "/development", "/staging"
            };
            foreach (var directory in configDirectories)
            {
                try
                {
                    var url = baseUrl.TrimEnd('/') + directory;
                    var response = await _httpClient.GetAsync(url);
                    
                    if (response.Success)
                    {
                        _logger.Warning("🚨 Configuration directory found: {Directory}", directory);
                        vulnerabilities.Add(new Vulnerability
                        {
                            Type = VulnerabilityType.InformationDisclosure,
                            Severity = SeverityLevel.Medium,
                            Title = $"Configuration Directory Exposed: {directory}",
                            Description = $"Configuration directory is accessible and may contain sensitive files",
                            Evidence = $"Directory accessible at: {url}",
                            Endpoint = directory,
                            Method = "GET",
                            DiscoveredAt = DateTime.UtcNow
                        });
                        
                        // Try to enumerate files in the directory
                        await EnumerateDirectoryFilesAsync(baseUrl, directory, vulnerabilities);
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Error testing configuration directory {Directory}", directory);
                }
            }

            // Enhanced: Analyze all discovered endpoints for credential leakage
            _logger.Information("🔍 Analyzing endpoint responses for credential leakage...");
            var endpointCredentialVulns = await AnalyzeEndpointResponsesForCredentialsAsync(baseUrl);
            vulnerabilities.AddRange(endpointCredentialVulns);

            _logger.Information("✅ Configuration file scanning completed. Found {Count} vulnerabilities", vulnerabilities.Count);
            return vulnerabilities;
        }

        /// <summary>
        /// Analyzes endpoint responses for credential leakage
        /// </summary>
        private async Task<List<Vulnerability>> AnalyzeEndpointResponsesForCredentialsAsync(string baseUrl)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            // Test common endpoints that might leak configuration
            var testEndpoints = new[]
            {
                "/", "/index.html", "/api/hello", "/api/db-test", "/api/desserts",
                "/swagger", "/swagger/index.html", "/api-docs", "/health", "/status",
                "/debug", "/info", "/config", "/settings", "/admin", "/test"
            };

            foreach (var endpoint in testEndpoints)
            {
                try
                {
                    var url = baseUrl.TrimEnd('/') + endpoint;
                    var response = await _httpClient.GetAsync(url);
                    
                    if (response.Success && !string.IsNullOrEmpty(response.Content))
                    {
                        var credentialVulns = ScanContentForCredentials(response.Content, endpoint, url);
                        vulnerabilities.AddRange(credentialVulns);
                        
                        // IMPROVED: Use pattern-based credential detection instead of simple keywords
                        try
                        {
                            var improvedDetection = new Engines.ImprovedVulnerabilityDetection(baseUrl);
                            var credentialFindings = improvedDetection.DetectCredentialsInResponse(response.Content, endpoint);
                            
                            foreach (var finding in credentialFindings)
                            {
                                if (finding.Confidence >= 0.6) // Only report high-confidence findings
                                {
                                    _logger.Warning("🚨 Credential leakage detected in {Endpoint}: {Type} (Confidence: {Confidence:P0})", 
                                        endpoint, finding.Type, finding.Confidence);
                                    
                                    // Create vulnerability for credential leakage
                                    vulnerabilities.Add(new Vulnerability
                                    {
                                        Type = VulnerabilityType.InformationDisclosure,
                                        Severity = finding.Severity,
                                        Title = $"Credential Leakage Detected: {finding.Type}",
                                        Description = $"Credential information found in {endpoint} response. Confidence: {finding.Confidence:P0}",
                                        Evidence = $"Found {finding.Type}: {finding.Value.Substring(0, Math.Min(50, finding.Value.Length))}... (Line {finding.LineNumber})",
                                        Endpoint = endpoint,
                                        DiscoveredAt = DateTime.UtcNow,
                                        Confidence = finding.Confidence
                                    });
                                }
                            }
                            
                            improvedDetection.Dispose();
                        }
                        catch (Exception ex)
                        {
                            _logger.Debug(ex, "Error using improved credential detection, falling back to basic detection");
                            
                            // Fallback: Only check for highly specific indicators
                            var specificIndicators = new[]
                            {
                                "sk-proj-", // OpenAI API key pattern
                                "sql5111.site4now.net", // Specific database server
                                "Server=.*;Password=", // Connection string pattern
                            };
                            
                            foreach (var indicator in specificIndicators)
                            {
                                if (response.Content.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                                {
                                    vulnerabilities.Add(new Vulnerability
                                    {
                                        Type = VulnerabilityType.InformationDisclosure,
                                        Severity = SeverityLevel.High,
                                        Title = $"Information Disclosure: {indicator}",
                                        Description = $"Potentially sensitive information found in {endpoint} response",
                                        Evidence = $"Found indicator '{indicator}' in response content",
                                        Endpoint = endpoint,
                                        DiscoveredAt = DateTime.UtcNow,
                                        Confidence = 0.7
                                    });
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Error analyzing endpoint {Endpoint}", endpoint);
                }
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Scans content for sensitive credentials using regex patterns
        /// </summary>
        private List<Vulnerability> ScanContentForCredentials(string content, string fileName, string url)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            foreach (var credentialPattern in _credentialPatterns)
            {
                try
                {
                    var regex = new Regex(credentialPattern.Pattern, RegexOptions.IgnoreCase);
                    var matches = regex.Matches(content);
                    foreach (Match match in matches)
                    {
                        var vulnerability = new Vulnerability
                        {
                            Type = VulnerabilityType.InformationDisclosure,
                            Severity = credentialPattern.Severity,
                            Title = $"{credentialPattern.Name} Exposed in {fileName}",
                            Description = credentialPattern.Description,
                            Evidence = $"Pattern: {credentialPattern.Pattern}, Match: {match.Value}",
                            Endpoint = url,
                            Method = "GET",
                            Parameter = fileName,
                            Remediation = $"Remove or secure the exposed {credentialPattern.Name.ToLower()} in {fileName}",
                            Confidence = 0.95
                        };
                        
                        vulnerabilities.Add(vulnerability);
                        _logger.Warning("🚨 {CredentialType} found in {FileName}: {Match}", 
                            credentialPattern.Name, fileName, match.Value);
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Error scanning for credential pattern {Pattern}", credentialPattern.Pattern);
                }
            }

            // Additional checks for common sensitive patterns
            vulnerabilities.AddRange(ScanForAdditionalSensitivePatterns(content, fileName, url));

            return vulnerabilities;
        }

        /// <summary>
        /// Scans for additional sensitive patterns not covered by main patterns
        /// </summary>
        private List<Vulnerability> ScanForAdditionalSensitivePatterns(string content, string fileName, string url)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            // Check for JSON structure with sensitive keys
            var sensitiveKeys = new[] { "password", "secret", "key", "token", "auth", "credential", "api" };
            foreach (var key in sensitiveKeys)
            {
                var pattern = $@"""{key}""\s*:\s*""([^""]+)""";
                var matches = Regex.Matches(content, pattern, RegexOptions.IgnoreCase);
                foreach (Match match in matches)
                {
                    if (match.Groups[1].Value.Length > 5) // Only flag if it looks like a real credential
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Type = VulnerabilityType.InformationDisclosure,
                            Severity = SeverityLevel.High,
                            Title = $"Sensitive {key.ToUpper()} Field Exposed in {fileName}",
                            Description = $"Sensitive {key} field found in configuration file",
                            Evidence = $"Field: {key}, Value: {match.Groups[1].Value}",
                            Endpoint = url,
                            Method = "GET",
                            Parameter = fileName,
                            Remediation = $"Remove or secure the exposed {key} field in {fileName}",
                            Confidence = 0.85
                        });
                    }
                }
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Enumerates files in a discovered directory
        /// </summary>
        private async Task EnumerateDirectoryFilesAsync(string baseUrl, string directory, List<Vulnerability> vulnerabilities)
        {
            var commonFiles = new[]
            {
                "index.html", "index.php", "index.asp", "index.aspx",
                "readme.txt", "readme.md", "README.txt", "README.md",
                "config.txt", "config.md", "settings.txt", "settings.md",
                "backup.sql", "backup.db", "dump.sql", "dump.db",
                "error.log", "access.log", "debug.log", "app.log"
            };

            foreach (var file in commonFiles)
            {
                try
                {
                    var fileUrl = $"{directory}/{file}";
                    var response = await _httpClient.GetAsync(fileUrl);
                    
                    if (response.Success)
                    {
                        _logger.Warning("🚨 File found in directory {Directory}: {File}", directory, file);
                        vulnerabilities.Add(new Vulnerability
                        {
                            Type = VulnerabilityType.InformationDisclosure,
                            Severity = SeverityLevel.High,
                            Title = $"File Exposed in Directory: {file}",
                            Description = $"Sensitive file found in accessible directory",
                            Evidence = $"File accessible at: {baseUrl.TrimEnd('/')}{fileUrl}",
                            Endpoint = fileUrl,
                            Method = "GET",
                            DiscoveredAt = DateTime.UtcNow
                        });
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Error testing file {File} in directory {Directory}", file, directory);
                }
            }
        }

        /// <summary>
        /// Disposes of resources
        /// </summary>
        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }

    /// <summary>
    /// Represents a credential pattern for scanning
    /// </summary>
    public class CredentialPattern
    {
        public string Type { get; set; } = string.Empty;
        public Regex Regex { get; set; } = new Regex("");
        public string Description { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Pattern { get; set; } = string.Empty;
        public SeverityLevel Severity { get; set; }
    }
}
