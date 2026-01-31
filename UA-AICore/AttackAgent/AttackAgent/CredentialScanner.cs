using AttackAgent.Models;
using Serilog;
using System.Text.RegularExpressions;

namespace AttackAgent
{
    /// <summary>
    /// Credential scanner that searches for exposed sensitive information
    /// including database credentials, API keys, and other secrets
    /// </summary>
    public class CredentialScanner
    {
        private readonly SecurityHttpClient _httpClient;
        private readonly ILogger _logger;
        private readonly List<CredentialPattern> _patterns;
        private int _testedFilesCount = 0;

        public CredentialScanner(string baseUrl = "")
        {
            _httpClient = new SecurityHttpClient(baseUrl);
            _logger = Log.ForContext<CredentialScanner>();
            _patterns = InitializeCredentialPatterns();
        }

        /// <summary>
        /// Scans the application for exposed credentials and sensitive information
        /// </summary>
        public async Task<List<Vulnerability>> ScanForCredentialsAsync(ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            _logger.Information("🔍 Starting credential scanning...");
            _logger.Information("Scanning {EndpointCount} endpoints for exposed credentials", profile.DiscoveredEndpoints.Count);

            // Scan each endpoint for credential exposure
            foreach (var endpoint in profile.DiscoveredEndpoints)
            {
                var endpointVulns = await ScanEndpointForCredentialsAsync(endpoint, profile.BaseUrl);
                vulnerabilities.AddRange(endpointVulns);
            }

            // Scan for common credential files
            var fileVulns = await ScanForCredentialFilesAsync(profile.BaseUrl);
            vulnerabilities.AddRange(fileVulns);

            // Enhanced configuration file scanning
            var configVulns = await ScanConfigurationFilesAsync(profile.BaseUrl);
            vulnerabilities.AddRange(configVulns);

            _logger.Information("Credential scanning completed. Found {VulnCount} credential exposures", vulnerabilities.Count);
            return vulnerabilities;
        }

        /// <summary>
        /// Scans a specific endpoint for credential exposure
        /// </summary>
        private async Task<List<Vulnerability>> ScanEndpointForCredentialsAsync(EndpointInfo endpoint, string baseUrl)
        {
            var vulnerabilities = new List<Vulnerability>();
            var url = baseUrl.TrimEnd('/') + endpoint.Path;

            try
            {
                var response = await _httpClient.GetAsync(url);
                
                if (response.Success)
                {
                    var foundCredentials = ScanContentForCredentials(response.Content, endpoint);
                    vulnerabilities.AddRange(foundCredentials);
                }
            }
            catch (Exception ex)
            {
                _logger.Debug("Error scanning endpoint {Path} for credentials: {Error}", endpoint.Path, ex.Message);
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Scans content for credential patterns
        /// </summary>
        private List<Vulnerability> ScanContentForCredentials(string content, EndpointInfo endpoint)
        {
            var vulnerabilities = new List<Vulnerability>();

            foreach (var pattern in _patterns)
            {
                var matches = pattern.Regex.Matches(content);
                
                foreach (Match match in matches)
                {
                    var vulnerability = CreateCredentialVulnerability(endpoint, pattern, match);
                    vulnerabilities.Add(vulnerability);
                    
                    _logger.Warning("🚨 Credential exposure found: {Type} in {Method} {Path}", 
                        pattern.Type, endpoint.Method, endpoint.Path);
                }
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Scans for common credential files
        /// </summary>
        private async Task<List<Vulnerability>> ScanForCredentialFilesAsync(string baseUrl)
        {
            var vulnerabilities = new List<Vulnerability>();
            var credentialFiles = new[]
            {
                "/.env",
                "/config/database.yml",
                "/config/database.json",
                "/appsettings.json",
                "/appsettings.Development.json",
                "/appsettings.Production.json",
                "/web.config",
                "/.aws/credentials",
                "/.ssh/id_rsa",
                "/.ssh/id_dsa",
                "/.ssh/known_hosts",
                "/.git/config",
                "/.htaccess",
                "/robots.txt",
                "/sitemap.xml",
                "/backup.sql",
                "/dump.sql",
                "/database.sql",
                "/config.php",
                "/wp-config.php",
                "/.env.local",
                "/.env.production",
                "/secrets.json",
                "/credentials.json"
            };

            _logger.Information("Scanning for {FileCount} common credential files", credentialFiles.Length);
            _testedFilesCount = credentialFiles.Length;

            foreach (var file in credentialFiles)
            {
                try
                {
                    var url = baseUrl.TrimEnd('/') + file;
                    var response = await _httpClient.GetAsync(url);
                    
                    if (response.Success && response.ContentLength > 0)
                    {
                        var foundCredentials = ScanContentForCredentials(response.Content, 
                            new EndpointInfo { Path = file, Method = "GET" });
                        vulnerabilities.AddRange(foundCredentials);
                        
                        if (foundCredentials.Any())
                        {
                            _logger.Warning("🚨 Credential file accessible: {File}", file);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug("Error scanning credential file {File}: {Error}", file, ex.Message);
                }
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Creates a vulnerability object for found credentials
        /// </summary>
        private Vulnerability CreateCredentialVulnerability(EndpointInfo endpoint, CredentialPattern pattern, Match match)
        {
            var severity = DetermineCredentialSeverity(pattern.Type);
            var maskedValue = MaskSensitiveValue(match.Value);

            return new Vulnerability
            {
                Type = VulnerabilityType.InformationDisclosure,
                Severity = severity,
                Title = $"Exposed {pattern.Type}",
                Description = $"Sensitive {pattern.Type.ToLower()} found in application response. This could lead to unauthorized access.",
                Endpoint = endpoint.Path,
                Method = endpoint.Method,
                Payload = maskedValue,
                Evidence = $"Found {pattern.Type} pattern: {maskedValue}",
                Remediation = GetCredentialRemediation(pattern.Type),
                AttackMode = AttackMode.Stealth,
                Confidence = 0.9,
                Verified = true
            };
        }

        /// <summary>
        /// Determines severity based on credential type
        /// </summary>
        private SeverityLevel DetermineCredentialSeverity(string credentialType)
        {
            return credentialType.ToLower() switch
            {
                "database password" or "api key" or "secret key" or "private key" => SeverityLevel.Critical,
                "database connection string" or "aws credentials" or "oauth token" => SeverityLevel.High,
                "email password" or "ftp password" or "ssh key" => SeverityLevel.High,
                "username" or "email" => SeverityLevel.Medium,
                _ => SeverityLevel.Medium
            };
        }

        /// <summary>
        /// Masks sensitive values for security
        /// </summary>
        private string MaskSensitiveValue(string value)
        {
            if (value.Length <= 8)
                return new string('*', value.Length);
            
            return value.Substring(0, 4) + new string('*', value.Length - 8) + value.Substring(value.Length - 4);
        }

        /// <summary>
        /// Gets remediation advice for credential exposure
        /// </summary>
        private string GetCredentialRemediation(string credentialType)
        {
            return credentialType.ToLower() switch
            {
                "database password" => "Remove database credentials from source code and configuration files. Use environment variables or secure key management services.",
                "api key" => "Regenerate the exposed API key immediately. Store API keys in environment variables or secure key management services.",
                "secret key" => "Regenerate the exposed secret key immediately. Use secure key management services for secret storage.",
                "private key" => "Revoke the exposed private key immediately. Generate a new key pair and update all systems.",
                "database connection string" => "Remove connection strings from source code. Use environment variables or secure configuration management.",
                "aws credentials" => "Revoke the exposed AWS credentials immediately. Generate new credentials and update all systems.",
                _ => "Remove all sensitive information from source code and configuration files. Use environment variables or secure key management services."
            };
        }

        /// <summary>
        /// Initializes comprehensive credential detection patterns
        /// </summary>
        private List<CredentialPattern> InitializeCredentialPatterns()
        {
            return new List<CredentialPattern>
            {
                // Database credentials
                new CredentialPattern
                {
                    Type = "Database Password",
                    Regex = new Regex(@"password\s*[=:]\s*['""]?([^'""\s]{6,})['""]?", RegexOptions.IgnoreCase),
                    Description = "Database password in connection strings"
                },
                new CredentialPattern
                {
                    Type = "Database Connection String",
                    Regex = new Regex(@"connectionstring\s*[=:]\s*['""]([^'""]{20,})['""]", RegexOptions.IgnoreCase),
                    Description = "Full database connection string"
                },
                new CredentialPattern
                {
                    Type = "Database Connection String",
                    Regex = new Regex(@"server\s*=\s*[^;]+;.*password\s*=\s*[^;]+", RegexOptions.IgnoreCase),
                    Description = "SQL Server connection string with password"
                },
                new CredentialPattern
                {
                    Type = "Database Connection String",
                    Regex = new Regex(@"host\s*=\s*[^;]+;.*password\s*=\s*[^;]+", RegexOptions.IgnoreCase),
                    Description = "MySQL/PostgreSQL connection string with password"
                },

                // API Keys
                new CredentialPattern
                {
                    Type = "API Key",
                    Regex = new Regex(@"api[_-]?key\s*[=:]\s*['""]?([a-zA-Z0-9]{20,})['""]?", RegexOptions.IgnoreCase),
                    Description = "API key in configuration"
                },
                new CredentialPattern
                {
                    Type = "API Key",
                    Regex = new Regex(@"apikey\s*[=:]\s*['""]?([a-zA-Z0-9]{20,})['""]?", RegexOptions.IgnoreCase),
                    Description = "API key without underscore"
                },
                new CredentialPattern
                {
                    Type = "API Key",
                    Regex = new Regex(@"['""]?sk-[a-zA-Z0-9]{20,}['""]?", RegexOptions.IgnoreCase),
                    Description = "OpenAI API key"
                },
                new CredentialPattern
                {
                    Type = "API Key",
                    Regex = new Regex(@"['""]?pk_[a-zA-Z0-9]{20,}['""]?", RegexOptions.IgnoreCase),
                    Description = "Stripe API key"
                },
                new CredentialPattern
                {
                    Type = "API Key",
                    Regex = new Regex(@"['""]?AIza[0-9A-Za-z\\-_]{35}['""]?", RegexOptions.IgnoreCase),
                    Description = "Google API key"
                },

                // AWS Credentials
                new CredentialPattern
                {
                    Type = "AWS Credentials",
                    Regex = new Regex(@"aws_access_key_id\s*=\s*['""]?([A-Z0-9]{20})['""]?", RegexOptions.IgnoreCase),
                    Description = "AWS access key ID"
                },
                new CredentialPattern
                {
                    Type = "AWS Credentials",
                    Regex = new Regex(@"aws_secret_access_key\s*=\s*['""]?([A-Za-z0-9/+=]{40})['""]?", RegexOptions.IgnoreCase),
                    Description = "AWS secret access key"
                },
                new CredentialPattern
                {
                    Type = "AWS Credentials",
                    Regex = new Regex(@"['""]?AKIA[0-9A-Z]{16}['""]?", RegexOptions.IgnoreCase),
                    Description = "AWS access key ID pattern"
                },

                // OAuth and Tokens
                new CredentialPattern
                {
                    Type = "OAuth Token",
                    Regex = new Regex(@"oauth[_-]?token\s*[=:]\s*['""]?([a-zA-Z0-9]{20,})['""]?", RegexOptions.IgnoreCase),
                    Description = "OAuth token"
                },
                new CredentialPattern
                {
                    Type = "Bearer Token",
                    Regex = new Regex(@"bearer\s+['""]?([a-zA-Z0-9._-]{20,})['""]?", RegexOptions.IgnoreCase),
                    Description = "Bearer token"
                },
                new CredentialPattern
                {
                    Type = "JWT Token",
                    Regex = new Regex(@"['""]?eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*['""]?", RegexOptions.IgnoreCase),
                    Description = "JWT token"
                },

                // Email credentials
                new CredentialPattern
                {
                    Type = "Email Password",
                    Regex = new Regex(@"smtp[_-]?password\s*[=:]\s*['""]?([^'""\s]{6,})['""]?", RegexOptions.IgnoreCase),
                    Description = "SMTP password"
                },
                new CredentialPattern
                {
                    Type = "Email Password",
                    Regex = new Regex(@"mail[_-]?password\s*[=:]\s*['""]?([^'""\s]{6,})['""]?", RegexOptions.IgnoreCase),
                    Description = "Mail password"
                },

                // SSH Keys
                new CredentialPattern
                {
                    Type = "SSH Private Key",
                    Regex = new Regex(@"-----BEGIN [A-Z ]+ PRIVATE KEY-----", RegexOptions.IgnoreCase),
                    Description = "SSH private key"
                },
                new CredentialPattern
                {
                    Type = "SSH Private Key",
                    Regex = new Regex(@"-----BEGIN RSA PRIVATE KEY-----", RegexOptions.IgnoreCase),
                    Description = "RSA private key"
                },
                new CredentialPattern
                {
                    Type = "SSH Private Key",
                    Regex = new Regex(@"-----BEGIN OPENSSH PRIVATE KEY-----", RegexOptions.IgnoreCase),
                    Description = "OpenSSH private key"
                },

                // FTP credentials
                new CredentialPattern
                {
                    Type = "FTP Password",
                    Regex = new Regex(@"ftp[_-]?password\s*[=:]\s*['""]?([^'""\s]{6,})['""]?", RegexOptions.IgnoreCase),
                    Description = "FTP password"
                },

                // Generic secrets
                new CredentialPattern
                {
                    Type = "Secret Key",
                    Regex = new Regex(@"secret[_-]?key\s*[=:]\s*['""]?([a-zA-Z0-9]{16,})['""]?", RegexOptions.IgnoreCase),
                    Description = "Secret key"
                },
                new CredentialPattern
                {
                    Type = "Private Key",
                    Regex = new Regex(@"private[_-]?key\s*[=:]\s*['""]?([a-zA-Z0-9]{16,})['""]?", RegexOptions.IgnoreCase),
                    Description = "Private key"
                },

                // Database specific
                new CredentialPattern
                {
                    Type = "Database Password",
                    Regex = new Regex(@"mysql[_-]?password\s*[=:]\s*['""]?([^'""\s]{6,})['""]?", RegexOptions.IgnoreCase),
                    Description = "MySQL password"
                },
                new CredentialPattern
                {
                    Type = "Database Password",
                    Regex = new Regex(@"postgres[_-]?password\s*[=:]\s*['""]?([^'""\s]{6,})['""]?", RegexOptions.IgnoreCase),
                    Description = "PostgreSQL password"
                },
                new CredentialPattern
                {
                    Type = "Database Password",
                    Regex = new Regex(@"sqlserver[_-]?password\s*[=:]\s*['""]?([^'""\s]{6,})['""]?", RegexOptions.IgnoreCase),
                    Description = "SQL Server password"
                },

                // Usernames (lower severity but still sensitive)
                new CredentialPattern
                {
                    Type = "Username",
                    Regex = new Regex(@"username\s*[=:]\s*['""]?([^'""\s]{3,})['""]?", RegexOptions.IgnoreCase),
                    Description = "Username in configuration"
                },
                new CredentialPattern
                {
                    Type = "Email",
                    Regex = new Regex(@"email\s*[=:]\s*['""]?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})['""]?", RegexOptions.IgnoreCase),
                    Description = "Email address in configuration"
                }
            };
        }

        /// <summary>
        /// Scans configuration files for exposed credentials and sensitive information
        /// </summary>
        private async Task<List<Vulnerability>> ScanConfigurationFilesAsync(string baseUrl)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            // Configuration files to scan
            var configFiles = new[]
            {
                "/appsettings.json", "/appsettings.Development.json", "/appsettings.Production.json",
                "/appsettings.Staging.json", "/appsettings.Local.json", "/appsettings.Test.json",
                "/web.config", "/app.config", "/config.json", "/settings.json",
                "/.env", "/.env.local", "/.env.production", "/.env.development",
                "/config/database.yml", "/config/database.json", "/config/secrets.json",
                "/secrets.json", "/credentials.json", "/keys.json", "/tokens.json"
            };

            _logger.Information("🔍 Scanning {Count} configuration files for exposed credentials...", configFiles.Length);

            foreach (var configFile in configFiles)
            {
                try
                {
                    var url = baseUrl.TrimEnd('/') + configFile;
                    var response = await _httpClient.GetAsync(url);
                    
                    if (response.Success && response.ContentLength > 0)
                    {
                        _logger.Information("📄 Found configuration file: {File}", configFile);
                        
                        // Analyze the configuration file for credentials
                        var configVulns = AnalyzeConfigurationFile(response.Content, configFile);
                        vulnerabilities.AddRange(configVulns);
                        
                        if (configVulns.Any())
                        {
                            _logger.Warning("🚨 Found {Count} credential exposures in {File}", configVulns.Count, configFile);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Error scanning configuration file {File}", configFile);
                }
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Analyzes configuration file content for exposed credentials
        /// </summary>
        private List<Vulnerability> AnalyzeConfigurationFile(string content, string filePath)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            // Enhanced credential patterns for configuration files
            var credentialPatterns = new[]
            {
                // Database connection strings
                new CredentialPattern
                {
                    Type = "Database Connection String",
                    Regex = new Regex(@"Server\s*=\s*[^;]+;.*Password\s*=\s*[^;]+", RegexOptions.IgnoreCase),
                    Description = "Database connection string with password"
                },
                new CredentialPattern
                {
                    Type = "SQL Server Connection",
                    Regex = new Regex(@"Server\s*=\s*[^;]+;.*User\s*Id\s*=\s*[^;]+;.*Password\s*=\s*[^;]+", RegexOptions.IgnoreCase),
                    Description = "SQL Server connection with credentials"
                },
                
                // API Keys
                new CredentialPattern
                {
                    Type = "OpenAI API Key",
                    Regex = new Regex(@"sk-[a-zA-Z0-9]{20,}", RegexOptions.IgnoreCase),
                    Description = "OpenAI API key"
                },
                new CredentialPattern
                {
                    Type = "API Key",
                    Regex = new Regex(@"""ApiKey""\s*:\s*""[^""]+""", RegexOptions.IgnoreCase),
                    Description = "API key in configuration"
                },
                new CredentialPattern
                {
                    Type = "API Key",
                    Regex = new Regex(@"""api[_-]?key""\s*:\s*""[^""]+""", RegexOptions.IgnoreCase),
                    Description = "API key field"
                },
                
                // Connection strings
                new CredentialPattern
                {
                    Type = "Connection String",
                    Regex = new Regex(@"""ConnectionStrings""\s*:\s*{[^}]+}", RegexOptions.IgnoreCase),
                    Description = "Connection strings section"
                },
                new CredentialPattern
                {
                    Type = "Connection String",
                    Regex = new Regex(@"ConnectionString\s*=\s*[^;]+", RegexOptions.IgnoreCase),
                    Description = "Connection string configuration"
                },
                
                // JWT and tokens
                new CredentialPattern
                {
                    Type = "JWT Secret",
                    Regex = new Regex(@"""JwtSecret""\s*:\s*""[^""]+""", RegexOptions.IgnoreCase),
                    Description = "JWT secret key"
                },
                new CredentialPattern
                {
                    Type = "JWT Secret",
                    Regex = new Regex(@"""Secret""\s*:\s*""[^""]+""", RegexOptions.IgnoreCase),
                    Description = "Secret key configuration"
                },
                
                // Passwords
                new CredentialPattern
                {
                    Type = "Password",
                    Regex = new Regex(@"""Password""\s*:\s*""[^""]+""", RegexOptions.IgnoreCase),
                    Description = "Password in configuration"
                },
                new CredentialPattern
                {
                    Type = "Password",
                    Regex = new Regex(@"Password\s*=\s*[^;]+", RegexOptions.IgnoreCase),
                    Description = "Password configuration"
                }
            };

            foreach (var pattern in credentialPatterns)
            {
                var matches = pattern.Regex.Matches(content);
                foreach (Match match in matches)
                {
                    var vulnerability = new Vulnerability
                    {
                        Title = $"Exposed {pattern.Type} in {filePath}",
                        Description = $"{pattern.Description} found in configuration file",
                        Type = VulnerabilityType.InformationDisclosure,
                        Severity = SeverityLevel.High,
                        Endpoint = filePath,
                        Evidence = match.Value.Length > 100 ? match.Value.Substring(0, 100) + "..." : match.Value,
                        Remediation = "Remove or encrypt sensitive information in configuration files",
                        DiscoveredAt = DateTime.UtcNow,
                        FalsePositive = false,
                        Verified = true
                    };
                    
                    vulnerabilities.Add(vulnerability);
                }
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Gets the number of credential files tested
        /// </summary>
        public int GetTestedFilesCount()
        {
            return _testedFilesCount;
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }

}

