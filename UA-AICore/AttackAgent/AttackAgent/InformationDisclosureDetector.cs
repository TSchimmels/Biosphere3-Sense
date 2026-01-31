using AttackAgent.Models;
using Serilog;
using System.Text.RegularExpressions;

namespace AttackAgent
{
    /// <summary>
    /// Enhanced information disclosure detection engine
    /// Detects sensitive information exposure in API responses
    /// </summary>
    public class InformationDisclosureDetector
    {
        private readonly SecurityHttpClient _httpClient;
        private readonly ILogger _logger;

        public InformationDisclosureDetector(string baseUrl = "")
        {
            _httpClient = new SecurityHttpClient(baseUrl);
            _logger = Log.ForContext<InformationDisclosureDetector>();
        }

        /// <summary>
        /// Tests all discovered endpoints for information disclosure vulnerabilities
        /// </summary>
        public async Task<List<Vulnerability>> TestForInformationDisclosureAsync(ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            _logger.Information("🔍 Starting information disclosure testing...");
            _logger.Information("Testing {EndpointCount} endpoints for sensitive information exposure", 
                profile.DiscoveredEndpoints.Count);

            foreach (var endpoint in profile.DiscoveredEndpoints)
            {
                if (!IsTestableEndpoint(endpoint))
                    continue;

                _logger.Debug("Testing endpoint: {Method} {Path}", endpoint.Method, endpoint.Path);

                var endpointVulns = await TestEndpointForInformationDisclosureAsync(endpoint, profile.BaseUrl);
                vulnerabilities.AddRange(endpointVulns);
            }

            _logger.Information("Information disclosure testing completed. Found {VulnCount} vulnerabilities", vulnerabilities.Count);
            return vulnerabilities;
        }

        /// <summary>
        /// Tests a specific endpoint for information disclosure vulnerabilities
        /// </summary>
        private async Task<List<Vulnerability>> TestEndpointForInformationDisclosureAsync(EndpointInfo endpoint, string baseUrl)
        {
            var vulnerabilities = new List<Vulnerability>();
            var url = baseUrl.TrimEnd('/') + endpoint.Path;

            try
            {
                // Get response from endpoint
                var response = await GetEndpointResponseAsync(url, endpoint.Method);
                
                if (response.Success)
                {
                    // Test for various types of information disclosure
                    var databaseDisclosure = TestForDatabaseInformationDisclosure(endpoint, response);
                    if (databaseDisclosure != null) vulnerabilities.Add(databaseDisclosure);

                    var errorDisclosure = TestForErrorInformationDisclosure(endpoint, response);
                    if (errorDisclosure != null) vulnerabilities.Add(errorDisclosure);

                    var internalPathDisclosure = TestForInternalPathDisclosure(endpoint, response);
                    if (internalPathDisclosure != null) vulnerabilities.Add(internalPathDisclosure);

                    var apiKeyDisclosure = TestForApiKeyDisclosure(endpoint, response);
                    if (apiKeyDisclosure != null) vulnerabilities.Add(apiKeyDisclosure);

                    var versionDisclosure = TestForVersionInformationDisclosure(endpoint, response);
                    if (versionDisclosure != null) vulnerabilities.Add(versionDisclosure);

                    var configurationDisclosure = TestForConfigurationDisclosure(endpoint, response);
                    if (configurationDisclosure != null) vulnerabilities.Add(configurationDisclosure);
                }
            }
            catch (Exception ex)
            {
                _logger.Debug("Error testing information disclosure for {Endpoint}: {Error}", endpoint.Path, ex.Message);
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Tests for database information disclosure with enhanced context analysis
        /// </summary>
        private Vulnerability? TestForDatabaseInformationDisclosure(EndpointInfo endpoint, HttpResponse response)
        {
            // High-confidence database indicators (actual database terms)
            var highConfidenceIndicators = new[]
            {
                "sql5111.site4now.net", "connectionstring", "serverinfo", "datasource", 
                "initial catalog", "user id", "password", "connection string", "server=",
                "database=", "uid=", "pwd=", "server name", "database name"
            };

            // Medium-confidence indicators that need context validation
            var mediumConfidenceIndicators = new[]
            {
                "sql server", "mysql", "postgresql", "oracle", "mongodb", "redis"
            };

            // Low-confidence indicators (often false positives)
            var lowConfidenceIndicators = new[]
            {
                "database", "server", "connection"
            };

            var foundHighConfidence = new List<string>();
            var foundMediumConfidence = new List<string>();
            var foundLowConfidence = new List<string>();

            // Check high-confidence indicators
            foreach (var indicator in highConfidenceIndicators)
            {
                if (response.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                {
                    foundHighConfidence.Add(indicator);
                }
            }

            // Check medium-confidence indicators with context validation
            foreach (var indicator in mediumConfidenceIndicators)
            {
                if (response.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                {
                    // Additional context validation to reduce false positives
                    if (IsLikelyDatabaseContext(response, indicator))
                    {
                        foundMediumConfidence.Add(indicator);
                    }
                }
            }

            // Check low-confidence indicators only if they appear in suspicious contexts
            foreach (var indicator in lowConfidenceIndicators)
            {
                if (response.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                {
                    if (IsLikelyDatabaseContext(response, indicator))
                    {
                        foundLowConfidence.Add(indicator);
                    }
                }
            }

            // Only report if we have high-confidence indicators or multiple medium-confidence ones
            if (foundHighConfidence.Any() || foundMediumConfidence.Count >= 2 || 
                (foundMediumConfidence.Any() && foundLowConfidence.Any()))
            {
                var allFound = foundHighConfidence.Concat(foundMediumConfidence).Concat(foundLowConfidence).ToList();
                var confidence = CalculateDatabaseDisclosureConfidence(foundHighConfidence, foundMediumConfidence, foundLowConfidence);
                var severity = confidence > 0.8 ? SeverityLevel.Critical : 
                              confidence > 0.6 ? SeverityLevel.High : SeverityLevel.Medium;

                return new Vulnerability
                {
                    Type = VulnerabilityType.InformationDisclosure,
                    Severity = severity,
                    Title = "Database Information Disclosure",
                    Description = $"Endpoint {endpoint.Path} exposes sensitive database information including: {string.Join(", ", allFound)}",
                    Endpoint = endpoint.Path,
                    Method = endpoint.Method,
                    Response = response.Content,
                    Evidence = $"Database indicators found: {string.Join(", ", allFound)}",
                    Remediation = "Remove or sanitize database server information from API responses. Use generic error messages instead of detailed database information.",
                    AttackMode = AttackMode.Stealth,
                    Confidence = confidence,
                    FalsePositive = confidence < 0.5,
                    Verified = confidence > 0.7
                };
            }

            return null;
        }

        /// <summary>
        /// Validates if the context suggests actual database information disclosure
        /// </summary>
        private bool IsLikelyDatabaseContext(HttpResponse response, string indicator)
        {
            var content = response.Content.ToLower();
            var indicatorLower = indicator.ToLower();
            
            // Get context around the indicator (50 characters before and after)
            var index = content.IndexOf(indicatorLower);
            if (index == -1) return false;
            
            var start = Math.Max(0, index - 50);
            var end = Math.Min(content.Length, index + indicatorLower.Length + 50);
            var context = content.Substring(start, end - start);
            
            // Check for database-specific context clues
            var databaseContextClues = new[]
            {
                "connection", "server", "database", "sql", "query", "table", "schema",
                "connectionstring", "datasource", "initial catalog", "user id", "password",
                "server name", "database name", "connection timeout", "command timeout"
            };
            
            // Check for UI/frontend context clues that suggest false positive
            var uiContextClues = new[]
            {
                "bootstrap", "jquery", "javascript", "css", "html", "frontend", "ui",
                "button", "click", "form", "input", "div", "span", "class=", "id="
            };
            
            var databaseClueCount = databaseContextClues.Count(clue => context.Contains(clue));
            var uiClueCount = uiContextClues.Count(clue => context.Contains(clue));
            
            // If more database clues than UI clues, likely real database info
            return databaseClueCount > uiClueCount;
        }

        /// <summary>
        /// Calculates confidence score for database disclosure based on indicator types
        /// </summary>
        private double CalculateDatabaseDisclosureConfidence(List<string> highConfidence, List<string> mediumConfidence, List<string> lowConfidence)
        {
            var score = 0.0;
            
            // High confidence indicators are worth 0.9 points each
            score += highConfidence.Count * 0.9;
            
            // Medium confidence indicators are worth 0.6 points each
            score += mediumConfidence.Count * 0.6;
            
            // Low confidence indicators are worth 0.3 points each
            score += lowConfidence.Count * 0.3;
            
            // Cap at 1.0
            return Math.Min(1.0, score);
        }

        /// <summary>
        /// Tests for error information disclosure
        /// </summary>
        private Vulnerability? TestForErrorInformationDisclosure(EndpointInfo endpoint, HttpResponse response)
        {
            var errorIndicators = new[]
            {
                "exception", "error", "stack trace", "inner exception", "at line",
                "system.exception", "nullreference", "argumentexception", "sqlconnection",
                "entityframework", "system.data", "microsoft.data", "inner exception"
            };

            var foundIndicators = new List<string>();
            foreach (var indicator in errorIndicators)
            {
                if (response.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                {
                    foundIndicators.Add(indicator);
                }
            }

            if (foundIndicators.Any())
            {
                return new Vulnerability
                {
                    Type = VulnerabilityType.InformationDisclosure,
                    Severity = SeverityLevel.High,
                    Title = "Error Information Disclosure",
                    Description = $"Endpoint {endpoint.Path} exposes detailed error information including: {string.Join(", ", foundIndicators)}",
                    Endpoint = endpoint.Path,
                    Method = endpoint.Method,
                    Response = response.Content,
                    Evidence = $"Error indicators found: {string.Join(", ", foundIndicators)}",
                    Remediation = "Implement generic error messages for production. Log detailed errors server-side but return user-friendly messages to clients.",
                    AttackMode = AttackMode.Stealth,
                    Confidence = 0.9,
                    FalsePositive = false,
                    Verified = true
                };
            }

            return null;
        }

        /// <summary>
        /// Tests for internal path disclosure
        /// </summary>
        private Vulnerability? TestForInternalPathDisclosure(EndpointInfo endpoint, HttpResponse response)
        {
            var pathIndicators = new[]
            {
                "c:\\", "d:\\", "e:\\", "/home/", "/var/", "/usr/", "/opt/",
                "appsettings", "web.config", "package.json", "composer.json",
                "bin\\", "obj\\", "wwwroot", "controllers", "models", "services"
            };

            var foundIndicators = new List<string>();
            foreach (var indicator in pathIndicators)
            {
                if (response.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                {
                    foundIndicators.Add(indicator);
                }
            }

            if (foundIndicators.Any())
            {
                return new Vulnerability
                {
                    Type = VulnerabilityType.InformationDisclosure,
                    Severity = SeverityLevel.Medium,
                    Title = "Internal Path Disclosure",
                    Description = $"Endpoint {endpoint.Path} exposes internal file system paths: {string.Join(", ", foundIndicators)}",
                    Endpoint = endpoint.Path,
                    Method = endpoint.Method,
                    Response = response.Content,
                    Evidence = $"Internal paths found: {string.Join(", ", foundIndicators)}",
                    Remediation = "Remove internal file system paths from error messages and API responses. Use relative paths or generic identifiers.",
                    AttackMode = AttackMode.Stealth,
                    Confidence = 0.8,
                    FalsePositive = false,
                    Verified = true
                };
            }

            return null;
        }

        /// <summary>
        /// Tests for API key disclosure
        /// </summary>
        private Vulnerability? TestForApiKeyDisclosure(EndpointInfo endpoint, HttpResponse response)
        {
            var apiKeyPatterns = new[]
            {
                @"sk-[a-zA-Z0-9]{20,}",  // OpenAI API keys
                @"AIza[0-9A-Za-z-_]{35}",  // Google API keys
                @"AKIA[0-9A-Z]{16}",      // AWS Access Keys
                @"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", // UUIDs that might be keys
                @"[a-zA-Z0-9]{32,}",      // Generic long keys
                @"Bearer [a-zA-Z0-9._-]+", // Bearer tokens
                @"api[_-]?key", "apikey", "access[_-]?key", "secret[_-]?key"
            };

            var foundKeys = new List<string>();
            foreach (var pattern in apiKeyPatterns)
            {
                var matches = Regex.Matches(response.Content, pattern, RegexOptions.IgnoreCase);
                foreach (Match match in matches)
                {
                    if (match.Value.Length > 10) // Only consider substantial keys
                    {
                        foundKeys.Add(match.Value);
                    }
                }
            }

            if (foundKeys.Any())
            {
                return new Vulnerability
                {
                    Type = VulnerabilityType.InformationDisclosure,
                    Severity = SeverityLevel.Critical,
                    Title = "API Key Disclosure",
                    Description = $"Endpoint {endpoint.Path} exposes API keys or tokens: {string.Join(", ", foundKeys.Take(3))}",
                    Endpoint = endpoint.Path,
                    Method = endpoint.Method,
                    Response = response.Content,
                    Evidence = $"API keys found: {string.Join(", ", foundKeys.Take(3))}",
                    Remediation = "Remove API keys and tokens from API responses. Use environment variables and secure key management.",
                    AttackMode = AttackMode.Stealth,
                    Confidence = 0.95,
                    FalsePositive = false,
                    Verified = true
                };
            }

            return null;
        }

        /// <summary>
        /// Tests for version information disclosure
        /// </summary>
        private Vulnerability? TestForVersionInformationDisclosure(EndpointInfo endpoint, HttpResponse response)
        {
            // High-risk server version indicators
            var serverVersionIndicators = new[]
            {
                "asp.net", "kestrel", "iis", "nginx", "apache", "php", "node.js", "express",
                "spring", "django", "flask", "rails", "laravel", "symfony", "dotnet",
                "microsoft", "windows", "linux", "ubuntu", "centos", "debian"
            };

            // Medium-risk framework version indicators
            var frameworkVersionIndicators = new[]
            {
                "entity framework", "ef core", "dapper", "nhibernate", "hibernate",
                "jpa", "doctrine", "sequelize", "mongoose", "prisma"
            };

            // Low-risk client-side version indicators (often false positives)
            var clientVersionIndicators = new[]
            {
                "bootstrap", "jquery", "react", "vue", "angular", "lodash", "moment",
                "chart.js", "d3", "leaflet", "font-awesome", "material-ui"
            };

            var foundServerVersions = new List<string>();
            var foundFrameworkVersions = new List<string>();
            var foundClientVersions = new List<string>();

            // Check for server version indicators
            foreach (var indicator in serverVersionIndicators)
            {
                if (response.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                {
                    if (IsServerVersionContext(response, indicator))
                    {
                        foundServerVersions.Add(indicator);
                    }
                }
            }

            // Check for framework version indicators
            foreach (var indicator in frameworkVersionIndicators)
            {
                if (response.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                {
                    if (IsFrameworkVersionContext(response, indicator))
                    {
                        foundFrameworkVersions.Add(indicator);
                    }
                }
            }

            // Check for client-side version indicators (lower priority)
            foreach (var indicator in clientVersionIndicators)
            {
                if (response.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                {
                    if (IsClientVersionContext(response, indicator))
                    {
                        foundClientVersions.Add(indicator);
                    }
                }
            }

            // Only report if we have server or framework versions
            if (foundServerVersions.Any() || foundFrameworkVersions.Any())
            {
                var allFound = foundServerVersions.Concat(foundFrameworkVersions).ToList();
                var confidence = CalculateVersionDisclosureConfidence(foundServerVersions, foundFrameworkVersions, foundClientVersions);
                var severity = foundServerVersions.Any() ? SeverityLevel.Medium : SeverityLevel.Low;

                return new Vulnerability
                {
                    Type = VulnerabilityType.InformationDisclosure,
                    Severity = severity,
                    Title = "Version Information Disclosure",
                    Description = $"Endpoint {endpoint.Path} exposes {GetVersionTypeDescription(foundServerVersions, foundFrameworkVersions)} version information: {string.Join(", ", allFound)}",
                    Endpoint = endpoint.Path,
                    Method = endpoint.Method,
                    Response = response.Content,
                    Evidence = $"Version info found: {string.Join(", ", allFound)}",
                    Remediation = "Remove version information from API responses. Use generic server identification.",
                    AttackMode = AttackMode.Stealth,
                    Confidence = 0.7,
                    FalsePositive = false,
                    Verified = true
                };
            }

            return null;
        }

        /// <summary>
        /// Tests for configuration disclosure
        /// </summary>
        private Vulnerability? TestForConfigurationDisclosure(EndpointInfo endpoint, HttpResponse response)
        {
            // High-confidence configuration indicators (actual config terms)
            var highConfidenceIndicators = new[]
            {
                "connectionstring", "connection string", "data source", "initial catalog",
                "integrated security", "trusted_connection", "appsettings", "web.config",
                "environment variables", "config file", "settings file"
            };

            // Medium-confidence indicators that need context validation
            var mediumConfidenceIndicators = new[]
            {
                "password", "pwd", "user", "username", "uid", "api key", "secret key",
                "access token", "bearer token", "jwt secret", "encryption key"
            };

            // Low-confidence indicators (often false positives)
            var lowConfidenceIndicators = new[]
            {
                "database", "server", "config", "environment", "settings"
            };

            var foundHighConfidence = new List<string>();
            var foundMediumConfidence = new List<string>();
            var foundLowConfidence = new List<string>();

            // Check high-confidence indicators
            foreach (var indicator in highConfidenceIndicators)
            {
                if (response.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                {
                    foundHighConfidence.Add(indicator);
                }
            }

            // Check medium-confidence indicators with context validation
            foreach (var indicator in mediumConfidenceIndicators)
            {
                if (response.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                {
                    if (IsLikelyConfigContext(response, indicator))
                    {
                        foundMediumConfidence.Add(indicator);
                    }
                }
            }

            // Check low-confidence indicators only if they appear in suspicious contexts
            foreach (var indicator in lowConfidenceIndicators)
            {
                if (response.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                {
                    if (IsLikelyConfigContext(response, indicator))
                    {
                        foundLowConfidence.Add(indicator);
                    }
                }
            }

            // Only report if we have high-confidence indicators or multiple medium-confidence ones
            if (foundHighConfidence.Any() || foundMediumConfidence.Count >= 2 || 
                (foundMediumConfidence.Any() && foundLowConfidence.Any()))
            {
                var allFound = foundHighConfidence.Concat(foundMediumConfidence).Concat(foundLowConfidence).ToList();
                var confidence = CalculateConfigDisclosureConfidence(foundHighConfidence, foundMediumConfidence, foundLowConfidence);
                var severity = confidence > 0.8 ? SeverityLevel.High : 
                              confidence > 0.6 ? SeverityLevel.Medium : SeverityLevel.Low;

                return new Vulnerability
                {
                    Type = VulnerabilityType.InformationDisclosure,
                    Severity = severity,
                    Title = "Configuration Information Disclosure",
                    Description = $"Endpoint {endpoint.Path} exposes configuration information: {string.Join(", ", allFound)}",
                    Endpoint = endpoint.Path,
                    Method = endpoint.Method,
                    Response = response.Content,
                    Evidence = $"Configuration indicators found: {string.Join(", ", allFound)}",
                    Remediation = "Remove configuration details from API responses. Use environment variables and secure configuration management.",
                    AttackMode = AttackMode.Stealth,
                    Confidence = confidence,
                    FalsePositive = confidence < 0.5,
                    Verified = confidence > 0.7
                };
            }

            return null;
        }

        /// <summary>
        /// Gets response from endpoint
        /// </summary>
        private async Task<HttpResponse> GetEndpointResponseAsync(string url, string method)
        {
            return method.ToUpper() switch
            {
                "GET" => await _httpClient.GetAsync(url),
                "POST" => await _httpClient.PostAsync(url, "{}"),
                "PUT" => await _httpClient.PutAsync(url, "{}"),
                "DELETE" => await _httpClient.DeleteAsync(url),
                _ => await _httpClient.GetAsync(url)
            };
        }

        /// <summary>
        /// Checks if endpoint is testable
        /// </summary>
        private bool IsTestableEndpoint(EndpointInfo endpoint)
        {
            // Skip static files and non-API endpoints for information disclosure testing
            var skipPaths = new[] { ".css", ".js", ".png", ".jpg", ".ico" };
            return !skipPaths.Any(path => endpoint.Path.Contains(path, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Validates if the context suggests server version information
        /// </summary>
        private bool IsServerVersionContext(HttpResponse response, string indicator)
        {
            var content = response.Content.ToLower();
            var indicatorLower = indicator.ToLower();
            
            var index = content.IndexOf(indicatorLower);
            if (index == -1) return false;
            
            var start = Math.Max(0, index - 100);
            var end = Math.Min(content.Length, index + indicatorLower.Length + 100);
            var context = content.Substring(start, end - start);
            
            // Check for server-specific context clues
            var serverContextClues = new[]
            {
                "server", "host", "runtime", "framework", "platform", "environment",
                "version", "build", "release", "patch", "error", "exception", "stack trace"
            };
            
            var serverClueCount = serverContextClues.Count(clue => context.Contains(clue));
            
            // If we find server context clues, it's likely server version info
            return serverClueCount >= 2;
        }

        /// <summary>
        /// Validates if the context suggests framework version information
        /// </summary>
        private bool IsFrameworkVersionContext(HttpResponse response, string indicator)
        {
            var content = response.Content.ToLower();
            var indicatorLower = indicator.ToLower();
            
            var index = content.IndexOf(indicatorLower);
            if (index == -1) return false;
            
            var start = Math.Max(0, index - 100);
            var end = Math.Min(content.Length, index + indicatorLower.Length + 100);
            var context = content.Substring(start, end - start);
            
            // Check for framework-specific context clues
            var frameworkContextClues = new[]
            {
                "framework", "library", "package", "dependency", "orm", "database",
                "entity", "model", "migration", "schema"
            };
            
            var frameworkClueCount = frameworkContextClues.Count(clue => context.Contains(clue));
            
            return frameworkClueCount >= 1;
        }

        /// <summary>
        /// Validates if the context suggests client-side version information
        /// </summary>
        private bool IsClientVersionContext(HttpResponse response, string indicator)
        {
            var content = response.Content.ToLower();
            var indicatorLower = indicator.ToLower();
            
            var index = content.IndexOf(indicatorLower);
            if (index == -1) return false;
            
            var start = Math.Max(0, index - 100);
            var end = Math.Min(content.Length, index + indicatorLower.Length + 100);
            var context = content.Substring(start, end - start);
            
            // Check for client-side context clues
            var clientContextClues = new[]
            {
                "bootstrap", "jquery", "javascript", "css", "html", "frontend", "ui",
                "button", "click", "form", "input", "div", "span", "class=", "id=",
                "cdn", "js", "css", "style", "script"
            };
            
            var clientClueCount = clientContextClues.Count(clue => context.Contains(clue));
            
            return clientClueCount >= 2;
        }

        /// <summary>
        /// Calculates confidence score for version disclosure
        /// </summary>
        private double CalculateVersionDisclosureConfidence(List<string> serverVersions, List<string> frameworkVersions, List<string> clientVersions)
        {
            var score = 0.0;
            
            // Server versions are high confidence
            score += serverVersions.Count * 0.8;
            
            // Framework versions are medium confidence
            score += frameworkVersions.Count * 0.6;
            
            // Client versions are low confidence (often false positives)
            score += clientVersions.Count * 0.2;
            
            return Math.Min(1.0, score);
        }

        /// <summary>
        /// Gets description of version type for vulnerability report
        /// </summary>
        private string GetVersionTypeDescription(List<string> serverVersions, List<string> frameworkVersions)
        {
            if (serverVersions.Any() && frameworkVersions.Any())
                return "server and framework";
            else if (serverVersions.Any())
                return "server";
            else if (frameworkVersions.Any())
                return "framework";
            else
                return "version";
        }

        /// <summary>
        /// Validates if the context suggests actual configuration information disclosure
        /// </summary>
        private bool IsLikelyConfigContext(HttpResponse response, string indicator)
        {
            var content = response.Content.ToLower();
            var indicatorLower = indicator.ToLower();
            
            var index = content.IndexOf(indicatorLower);
            if (index == -1) return false;
            
            var start = Math.Max(0, index - 100);
            var end = Math.Min(content.Length, index + indicatorLower.Length + 100);
            var context = content.Substring(start, end - start);
            
            // Check for configuration-specific context clues
            var configContextClues = new[]
            {
                "config", "settings", "environment", "variable", "file", "path",
                "connection", "database", "server", "api", "key", "secret", "token"
            };
            
            // Check for UI/frontend context clues that suggest false positive
            var uiContextClues = new[]
            {
                "bootstrap", "jquery", "javascript", "css", "html", "frontend", "ui",
                "button", "click", "form", "input", "div", "span", "class=", "id=",
                "avatar", "character", "ranking", "bending", "nation"
            };
            
            var configClueCount = configContextClues.Count(clue => context.Contains(clue));
            var uiClueCount = uiContextClues.Count(clue => context.Contains(clue));
            
            // If more config clues than UI clues, likely real config info
            return configClueCount > uiClueCount;
        }

        /// <summary>
        /// Calculates confidence score for configuration disclosure
        /// </summary>
        private double CalculateConfigDisclosureConfidence(List<string> highConfidence, List<string> mediumConfidence, List<string> lowConfidence)
        {
            var score = 0.0;
            
            // High confidence indicators are worth 0.9 points each
            score += highConfidence.Count * 0.9;
            
            // Medium confidence indicators are worth 0.6 points each
            score += mediumConfidence.Count * 0.6;
            
            // Low confidence indicators are worth 0.3 points each
            score += lowConfidence.Count * 0.3;
            
            return Math.Min(1.0, score);
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
}
