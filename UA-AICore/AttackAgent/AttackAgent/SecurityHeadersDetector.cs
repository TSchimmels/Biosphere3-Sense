using AttackAgent.Models;
using Serilog;

namespace AttackAgent
{
    /// <summary>
    /// Security headers detection and testing engine
    /// Tests for missing security headers and misconfigurations
    /// </summary>
    public class SecurityHeadersDetector
    {
        private readonly SecurityHttpClient _httpClient;
        private readonly ILogger _logger;

        public SecurityHeadersDetector(string baseUrl = "")
        {
            _httpClient = new SecurityHttpClient(baseUrl);
            _logger = Log.ForContext<SecurityHeadersDetector>();
        }

        /// <summary>
        /// Tests all discovered endpoints for security headers vulnerabilities
        /// </summary>
        public async Task<List<Vulnerability>> TestForSecurityHeadersAsync(ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            _logger.Information("🔍 Starting security headers testing...");
            _logger.Information("Testing {EndpointCount} endpoints for security headers", 
                profile.DiscoveredEndpoints.Count);

            foreach (var endpoint in profile.DiscoveredEndpoints)
            {
                if (!IsTestableEndpoint(endpoint))
                    continue;

                _logger.Debug("Testing endpoint: {Method} {Path}", endpoint.Method, endpoint.Path);

                var endpointVulns = await TestEndpointForSecurityHeadersAsync(endpoint, profile.BaseUrl);
                vulnerabilities.AddRange(endpointVulns);
            }

            _logger.Information("Security headers testing completed. Found {VulnCount} vulnerabilities", vulnerabilities.Count);
            return vulnerabilities;
        }

        /// <summary>
        /// Tests a specific endpoint for security headers vulnerabilities
        /// </summary>
        private async Task<List<Vulnerability>> TestEndpointForSecurityHeadersAsync(EndpointInfo endpoint, string baseUrl)
        {
            var vulnerabilities = new List<Vulnerability>();
            var url = baseUrl.TrimEnd('/') + endpoint.Path;

            try
            {
                // Get response from endpoint
                var response = await GetEndpointResponseAsync(url, endpoint.Method);
                
                if (response.Success)
                {
                    // Test for missing security headers
                    var missingHeaders = TestForMissingSecurityHeaders(endpoint, response);
                    vulnerabilities.AddRange(missingHeaders);

                    // Test for HTTPS enforcement
                    var httpsVuln = TestForHttpsEnforcement(endpoint, response, url);
                    if (httpsVuln != null) vulnerabilities.Add(httpsVuln);

                    // Test for CORS misconfiguration
                    var corsVuln = TestForCorsMisconfiguration(endpoint, response);
                    if (corsVuln != null) vulnerabilities.Add(corsVuln);
                }
            }
            catch (Exception ex)
            {
                _logger.Debug("Error testing security headers for {Endpoint}: {Error}", endpoint.Path, ex.Message);
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Tests for missing security headers
        /// </summary>
        private List<Vulnerability> TestForMissingSecurityHeaders(EndpointInfo endpoint, HttpResponse response)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            var requiredHeaders = new Dictionary<string, SecurityHeaderInfo>
            {
                ["X-Content-Type-Options"] = new SecurityHeaderInfo
                {
                    Severity = SeverityLevel.Medium,
                    Description = "Prevents MIME type sniffing attacks",
                    RecommendedValue = "nosniff"
                },
                ["X-Frame-Options"] = new SecurityHeaderInfo
                {
                    Severity = SeverityLevel.Medium,
                    Description = "Prevents clickjacking attacks",
                    RecommendedValue = "DENY"
                },
                ["X-XSS-Protection"] = new SecurityHeaderInfo
                {
                    Severity = SeverityLevel.Medium,
                    Description = "Enables XSS filtering in browsers",
                    RecommendedValue = "1; mode=block"
                },
                ["Strict-Transport-Security"] = new SecurityHeaderInfo
                {
                    Severity = SeverityLevel.High,
                    Description = "Enforces HTTPS connections",
                    RecommendedValue = "max-age=31536000; includeSubDomains"
                },
                ["Content-Security-Policy"] = new SecurityHeaderInfo
                {
                    Severity = SeverityLevel.High,
                    Description = "Prevents XSS and code injection attacks",
                    RecommendedValue = "default-src 'self'"
                },
                ["Referrer-Policy"] = new SecurityHeaderInfo
                {
                    Severity = SeverityLevel.Low,
                    Description = "Controls referrer information",
                    RecommendedValue = "strict-origin-when-cross-origin"
                },
                ["Permissions-Policy"] = new SecurityHeaderInfo
                {
                    Severity = SeverityLevel.Low,
                    Description = "Controls browser features and APIs",
                    RecommendedValue = "geolocation=(), microphone=(), camera=()"
                }
            };

            foreach (var header in requiredHeaders)
            {
                if (!response.HasHeader(header.Key))
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Type = VulnerabilityType.MissingSecurityHeaders,
                        Severity = header.Value.Severity,
                        Title = $"Missing Security Header: {header.Key}",
                        Description = $"Endpoint {endpoint.Path} is missing the {header.Key} security header. {header.Value.Description}",
                        Endpoint = endpoint.Path,
                        Method = endpoint.Method,
                        Evidence = $"Missing security header: {header.Key}",
                        Remediation = $"Add the {header.Key} header with value: {header.Value.RecommendedValue}",
                        AttackMode = AttackMode.Stealth,
                        Confidence = 0.9,
                        FalsePositive = false,
                        Verified = true
                    });
                }
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Tests for HTTPS enforcement
        /// </summary>
        private Vulnerability? TestForHttpsEnforcement(EndpointInfo endpoint, HttpResponse response, string url)
        {
            if (url.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            {
                return new Vulnerability
                {
                    Type = VulnerabilityType.WeakCryptography,
                    Severity = SeverityLevel.High,
                    Title = "Missing HTTPS Enforcement",
                    Description = $"Endpoint {endpoint.Path} is accessible over HTTP, which allows for man-in-the-middle attacks and data interception.",
                    Endpoint = endpoint.Path,
                    Method = endpoint.Method,
                    Evidence = "Application accessible over HTTP without HTTPS enforcement",
                    Remediation = "Implement HTTPS enforcement using Strict-Transport-Security header and redirect HTTP to HTTPS.",
                    AttackMode = AttackMode.Stealth,
                    Confidence = 0.95,
                    FalsePositive = false,
                    Verified = true
                };
            }

            return null;
        }

        /// <summary>
        /// Tests for CORS misconfiguration
        /// </summary>
        private Vulnerability? TestForCorsMisconfiguration(EndpointInfo endpoint, HttpResponse response)
        {
            var corsHeader = response.GetHeader("Access-Control-Allow-Origin");
            
            if (!string.IsNullOrEmpty(corsHeader))
            {
                if (corsHeader == "*")
                {
                    return new Vulnerability
                    {
                        Type = VulnerabilityType.CorsMisconfiguration,
                        Severity = SeverityLevel.High,
                        Title = "CORS Misconfiguration - Wildcard Origin",
                        Description = $"Endpoint {endpoint.Path} allows requests from any origin (*), which can lead to CSRF attacks.",
                        Endpoint = endpoint.Path,
                        Method = endpoint.Method,
                        Evidence = $"CORS header set to wildcard: {corsHeader}",
                        Remediation = "Restrict CORS to specific trusted origins instead of using wildcard (*).",
                        AttackMode = AttackMode.Stealth,
                        Confidence = 0.9,
                        FalsePositive = false,
                        Verified = true
                    };
                }
            }
            else
            {
                // Check if this is an API endpoint that might need CORS
                if (endpoint.Path.StartsWith("/api/", StringComparison.OrdinalIgnoreCase))
                {
                    return new Vulnerability
                    {
                        Type = VulnerabilityType.CorsMisconfiguration,
                        Severity = SeverityLevel.Medium,
                        Title = "Missing CORS Configuration",
                        Description = $"API endpoint {endpoint.Path} may need CORS configuration for cross-origin requests.",
                        Endpoint = endpoint.Path,
                        Method = endpoint.Method,
                        Evidence = "No CORS headers found on API endpoint",
                        Remediation = "Configure appropriate CORS headers for API endpoints that need cross-origin access.",
                        AttackMode = AttackMode.Stealth,
                        Confidence = 0.7,
                        FalsePositive = false,
                        Verified = true
                    };
                }
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
            // Test all endpoints for security headers
            return true;
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }

    /// <summary>
    /// Security header information
    /// </summary>
    public class SecurityHeaderInfo
    {
        public SeverityLevel Severity { get; set; }
        public string Description { get; set; } = string.Empty;
        public string RecommendedValue { get; set; } = string.Empty;
    }
}


