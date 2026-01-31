using AttackAgent.Models;
using Serilog;
using System.Text.RegularExpressions;

namespace AttackAgent
{
    /// <summary>
    /// Fixed Authentication bypass testing engine with proper public API detection
    /// Only tests authentication bypasses on endpoints that actually require authentication
    /// </summary>
    public class FixedAuthBypassEngine
    {
        private readonly SecurityHttpClient _httpClient;
        private readonly ILogger _logger;
        private readonly List<AuthBypassPayload> _payloads;

        public FixedAuthBypassEngine(string baseUrl = "")
        {
            _httpClient = new SecurityHttpClient(baseUrl);
            _logger = Log.ForContext<FixedAuthBypassEngine>();
            _payloads = InitializeAuthBypassPayloads();
        }

        /// <summary>
        /// Tests all discovered endpoints for authentication bypass vulnerabilities
        /// </summary>
        public async Task<List<Vulnerability>> TestForAuthBypassAsync(ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            _logger.Information("🔍 Starting fixed authentication bypass testing...");
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

            _logger.Information("Fixed authentication bypass testing completed. Found {VulnCount} vulnerabilities", vulnerabilities.Count);
            return vulnerabilities;
        }

        /// <summary>
        /// Tests a specific endpoint for authentication bypass vulnerabilities
        /// </summary>
        private async Task<List<Vulnerability>> TestEndpointForAuthBypassAsync(EndpointInfo endpoint, string baseUrl)
        {
            var vulnerabilities = new List<Vulnerability>();
            var url = baseUrl.TrimEnd('/') + endpoint.Path;

            // First, determine if this endpoint should require authentication
            var authRequirement = await DetermineAuthenticationRequirementAsync(url, endpoint);
            
            if (authRequirement.Requirement == AuthenticationRequirement.Public)
            {
                // This is a public endpoint - no authentication required
                _logger.Debug("Endpoint {Path} is public - skipping authentication bypass tests", endpoint.Path);
                return vulnerabilities; // No vulnerabilities for public endpoints
            }
            else if (authRequirement.Requirement == AuthenticationRequirement.Protected)
            {
                // This endpoint should be protected - test for bypasses
                _logger.Debug("Endpoint {Path} should be protected - testing for authentication bypasses", endpoint.Path);
                
                var bypassVulns = await TestForActualBypassesAsync(url, endpoint);
                vulnerabilities.AddRange(bypassVulns);
            }
            else if (authRequirement.Requirement == AuthenticationRequirement.Missing)
            {
                // This endpoint should be protected but has no authentication
                var noAuthVuln = CreateMissingAuthenticationVulnerability(endpoint, authRequirement);
                vulnerabilities.Add(noAuthVuln);
                _logger.Warning("🚨 Missing authentication on protected endpoint: {Method} {Path}", endpoint.Method, endpoint.Path);
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Determines if an endpoint should require authentication based on context
        /// </summary>
        private async Task<AuthenticationRequirementAnalysis> DetermineAuthenticationRequirementAsync(string url, EndpointInfo endpoint)
        {
            var analysis = new AuthenticationRequirementAnalysis
            {
                Requirement = AuthenticationRequirement.Public,
                Confidence = 0.0,
                Evidence = ""
            };

            try
            {
                // Get baseline response
                var baselineResponse = await GetBaselineResponseAsync(url, endpoint.Method);
                
                // Check for explicit authentication requirements
                if (baselineResponse.StatusCode == System.Net.HttpStatusCode.Unauthorized || 
                    baselineResponse.StatusCode == System.Net.HttpStatusCode.Forbidden)
                {
                    analysis.Requirement = AuthenticationRequirement.Protected;
                    analysis.Confidence = 1.0;
                    analysis.Evidence = $"Endpoint returns {baselineResponse.StatusCode}";
                    return analysis;
                }

                // Check for authentication headers
                if (baselineResponse.HasHeader("WWW-Authenticate") || 
                    baselineResponse.HasHeader("X-Auth-Required"))
                {
                    analysis.Requirement = AuthenticationRequirement.Protected;
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
                    analysis.Requirement = AuthenticationRequirement.Protected;
                    analysis.Confidence = Math.Min(0.8, authRequiredCount * 0.2);
                    analysis.Evidence = $"Found {authRequiredCount} authentication indicators";
                    return analysis;
                }

                // Determine if this endpoint should be protected based on context
                var shouldBeProtected = ShouldEndpointBeProtected(endpoint, url, baselineResponse);
                
                if (shouldBeProtected && baselineResponse.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    analysis.Requirement = AuthenticationRequirement.Missing;
                    analysis.Confidence = 0.7;
                    analysis.Evidence = "Sensitive endpoint accessible without authentication";
                    return analysis;
                }

                // If we get here, likely a public endpoint
                analysis.Requirement = AuthenticationRequirement.Public;
                analysis.Confidence = 0.8;
                analysis.Evidence = "Public endpoint - no authentication required";
            }
            catch (Exception ex)
            {
                _logger.Debug("Error analyzing authentication requirement: {Error}", ex.Message);
                analysis.Requirement = AuthenticationRequirement.Public;
                analysis.Confidence = 0.0;
                analysis.Evidence = "Error during analysis";
            }

            return analysis;
        }

        /// <summary>
        /// Determines if an endpoint should be protected based on its context
        /// </summary>
        private bool ShouldEndpointBeProtected(EndpointInfo endpoint, string url, HttpResponse response)
        {
            // Check for sensitive path patterns
            var sensitivePaths = new[]
            {
                "/admin", "/api/admin", "/dashboard", "/settings", "/profile",
                "/api/users", "/api/auth", "/api/chatbot", "/api/chat", "/api/history"
            };

            var isSensitivePath = sensitivePaths.Any(path => 
                endpoint.Path.Contains(path, StringComparison.OrdinalIgnoreCase));

            // Check for sensitive HTTP methods
            var sensitiveMethods = new[] { "POST", "PUT", "DELETE", "PATCH" };
            var isSensitiveMethod = sensitiveMethods.Contains(endpoint.Method.ToUpper());

            // Check for sensitive content in response
            var sensitiveContent = new[]
            {
                "user", "admin", "password", "token", "session", "private",
                "confidential", "secret", "internal", "management"
            };

            var hasSensitiveContent = sensitiveContent.Any(content =>
                response.Contains(content, StringComparison.OrdinalIgnoreCase));

            // Check for database operations
            var hasDatabaseContent = response.Contains("database") || 
                                   response.Contains("sql") || 
                                   response.Contains("connection");

            // Determine if endpoint should be protected
            if (isSensitivePath)
            {
                _logger.Debug("Endpoint {Path} is on sensitive path", endpoint.Path);
                return true;
            }

            if (isSensitiveMethod && (hasSensitiveContent || hasDatabaseContent))
            {
                _logger.Debug("Endpoint {Path} uses sensitive method with sensitive content", endpoint.Path);
                return true;
            }

            // For GET endpoints, only protect if they have very sensitive content
            if (endpoint.Method.ToUpper() == "GET" && hasSensitiveContent && hasDatabaseContent)
            {
                _logger.Debug("Endpoint {Path} is GET with sensitive database content", endpoint.Path);
                return true;
            }

            // Default: public endpoint
            return false;
        }

        /// <summary>
        /// Tests for actual authentication bypasses on protected endpoints
        /// </summary>
        private async Task<List<Vulnerability>> TestForActualBypassesAsync(string url, EndpointInfo endpoint)
        {
            var vulnerabilities = new List<Vulnerability>();

            // Only test bypasses if we know authentication is required
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
                Remediation = "🔒 RECOMMENDED FIX: Implement comprehensive authentication and authorization controls.\n\n" +
                             "❌ VULNERABLE CODE:\n" +
                             "// Weak authentication check\n" +
                             "if (username == \"admin\" && password == \"password\")\n" +
                             "    return Ok();\n" +
                             "// SQL injection in authentication\n" +
                             "string sql = \"SELECT * FROM Users WHERE Username = '\" + username + \"' AND Password = '\" + password + \"'\";\n" +
                             "// Missing authorization checks\n" +
                             "[HttpGet(\"admin/users\")]\n" +
                             "public IActionResult GetUsers() { return Ok(); }\n\n" +
                             "✅ SECURE CODE:\n" +
                             "// Strong authentication with parameterized queries\n" +
                             "string sql = \"SELECT Id, Username, PasswordHash FROM Users WHERE Username = @Username\";\n" +
                             "command.Parameters.AddWithValue(\"@Username\", username);\n" +
                             "var user = await command.ExecuteReaderAsync();\n" +
                             "if (user.Read() && BCrypt.Verify(password, user[\"PasswordHash\"]))\n" +
                             "    return Ok();\n" +
                             "// Proper authorization with attributes\n" +
                             "[Authorize(Roles = \"Admin\")]\n" +
                             "[HttpGet(\"admin/users\")]\n" +
                             "public IActionResult GetUsers() { return Ok(); }\n\n" +
                             "📋 ADDITIONAL MEASURES:\n" +
                             "• Use strong password hashing (BCrypt, Argon2)\n" +
                             "• Implement multi-factor authentication (MFA)\n" +
                             "• Use parameterized queries for all database operations\n" +
                             "• Implement proper session management with secure cookies\n" +
                             "• Use JWT tokens with proper validation and expiration\n" +
                             "• Implement rate limiting on authentication endpoints\n" +
                             "• Validate and sanitize all user input\n" +
                             "• Use HTTPS for all authentication communications\n" +
                             "• Implement proper logout functionality\n" +
                             "• Regular security audits and penetration testing",
                AttackMode = AttackMode.Aggressive,
                Confidence = result.Confidence,
                FalsePositive = false,
                Verified = true
            };
        }

        /// <summary>
        /// Creates missing authentication vulnerability
        /// </summary>
        private Vulnerability CreateMissingAuthenticationVulnerability(EndpointInfo endpoint, AuthenticationRequirementAnalysis analysis)
        {
            return new Vulnerability
            {
                Type = VulnerabilityType.WeakAuthentication,
                Severity = DetermineMissingAuthSeverity(endpoint),
                Title = "Missing Authentication on Protected Endpoint",
                Description = $"Endpoint {endpoint.Path} should be protected but has no authentication mechanism.",
                Endpoint = endpoint.Path,
                Method = endpoint.Method,
                Evidence = analysis.Evidence,
                Remediation = "🔒 RECOMMENDED FIX: Implement proper authentication and authorization for sensitive endpoints.\n\n" +
                             "❌ VULNERABLE CODE:\n" +
                             "// Missing authentication on sensitive endpoint\n" +
                             "[HttpGet(\"admin/users\")]\n" +
                             "public IActionResult GetUsers() { return Ok(); }\n" +
                             "// Missing authorization checks\n" +
                             "[HttpGet(\"api/sensitive-data\")]\n" +
                             "public IActionResult GetSensitiveData() { return Ok(); }\n\n" +
                             "✅ SECURE CODE:\n" +
                             "// Proper authentication and authorization\n" +
                             "[Authorize]\n" +
                             "[HttpGet(\"admin/users\")]\n" +
                             "public IActionResult GetUsers() { return Ok(); }\n" +
                             "// Role-based authorization\n" +
                             "[Authorize(Roles = \"Admin\")]\n" +
                             "[HttpGet(\"api/sensitive-data\")]\n" +
                             "public IActionResult GetSensitiveData() { return Ok(); }\n" +
                             "// Policy-based authorization\n" +
                             "[Authorize(Policy = \"RequireAdminRole\")]\n" +
                             "[HttpGet(\"api/admin-only\")]\n" +
                             "public IActionResult AdminOnly() { return Ok(); }\n\n" +
                             "📋 ADDITIONAL MEASURES:\n" +
                             "• Implement authentication middleware\n" +
                             "• Use role-based access control (RBAC)\n" +
                             "• Implement policy-based authorization\n" +
                             "• Secure session management with HttpOnly cookies\n" +
                             "• Use HTTPS for all sensitive communications\n" +
                             "• Implement proper logout functionality\n" +
                             "• Regular security audits and access reviews\n" +
                             "• Monitor and log all authentication attempts\n" +
                             "• Implement account lockout policies\n" +
                             "• Use strong password policies",
                AttackMode = AttackMode.Stealth,
                Confidence = analysis.Confidence,
                FalsePositive = false,
                Verified = true
            };
        }

        /// <summary>
        /// Determines severity for missing authentication vulnerability
        /// </summary>
        private SeverityLevel DetermineMissingAuthSeverity(EndpointInfo endpoint)
        {
            var criticalPaths = new[] { "/admin", "/api/admin", "/dashboard", "/settings", "/profile" };
            var highPaths = new[] { "/api/users", "/api/auth", "/api/chatbot" };
            
            if (criticalPaths.Any(path => endpoint.Path.Contains(path, StringComparison.OrdinalIgnoreCase)))
                return SeverityLevel.Critical;
            else if (highPaths.Any(path => endpoint.Path.Contains(path, StringComparison.OrdinalIgnoreCase)))
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
    /// Authentication requirement analysis result
    /// </summary>
    public class AuthenticationRequirementAnalysis
    {
        public AuthenticationRequirement Requirement { get; set; }
        public double Confidence { get; set; }
        public string Evidence { get; set; } = string.Empty;
    }

    /// <summary>
    /// Authentication requirement types
    /// </summary>
    public enum AuthenticationRequirement
    {
        Public,     // Endpoint is public by design
        Protected,  // Endpoint requires authentication
        Missing     // Endpoint should be protected but has no auth
    }
}


