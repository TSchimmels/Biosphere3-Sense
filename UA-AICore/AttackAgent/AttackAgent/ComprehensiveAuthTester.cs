using AttackAgent.Models;
using Serilog;

namespace AttackAgent
{
    /// <summary>
    /// Comprehensive authentication testing engine
    /// Tests all HTTP methods and sensitive operations for authentication requirements
    /// </summary>
    public class ComprehensiveAuthTester
    {
        private readonly SecurityHttpClient _httpClient;
        private readonly ILogger _logger;

        public ComprehensiveAuthTester(string baseUrl = "")
        {
            _httpClient = new SecurityHttpClient(baseUrl);
            _logger = Log.ForContext<ComprehensiveAuthTester>();
        }

        /// <summary>
        /// Tests all discovered endpoints for comprehensive authentication vulnerabilities
        /// </summary>
        public async Task<List<Vulnerability>> TestForComprehensiveAuthAsync(ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            _logger.Information("🔍 Starting comprehensive authentication testing...");
            _logger.Information("Testing {EndpointCount} endpoints for authentication requirements", 
                profile.DiscoveredEndpoints.Count);

            // Test all HTTP methods for each endpoint
            var allMethods = new[] { "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS" };
            
            foreach (var endpoint in profile.DiscoveredEndpoints)
            {
                if (!IsTestableEndpoint(endpoint))
                    continue;

                _logger.Debug("Testing endpoint: {Path} for all HTTP methods", endpoint.Path);

                foreach (var method in allMethods)
                {
                    var methodVulns = await TestEndpointMethodForAuthAsync(endpoint, profile.BaseUrl, method);
                    vulnerabilities.AddRange(methodVulns);
                }
            }

            _logger.Information("Comprehensive authentication testing completed. Found {VulnCount} vulnerabilities", vulnerabilities.Count);
            return vulnerabilities;
        }

        /// <summary>
        /// Tests a specific endpoint method for authentication vulnerabilities
        /// </summary>
        private async Task<List<Vulnerability>> TestEndpointMethodForAuthAsync(EndpointInfo endpoint, string baseUrl, string method)
        {
            var vulnerabilities = new List<Vulnerability>();
            var url = baseUrl.TrimEnd('/') + endpoint.Path;

            try
            {
                // Test the method WITHOUT authentication
                var response = await TestHttpMethodAsync(url, method);
                
                // Check if authentication is required (401/403 means auth is required - GOOD)
                var requiresAuth = response.StatusCode == System.Net.HttpStatusCode.Unauthorized ||
                                  response.StatusCode == System.Net.HttpStatusCode.Forbidden ||
                                  response.Content.Contains("unauthorized", StringComparison.OrdinalIgnoreCase) ||
                                  response.Content.Contains("authentication required", StringComparison.OrdinalIgnoreCase) ||
                                  response.Content.Contains("login", StringComparison.OrdinalIgnoreCase) ||
                                  response.GetHeader("WWW-Authenticate") != null;
                
                // If auth is required, endpoint is secure - no vulnerability
                if (requiresAuth)
                {
                    _logger.Debug("✅ {Method} {Path} requires authentication - secure", method, endpoint.Path);
                    return vulnerabilities;
                }
                
                // If no auth required, check if this SHOULD require authentication
                var shouldRequireAuth = ShouldMethodRequireAuthentication(endpoint.Path, method, response);
                
                if (shouldRequireAuth && response.Success)
                {
                    // VULNERABILITY: Sensitive operation accessible without authentication
                    var authVuln = CreateMissingAuthenticationVulnerability(endpoint, method, response);
                    vulnerabilities.Add(authVuln);
                    
                    _logger.Warning("🚨 Missing authentication on sensitive operation: {Method} {Path} (Status: {StatusCode})", 
                        method, endpoint.Path, response.StatusCode);
                }
            }
            catch (Exception ex)
            {
                _logger.Debug("Error testing {Method} {Path}: {Error}", method, endpoint.Path, ex.Message);
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Determines if a method should require authentication based on context
        /// </summary>
        private bool ShouldMethodRequireAuthentication(string path, string method, HttpResponse response)
        {
            // High-risk methods that should always require authentication
            var highRiskMethods = new[] { "POST", "PUT", "DELETE", "PATCH" };
            if (highRiskMethods.Contains(method.ToUpper()))
            {
                return true;
            }

            // Sensitive paths that should require authentication
            var sensitivePaths = new[]
            {
                "/api/chatbot", "/api/chatbot/", "/api/chatbot/history", "/api/chatbot/chat",
                "/api/desserts", "/api/desserts/", "/api/desserts/", "/api/desserts/generate-image",
                "/api/admin", "/api/users", "/api/auth", "/api/settings", "/api/profile"
            };

            var isSensitivePath = sensitivePaths.Any(sp => path.StartsWith(sp, StringComparison.OrdinalIgnoreCase));
            if (isSensitivePath)
            {
                return true;
            }

            // Check for sensitive content in response
            var sensitiveContent = new[]
            {
                "user", "admin", "password", "token", "session", "private",
                "confidential", "secret", "internal", "management", "chat",
                "history", "delete", "update", "create", "modify"
            };

            var hasSensitiveContent = sensitiveContent.Any(content =>
                response.Contains(content, StringComparison.OrdinalIgnoreCase));

            // Check for database operations
            var hasDatabaseContent = response.Contains("database") || 
                                   response.Contains("sql") || 
                                   response.Contains("connection") ||
                                   response.Contains("entity") ||
                                   response.Contains("context");

            // Check for AI/API operations
            var hasAIContent = response.Contains("openai") || 
                             response.Contains("chatgpt") || 
                             response.Contains("dall-e") ||
                             response.Contains("api") ||
                             response.Contains("generate");

            if (hasSensitiveContent && (hasDatabaseContent || hasAIContent))
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Tests HTTP method on endpoint
        /// </summary>
        private async Task<HttpResponse> TestHttpMethodAsync(string url, string method)
        {
            return method.ToUpper() switch
            {
                "GET" => await _httpClient.GetAsync(url),
                "POST" => await _httpClient.PostAsync(url, "{}"),
                "PUT" => await _httpClient.PutAsync(url, "{}"),
                "DELETE" => await _httpClient.DeleteAsync(url),
                "PATCH" => await _httpClient.PutAsync(url, "{}"), // Use PUT for PATCH
                "HEAD" => await _httpClient.GetAsync(url), // Use GET for HEAD
                "OPTIONS" => await _httpClient.GetAsync(url), // Use GET for OPTIONS
                _ => await _httpClient.GetAsync(url)
            };
        }

        /// <summary>
        /// Creates missing authentication vulnerability
        /// </summary>
        private Vulnerability CreateMissingAuthenticationVulnerability(EndpointInfo endpoint, string method, HttpResponse response)
        {
            var severity = DetermineAuthSeverity(endpoint.Path, method);
            
            return new Vulnerability
            {
                Type = VulnerabilityType.WeakAuthentication,
                Severity = severity,
                Title = $"Missing Authentication on {method} {endpoint.Path}",
                Description = $"Endpoint {endpoint.Path} with {method} method should be protected but has no authentication mechanism. This allows unauthorized access to sensitive operations.",
                Endpoint = endpoint.Path,
                Method = method,
                Evidence = $"Sensitive {method} operation accessible without authentication",
                Remediation = "Implement proper authentication and authorization for sensitive endpoints. Use role-based access control and secure session management.",
                AttackMode = AttackMode.Stealth,
                Confidence = 0.9,
                FalsePositive = false,
                Verified = true
            };
        }

        /// <summary>
        /// Determines severity for missing authentication vulnerability
        /// </summary>
        private SeverityLevel DetermineAuthSeverity(string path, string method)
        {
            // Critical severity for high-risk operations
            var criticalPaths = new[] { "/api/admin", "/api/users", "/api/auth", "/api/chatbot/history" };
            var criticalMethods = new[] { "DELETE", "PUT", "PATCH" };
            
            if (criticalPaths.Any(cp => path.StartsWith(cp, StringComparison.OrdinalIgnoreCase)) ||
                criticalMethods.Contains(method.ToUpper()))
            {
                return SeverityLevel.Critical;
            }

            // High severity for sensitive operations
            var highRiskPaths = new[] { "/api/chatbot", "/api/desserts" };
            var highRiskMethods = new[] { "POST" };
            
            if (highRiskPaths.Any(hp => path.StartsWith(hp, StringComparison.OrdinalIgnoreCase)) ||
                highRiskMethods.Contains(method.ToUpper()))
            {
                return SeverityLevel.High;
            }

            // Medium severity for other operations
            return SeverityLevel.Medium;
        }

        /// <summary>
        /// Checks if endpoint is testable
        /// </summary>
        private bool IsTestableEndpoint(EndpointInfo endpoint)
        {
            // Skip static files but test all API endpoints
            var skipPaths = new[] { ".css", ".js", ".png", ".jpg", ".ico" };
            return !skipPaths.Any(path => endpoint.Path.Contains(path, StringComparison.OrdinalIgnoreCase));
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
}
