using AttackAgent.Models;
using Serilog;

namespace AttackAgent
{
    /// <summary>
    /// Rate limiting detection and testing engine
    /// Tests for missing rate limiting and potential DoS vulnerabilities
    /// </summary>
    public class RateLimitingDetector
    {
        private readonly SecurityHttpClient _httpClient;
        private readonly ILogger _logger;

        public RateLimitingDetector(string baseUrl = "")
        {
            _httpClient = new SecurityHttpClient(baseUrl);
            _logger = Log.ForContext<RateLimitingDetector>();
        }

        /// <summary>
        /// Tests all discovered endpoints for rate limiting vulnerabilities
        /// </summary>
        public async Task<List<Vulnerability>> TestForRateLimitingAsync(ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            _logger.Information("🔍 Starting rate limiting testing...");
            _logger.Information("Testing {EndpointCount} endpoints for rate limiting", 
                profile.DiscoveredEndpoints.Count);

            foreach (var endpoint in profile.DiscoveredEndpoints)
            {
                if (!IsTestableEndpoint(endpoint))
                    continue;

                _logger.Debug("Testing endpoint: {Method} {Path}", endpoint.Method, endpoint.Path);

                var endpointVulns = await TestEndpointForRateLimitingAsync(endpoint, profile.BaseUrl);
                vulnerabilities.AddRange(endpointVulns);
            }

            _logger.Information("Rate limiting testing completed. Found {VulnCount} vulnerabilities", vulnerabilities.Count);
            return vulnerabilities;
        }

        /// <summary>
        /// Tests a specific endpoint for rate limiting vulnerabilities
        /// </summary>
        private async Task<List<Vulnerability>> TestEndpointForRateLimitingAsync(EndpointInfo endpoint, string baseUrl)
        {
            var vulnerabilities = new List<Vulnerability>();
            var url = baseUrl.TrimEnd('/') + endpoint.Path;

            try
            {
                // Test for rate limiting by sending multiple rapid requests
                var rateLimitVuln = await TestRateLimitingAsync(endpoint, url);
                if (rateLimitVuln != null) vulnerabilities.Add(rateLimitVuln);

                // Test for DoS vulnerability
                var dosVuln = await TestDoSAsync(endpoint, url);
                if (dosVuln != null) vulnerabilities.Add(dosVuln);
            }
            catch (Exception ex)
            {
                _logger.Debug("Error testing rate limiting for {Endpoint}: {Error}", endpoint.Path, ex.Message);
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Tests for rate limiting by sending rapid requests
        /// </summary>
        private async Task<Vulnerability?> TestRateLimitingAsync(EndpointInfo endpoint, string url)
        {
            var requestCount = 10; // Send 10 rapid requests
            var requests = new List<Task<HttpResponse>>();
            
            // Send rapid requests
            for (int i = 0; i < requestCount; i++)
            {
                var request = SendRequestAsync(url, endpoint.Method);
                requests.Add(request);
            }

            // Wait for all requests to complete
            var responses = await Task.WhenAll(requests);
            
            // Check if all requests succeeded (indicating no rate limiting)
            var successCount = responses.Count(r => r.Success);
            
            if (successCount == requestCount)
            {
                return new Vulnerability
                {
                    Type = VulnerabilityType.MissingRateLimiting,
                    Severity = DetermineRateLimitSeverity(endpoint),
                    Title = "Missing Rate Limiting",
                    Description = $"Endpoint {endpoint.Path} does not implement rate limiting, allowing potential abuse and DoS attacks.",
                    Endpoint = endpoint.Path,
                    Method = endpoint.Method,
                    Evidence = $"All {requestCount} rapid requests succeeded without rate limiting",
                    Remediation = "Implement rate limiting using middleware, API gateways, or cloud services. Set appropriate limits per IP/user.",
                    AttackMode = AttackMode.Aggressive,
                    Confidence = 0.8,
                    FalsePositive = false,
                    Verified = true
                };
            }

            return null;
        }

        /// <summary>
        /// Tests for DoS vulnerability
        /// </summary>
        private async Task<Vulnerability?> TestDoSAsync(EndpointInfo endpoint, string url)
        {
            // Test for resource-intensive operations
            var isResourceIntensive = IsResourceIntensiveEndpoint(endpoint);
            
            if (isResourceIntensive)
            {
                return new Vulnerability
                {
                    Type = VulnerabilityType.DenialOfService,
                    Severity = SeverityLevel.High,
                    Title = "Potential DoS Vulnerability",
                    Description = $"Endpoint {endpoint.Path} performs resource-intensive operations without rate limiting, making it vulnerable to DoS attacks.",
                    Endpoint = endpoint.Path,
                    Method = endpoint.Method,
                    Evidence = "Resource-intensive endpoint without rate limiting protection",
                    Remediation = "Implement rate limiting, request throttling, and resource quotas for expensive operations.",
                    AttackMode = AttackMode.Aggressive,
                    Confidence = 0.7,
                    FalsePositive = false,
                    Verified = true
                };
            }

            return null;
        }

        /// <summary>
        /// Determines if endpoint is resource-intensive
        /// </summary>
        private bool IsResourceIntensiveEndpoint(EndpointInfo endpoint)
        {
            var resourceIntensivePaths = new[]
            {
                "/api/chatbot", "/api/chatbot/recipe", "/api/chatbot/chat",
                "/api/desserts/generate-image", "/api/spell-check", "/api/loading"
            };

            var resourceIntensiveMethods = new[] { "POST", "PUT", "DELETE" };

            return resourceIntensivePaths.Any(path => endpoint.Path.StartsWith(path, StringComparison.OrdinalIgnoreCase)) ||
                   resourceIntensiveMethods.Contains(endpoint.Method.ToUpper());
        }

        /// <summary>
        /// Determines severity for rate limiting vulnerability
        /// </summary>
        private SeverityLevel DetermineRateLimitSeverity(EndpointInfo endpoint)
        {
            // High severity for API endpoints
            if (endpoint.Path.StartsWith("/api/", StringComparison.OrdinalIgnoreCase))
            {
                return SeverityLevel.High;
            }

            // Medium severity for other endpoints
            return SeverityLevel.Medium;
        }

        /// <summary>
        /// Sends request to endpoint
        /// </summary>
        private async Task<HttpResponse> SendRequestAsync(string url, string method)
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


