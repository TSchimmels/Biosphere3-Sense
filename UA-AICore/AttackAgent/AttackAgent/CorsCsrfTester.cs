using AttackAgent.Models;
using Serilog;
using System.Net;

namespace AttackAgent
{
    /// <summary>
    /// Tests for CORS and CSRF vulnerabilities including cross-origin requests,
    /// CSRF token validation, and origin header manipulation
    /// </summary>
    public class CorsCsrfTester : IDisposable
    {
        private readonly SecurityHttpClient _httpClient;
        private readonly ILogger _logger;

        public CorsCsrfTester(string baseEndpoint = "")
        {
            _httpClient = new SecurityHttpClient(baseEndpoint);
            _logger = Log.ForContext<CorsCsrfTester>();
        }

        /// <summary>
        /// Tests for CORS and CSRF vulnerabilities
        /// </summary>
        public async Task<List<Vulnerability>> TestForCorsCsrfVulnerabilitiesAsync(ApplicationProfile profile)
        {
            _logger.Information("🌐 Starting CORS/CSRF testing...");
            var vulnerabilities = new List<Vulnerability>();

            try
            {
                // Test CORS configuration
                await TestCorsConfigurationAsync(profile, vulnerabilities);
                
                // Test CSRF protection
                await TestCsrfProtectionAsync(profile, vulnerabilities);
                
                // Test origin header manipulation
                await TestOriginHeaderManipulationAsync(profile, vulnerabilities);

                _logger.Information("CORS/CSRF testing completed. Found {Count} vulnerabilities", vulnerabilities.Count);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error during CORS/CSRF testing");
            }

            return vulnerabilities;
        }

        private async Task TestCorsConfigurationAsync(ApplicationProfile profile, List<Vulnerability> vulnerabilities)
        {
            _logger.Debug("Testing CORS configuration...");
            
            // Test with malicious origin
            var maliciousOrigins = new[]
            {
                "https://evil.com",
                "http://evil.com",
                "https://attacker.com",
                "http://attacker.com",
                "https://malicious.com",
                "http://malicious.com",
                "null",
                "https://null",
                "http://null"
            };

            foreach (var origin in maliciousOrigins)
            {
                var headers = new Dictionary<string, string>
                {
                    ["Origin"] = origin,
                    ["Access-Control-Request-Method"] = "POST",
                    ["Access-Control-Request-Headers"] = "Content-Type"
                };

                var response = await _httpClient.GetAsync("/", headers);
                
                if (response.Headers.ContainsKey("Access-Control-Allow-Origin"))
                {
                    var allowedOrigin = response.Headers["Access-Control-Allow-Origin"];
                    if (allowedOrigin == "*" || allowedOrigin == origin)
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Id = Guid.NewGuid().ToString(),
                            Title = "CORS Misconfiguration",
                            Description = $"CORS allows requests from malicious origin: {origin}",
                            Severity = SeverityLevel.High,
                            Type = VulnerabilityType.Cors,
                            Endpoint = "/",
                            Evidence = $"Access-Control-Allow-Origin: {allowedOrigin}",
                            Remediation = "Configure CORS to only allow trusted origins",
                            DiscoveredAt = DateTime.UtcNow
                        });
                    }
                }
            }
        }

        private async Task TestCsrfProtectionAsync(ApplicationProfile profile, List<Vulnerability> vulnerabilities)
        {
            _logger.Debug("Testing CSRF protection...");
            
            // Test if CSRF tokens are required for state-changing operations
            var stateChangingEndpoints = new[]
            {
                "/api/desserts",
                "/api/chatbot/chat",
                "/api/chatbot/history",
                "/api/spell-check/country"
            };

            foreach (var endpoint in stateChangingEndpoints)
            {
                // Test POST without CSRF token
                var response = await _httpClient.PostAsync(endpoint, "test=data");
                
                if (response.StatusCode == HttpStatusCode.OK || response.StatusCode == HttpStatusCode.Created)
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Id = Guid.NewGuid().ToString(),
                        Title = "Missing CSRF Protection",
                        Description = $"Endpoint {endpoint} accepts POST requests without CSRF token",
                        Severity = SeverityLevel.High,
                        Type = VulnerabilityType.Csrf,
                        Endpoint = endpoint,
                        Evidence = $"Status: {response.StatusCode}",
                        Remediation = "Implement CSRF token validation for state-changing operations",
                        DiscoveredAt = DateTime.UtcNow
                    });
                }
            }
        }

        private async Task TestOriginHeaderManipulationAsync(ApplicationProfile profile, List<Vulnerability> vulnerabilities)
        {
            _logger.Debug("Testing origin header manipulation...");
            
            // Test with various origin header values
            var testOrigins = new[]
            {
                "https://trusted.com",
                "https://subdomain.trusted.com",
                "https://trusted.com:8080",
                "https://trusted.com/path",
                "https://trusted.com?param=value",
                "https://trusted.com#fragment",
                "https://trusted.com:8080/path?param=value#fragment",
                "https://trusted.com:8080/path?param=value#fragment",
                "https://trusted.com:8080/path?param=value#fragment",
                "https://trusted.com:8080/path?param=value#fragment"
            };

            foreach (var origin in testOrigins)
            {
                var headers = new Dictionary<string, string>
                {
                    ["Origin"] = origin,
                    ["Referer"] = origin
                };

                var response = await _httpClient.GetAsync("/", headers);
                
                // Check if the application properly validates origin headers
                if (response.Headers.ContainsKey("Access-Control-Allow-Origin"))
                {
                    var allowedOrigin = response.Headers["Access-Control-Allow-Origin"];
                    if (allowedOrigin == "*")
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Id = Guid.NewGuid().ToString(),
                            Title = "Overly Permissive CORS",
                            Description = "CORS allows all origins with wildcard (*)",
                            Severity = SeverityLevel.Medium,
                            Type = VulnerabilityType.Cors,
                            Endpoint = "/",
                            Evidence = $"Access-Control-Allow-Origin: {allowedOrigin}",
                            Remediation = "Use specific origins instead of wildcard",
                            DiscoveredAt = DateTime.UtcNow
                        });
                    }
                }
            }
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
}

