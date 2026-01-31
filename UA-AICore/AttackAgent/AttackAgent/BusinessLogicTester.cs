using AttackAgent.Models;
using Serilog;
using System.Net;

namespace AttackAgent
{
    /// <summary>
    /// Tests for business logic vulnerabilities including race conditions,
    /// rate limiting bypass, workflow issues, and authorization flaws
    /// </summary>
    public class BusinessLogicTester : IDisposable
    {
        private readonly SecurityHttpClient _httpClient;
        private readonly ILogger _logger;

        public BusinessLogicTester(string baseEndpoint = "")
        {
            _httpClient = new SecurityHttpClient(baseEndpoint);
            _logger = Log.ForContext<BusinessLogicTester>();
        }

        /// <summary>
        /// Tests for business logic vulnerabilities
        /// </summary>
        public async Task<List<Vulnerability>> TestForBusinessLogicVulnerabilitiesAsync(ApplicationProfile profile)
        {
            _logger.Information("🏢 Starting business logic testing...");
            var vulnerabilities = new List<Vulnerability>();

            try
            {
                // Test race conditions
                await TestRaceConditionsAsync(profile, vulnerabilities);
                
                // Test rate limiting
                await TestRateLimitingAsync(profile, vulnerabilities);
                
                // Test workflow issues
                await TestWorkflowIssuesAsync(profile, vulnerabilities);
                
                // Test authorization flaws
                await TestAuthorizationFlawsAsync(profile, vulnerabilities);

                _logger.Information("Business logic testing completed. Found {Count} vulnerabilities", vulnerabilities.Count);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error during business logic testing");
            }

            return vulnerabilities;
        }

        private async Task TestRaceConditionsAsync(ApplicationProfile profile, List<Vulnerability> vulnerabilities)
        {
            _logger.Debug("Testing race conditions...");
            
            // Test concurrent requests to the same endpoint
            var tasks = new List<Task<HttpResponse>>();
            
            for (int i = 0; i < 10; i++)
            {
                tasks.Add(_httpClient.PostAsync("/api/desserts", $"name=test{i}&description=test{i}"));
            }
            
            var responses = await Task.WhenAll(tasks);
            
            // Check if multiple requests succeeded (potential race condition)
            var successCount = responses.Count(r => r.StatusCode == HttpStatusCode.OK || r.StatusCode == HttpStatusCode.Created);
            if (successCount > 1)
            {
                vulnerabilities.Add(new Vulnerability
                {
                    Id = Guid.NewGuid().ToString(),
                    Title = "Race Condition Vulnerability",
                    Description = $"Multiple concurrent requests succeeded: {successCount}/10",
                    Severity = SeverityLevel.Medium,
                    Type = VulnerabilityType.BusinessLogic,
                    Endpoint = "/api/desserts",
                    Evidence = $"Success count: {successCount}",
                    Remediation = "Implement proper concurrency control and locking mechanisms",
                    DiscoveredAt = DateTime.UtcNow
                });
            }
        }

        private async Task TestRateLimitingAsync(ApplicationProfile profile, List<Vulnerability> vulnerabilities)
        {
            _logger.Debug("Testing rate limiting...");
            
            // Test rapid requests to check for rate limiting
            var requests = new List<Task<HttpResponse>>();
            
            for (int i = 0; i < 100; i++)
            {
                requests.Add(_httpClient.GetAsync("/"));
            }
            
            var responses = await Task.WhenAll(requests);
            
            // Check if all requests succeeded (no rate limiting)
            var successCount = responses.Count(r => r.StatusCode == HttpStatusCode.OK);
            if (successCount == 100)
            {
                vulnerabilities.Add(new Vulnerability
                {
                    Id = Guid.NewGuid().ToString(),
                    Title = "Missing Rate Limiting",
                    Description = "No rate limiting detected on endpoint",
                    Severity = SeverityLevel.Medium,
                    Type = VulnerabilityType.BusinessLogic,
                    Endpoint = "/",
                    Evidence = $"All {successCount} requests succeeded",
                    Remediation = "Implement rate limiting to prevent abuse",
                    DiscoveredAt = DateTime.UtcNow
                });
            }
        }

        private async Task TestWorkflowIssuesAsync(ApplicationProfile profile, List<Vulnerability> vulnerabilities)
        {
            _logger.Debug("Testing workflow issues...");
            
            // Test if endpoints can be accessed in wrong order
            var workflowTests = new[]
            {
                ("/api/desserts", "POST", "Creating dessert without authentication"),
                ("/api/chatbot/chat", "POST", "Sending chat message without authentication"),
                ("/api/chatbot/history", "GET", "Accessing chat history without authentication"),
                ("/api/spell-check/country", "POST", "Using spell check without authentication")
            };

            foreach (var (endpoint, method, description) in workflowTests)
            {
                HttpResponse response;
                if (method == "POST")
                {
                    response = await _httpClient.PostAsync(endpoint, "test=data");
                }
                else
                {
                    response = await _httpClient.GetAsync(endpoint);
                }
                
                if (response.StatusCode == HttpStatusCode.OK || response.StatusCode == HttpStatusCode.Created)
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Id = Guid.NewGuid().ToString(),
                        Title = "Workflow Bypass",
                        Description = description,
                        Severity = SeverityLevel.Medium,
                        Type = VulnerabilityType.BusinessLogic,
                        Endpoint = endpoint,
                        Evidence = $"Status: {response.StatusCode}",
                        Remediation = "Implement proper workflow validation and authentication",
                        DiscoveredAt = DateTime.UtcNow
                    });
                }
            }
        }

        private async Task TestAuthorizationFlawsAsync(ApplicationProfile profile, List<Vulnerability> vulnerabilities)
        {
            _logger.Debug("Testing authorization flaws...");
            
            // Test if admin endpoints are accessible without authentication
            var adminEndpoints = new[]
            {
                "/admin",
                "/admin/dashboard",
                "/admin/users",
                "/admin/settings",
                "/api/admin",
                "/api/admin/users",
                "/api/admin/settings"
            };

            foreach (var endpoint in adminEndpoints)
            {
                var response = await _httpClient.GetAsync(endpoint);
                
                if (response.StatusCode == HttpStatusCode.OK)
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Id = Guid.NewGuid().ToString(),
                        Title = "Authorization Bypass",
                        Description = $"Admin endpoint accessible without authentication: {endpoint}",
                        Severity = SeverityLevel.High,
                        Type = VulnerabilityType.Authorization,
                        Endpoint = endpoint,
                        Evidence = $"Status: {response.StatusCode}",
                        Remediation = "Implement proper authentication and authorization checks",
                        DiscoveredAt = DateTime.UtcNow
                    });
                }
            }
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
}

