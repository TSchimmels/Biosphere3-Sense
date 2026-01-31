using AttackAgent.Models;
using Serilog;

namespace AttackAgent
{
    /// <summary>
    /// Tests for session management vulnerabilities including session fixation,
    /// hijacking, timeout issues, and session prediction
    /// </summary>
    public class SessionManagementTester : IDisposable
    {
        private readonly SecurityHttpClient _httpClient;
        private readonly ILogger _logger;

        public SessionManagementTester(string baseEndpoint = "")
        {
            _httpClient = new SecurityHttpClient(baseEndpoint);
            _logger = Log.ForContext<SessionManagementTester>();
        }

        /// <summary>
        /// Tests for session management vulnerabilities
        /// </summary>
        public async Task<List<Vulnerability>> TestForSessionVulnerabilitiesAsync(ApplicationProfile profile)
        {
            _logger.Information("🔐 Starting session management testing...");
            var vulnerabilities = new List<Vulnerability>();

            try
            {
                // Test session fixation
                await TestSessionFixationAsync(profile, vulnerabilities);
                
                // Test session hijacking
                await TestSessionHijackingAsync(profile, vulnerabilities);
                
                // Test session timeout
                await TestSessionTimeoutAsync(profile, vulnerabilities);
                
                // Test session prediction
                await TestSessionPredictionAsync(profile, vulnerabilities);

                _logger.Information("Session management testing completed. Found {Count} vulnerabilities", vulnerabilities.Count);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error during session management testing");
            }

            return vulnerabilities;
        }

        private async Task TestSessionFixationAsync(ApplicationProfile profile, List<Vulnerability> vulnerabilities)
        {
            _logger.Debug("Testing session fixation...");
            
            // Test if session ID is predictable or can be set by attacker
            var response = await _httpClient.GetAsync("/login");
            if (response.Headers.ContainsKey("Set-Cookie"))
            {
                var cookies = response.Headers["Set-Cookie"];
                if (cookies.Contains("JSESSIONID") || cookies.Contains("PHPSESSID") || cookies.Contains("ASP.NET_SessionId"))
                {
                    // Check if session ID is predictable
                    if (IsSessionIdPredictable(cookies))
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Id = Guid.NewGuid().ToString(),
                            Title = "Session Fixation Vulnerability",
                            Description = "Session ID appears to be predictable or can be set by attacker",
                            Severity = SeverityLevel.High,
                            Type = VulnerabilityType.SessionManagement,
                            Endpoint = "/login",
                            Evidence = cookies,
                            Remediation = "Use cryptographically secure random session IDs and regenerate on login",
                            DiscoveredAt = DateTime.UtcNow
                        });
                    }
                }
            }
        }

        private async Task TestSessionHijackingAsync(ApplicationProfile profile, List<Vulnerability> vulnerabilities)
        {
            _logger.Debug("Testing session hijacking...");
            
            // Test if session cookies are secure
            var response = await _httpClient.GetAsync("/");
            if (response.Headers.ContainsKey("Set-Cookie"))
            {
                var cookies = response.Headers["Set-Cookie"];
                if (!cookies.Contains("Secure") || !cookies.Contains("HttpOnly"))
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Id = Guid.NewGuid().ToString(),
                        Title = "Insecure Session Cookie",
                        Description = "Session cookie lacks Secure or HttpOnly flags",
                        Severity = SeverityLevel.Medium,
                        Type = VulnerabilityType.SessionManagement,
                        Endpoint = "/",
                        Evidence = cookies,
                        Remediation = "Set Secure and HttpOnly flags on session cookies",
                        DiscoveredAt = DateTime.UtcNow
                    });
                }
            }
        }

        private async Task TestSessionTimeoutAsync(ApplicationProfile profile, List<Vulnerability> vulnerabilities)
        {
            _logger.Debug("Testing session timeout...");
            
            // Test if session expires properly
            var response = await _httpClient.GetAsync("/");
            if (response.Headers.ContainsKey("Set-Cookie"))
            {
                var cookies = response.Headers["Set-Cookie"];
                if (!cookies.Contains("Expires") && !cookies.Contains("Max-Age"))
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Id = Guid.NewGuid().ToString(),
                        Title = "Session Timeout Issue",
                        Description = "Session cookie lacks expiration settings",
                        Severity = SeverityLevel.Low,
                        Type = VulnerabilityType.SessionManagement,
                        Endpoint = "/",
                        Evidence = cookies,
                        Remediation = "Set appropriate session timeout and expiration",
                        DiscoveredAt = DateTime.UtcNow
                    });
                }
            }
        }

        private async Task TestSessionPredictionAsync(ApplicationProfile profile, List<Vulnerability> vulnerabilities)
        {
            _logger.Debug("Testing session prediction...");
            
            // Test if session ID is sequential or predictable
            var sessionIds = new List<string>();
            
            for (int i = 0; i < 5; i++)
            {
                var response = await _httpClient.GetAsync("/");
                if (response.Headers.ContainsKey("Set-Cookie"))
                {
                    var cookies = response.Headers["Set-Cookie"];
                    var sessionId = ExtractSessionId(cookies);
                    if (!string.IsNullOrEmpty(sessionId))
                    {
                        sessionIds.Add(sessionId);
                    }
                }
            }
            
            if (sessionIds.Count >= 3 && IsSequential(sessionIds))
            {
                vulnerabilities.Add(new Vulnerability
                {
                    Id = Guid.NewGuid().ToString(),
                    Title = "Predictable Session ID",
                    Description = "Session IDs appear to be sequential or predictable",
                    Severity = SeverityLevel.High,
                    Type = VulnerabilityType.SessionManagement,
                    Endpoint = "/",
                    Evidence = string.Join(", ", sessionIds),
                    Remediation = "Use cryptographically secure random session IDs",
                    DiscoveredAt = DateTime.UtcNow
                });
            }
        }

        private bool IsSessionIdPredictable(string cookies)
        {
            // Simple check for common predictable patterns
            return cookies.Contains("JSESSIONID=1") || 
                   cookies.Contains("PHPSESSID=1") || 
                   cookies.Contains("ASP.NET_SessionId=1");
        }

        private string ExtractSessionId(string cookies)
        {
            var patterns = new[] { "JSESSIONID=", "PHPSESSID=", "ASP.NET_SessionId=" };
            
            foreach (var pattern in patterns)
            {
                var start = cookies.IndexOf(pattern);
                if (start >= 0)
                {
                    start += pattern.Length;
                    var end = cookies.IndexOf(';', start);
                    if (end == -1) end = cookies.Length;
                    return cookies.Substring(start, end - start);
                }
            }
            
            return string.Empty;
        }

        private bool IsSequential(List<string> sessionIds)
        {
            if (sessionIds.Count < 2) return false;
            
            // Check if session IDs are sequential numbers
            for (int i = 1; i < sessionIds.Count; i++)
            {
                if (int.TryParse(sessionIds[i], out int current) && 
                    int.TryParse(sessionIds[i-1], out int previous))
                {
                    if (current != previous + 1) return false;
                }
                else
                {
                    return false;
                }
            }
            
            return true;
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
}

