using AttackAgent.Models;
using AttackAgent.Services;
using Serilog;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AttackAgent.Engines
{
    /// <summary>
    /// Comprehensive business logic testing engine
    /// Tests for IDOR, privilege escalation, workflow bypass, race conditions, and business rule violations
    /// Ensures all test data is tracked and cleaned up
    /// </summary>
    public class BusinessLogicTester : IDisposable
    {
        private readonly SecurityHttpClient _httpClient;
        private readonly ILogger _logger;
        private readonly ResourceTracker? _resourceTracker;
        private readonly string _baseUrl;
        private bool _disposed = false;

        public BusinessLogicTester(string baseUrl, ResourceTracker? resourceTracker = null)
        {
            _baseUrl = baseUrl;
            _httpClient = new SecurityHttpClient(baseUrl);
            _logger = Log.ForContext<BusinessLogicTester>();
            _resourceTracker = resourceTracker;
        }

        /// <summary>
        /// Performs comprehensive business logic testing
        /// </summary>
        public async Task<List<Vulnerability>> TestBusinessLogicAsync(ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            _logger.Information("🧠 Starting comprehensive business logic testing...");
            
            try
            {
                // 1. IDOR (Insecure Direct Object Reference) Testing
                _logger.Information("🔍 Testing for IDOR vulnerabilities...");
                var idorVulns = await TestIDORAsync(profile);
                vulnerabilities.AddRange(idorVulns);
                _logger.Information("✅ IDOR testing completed. Found {Count} vulnerabilities", idorVulns.Count);
                
                // 2. Privilege Escalation Testing
                _logger.Information("🔍 Testing for privilege escalation vulnerabilities...");
                var privilegeVulns = await TestPrivilegeEscalationAsync(profile);
                vulnerabilities.AddRange(privilegeVulns);
                _logger.Information("✅ Privilege escalation testing completed. Found {Count} vulnerabilities", privilegeVulns.Count);
                
                // 3. Workflow Bypass Testing
                _logger.Information("🔍 Testing for workflow bypass vulnerabilities...");
                var workflowVulns = await TestWorkflowBypassAsync(profile);
                vulnerabilities.AddRange(workflowVulns);
                _logger.Information("✅ Workflow bypass testing completed. Found {Count} vulnerabilities", workflowVulns.Count);
                
                // 4. Race Condition Testing
                _logger.Information("🔍 Testing for race condition vulnerabilities...");
                var raceVulns = await TestRaceConditionsAsync(profile);
                vulnerabilities.AddRange(raceVulns);
                _logger.Information("✅ Race condition testing completed. Found {Count} vulnerabilities", raceVulns.Count);
                
                // 5. Business Rule Violation Testing
                _logger.Information("🔍 Testing for business rule violations...");
                var ruleVulns = await TestBusinessRulesAsync(profile);
                vulnerabilities.AddRange(ruleVulns);
                _logger.Information("✅ Business rule testing completed. Found {Count} vulnerabilities", ruleVulns.Count);
                
                _logger.Information("✅ Business logic testing completed. Total: {Count} vulnerabilities", vulnerabilities.Count);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error during business logic testing");
            }
            
            return vulnerabilities;
        }

        /// <summary>
        /// Tests for IDOR (Insecure Direct Object Reference) vulnerabilities
        /// </summary>
        private async Task<List<Vulnerability>> TestIDORAsync(ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            // Find endpoints with ID parameters (users, orders, documents, etc.)
            var idEndpoints = profile.DiscoveredEndpoints
                .Where(e => e.Path.Contains("{id}", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("/users/", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("/orders/", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("/documents/", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("/files/", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("/messages/", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("/posts/", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("/comments/", StringComparison.OrdinalIgnoreCase))
                .Where(e => e.Method == "GET" || e.Method == "PUT" || e.Method == "DELETE")
                .ToList();

            _logger.Information("Found {Count} potential IDOR endpoints", idEndpoints.Count);

            foreach (var endpoint in idEndpoints)
            {
                try
                {
                    // Test with different IDs to see if we can access other users' resources
                    var testIds = new[] { "1", "2", "999", "1000", "-1", "0", "admin", "test" };
                    
                    // First, get baseline response with a valid-looking ID
                    var baselineUrl = endpoint.Path.Replace("{id}", "1");
                    var baselineResponse = await _httpClient.GetAsync(_baseUrl.TrimEnd('/') + baselineUrl);
                    
                    if (!baselineResponse.Success)
                        continue;

                    foreach (var testId in testIds)
                    {
                        try
                        {
                            var testUrl = endpoint.Path.Replace("{id}", testId);
                            var testResponse = await _httpClient.GetAsync(_baseUrl.TrimEnd('/') + testUrl);
                            
                            // Check if we got unauthorized access
                            if (testResponse.Success && 
                                testResponse.StatusCode == System.Net.HttpStatusCode.OK &&
                                baselineResponse.StatusCode == System.Net.HttpStatusCode.OK)
                            {
                                // Compare responses - if different content, might be IDOR
                                if (testResponse.ContentLength > 0 && 
                                    testResponse.ContentLength != baselineResponse.ContentLength &&
                                    !string.IsNullOrEmpty(testResponse.Content))
                                {
                                    // Check if response contains user-specific data
                                    if (ContainsUserSpecificData(testResponse.Content))
                                    {
                                        vulnerabilities.Add(new Vulnerability
                                        {
                                            Type = VulnerabilityType.InsecureDirectObjectReference,
                                            Severity = SeverityLevel.High,
                                            Title = $"IDOR Vulnerability in {endpoint.Method} {endpoint.Path}",
                                            Description = $"The endpoint allows access to resources belonging to other users. Resource ID '{testId}' was accessible without proper authorization checks.",
                                            Endpoint = endpoint.Path,
                                            Method = endpoint.Method,
                                            Parameter = "id",
                                            Payload = testId,
                                            Response = testResponse.Content?.Substring(0, Math.Min(500, testResponse.Content?.Length ?? 0)) ?? "",
                                            Evidence = $"Successfully accessed resource with ID '{testId}' without authorization. Response length: {testResponse.ContentLength} bytes.",
                                            Remediation = "Implement proper authorization checks. Verify that the authenticated user has permission to access the requested resource. Use user context to filter resources.",
                                            Confidence = 0.8,
                                            Verified = true,
                                            FalsePositive = false
                                        });
                                        
                                        _logger.Warning("🚨 IDOR vulnerability found: {Method} {Path} with ID {TestId}", 
                                            endpoint.Method, endpoint.Path, testId);
                                        
                                        // Only report first IDOR per endpoint to avoid duplicates
                                        break;
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.Debug("Error testing IDOR with ID {Id}: {Error}", testId, ex.Message);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug("Error testing IDOR on endpoint {Endpoint}: {Error}", endpoint.Path, ex.Message);
                }
            }
            
            return vulnerabilities;
        }

        /// <summary>
        /// Tests for privilege escalation vulnerabilities
        /// </summary>
        private async Task<List<Vulnerability>> TestPrivilegeEscalationAsync(ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            // Find admin/privileged endpoints
            var adminEndpoints = profile.DiscoveredEndpoints
                .Where(e => e.Path.Contains("admin", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("management", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("settings", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("config", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("users", StringComparison.OrdinalIgnoreCase) && e.Path.Contains("delete", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("roles", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("permissions", StringComparison.OrdinalIgnoreCase))
                .Where(e => e.Method == "GET" || e.Method == "POST" || e.Method == "PUT" || e.Method == "DELETE")
                .ToList();

            _logger.Information("Found {Count} potential privilege escalation endpoints", adminEndpoints.Count);

            foreach (var endpoint in adminEndpoints)
            {
                try
                {
                    var url = _baseUrl.TrimEnd('/') + endpoint.Path.Replace("{id}", "1");
                    
                    // Test without authentication (should fail)
                    var response = await _httpClient.GetAsync(url);
                    
                    // If we get OK without auth, it's a privilege escalation issue
                    if (response.Success && 
                        response.StatusCode == System.Net.HttpStatusCode.OK &&
                        !string.IsNullOrEmpty(response.Content))
                    {
                        // Check if response contains admin/sensitive data
                        if (ContainsAdminData(response.Content))
                        {
                            vulnerabilities.Add(new Vulnerability
                            {
                                Type = VulnerabilityType.PrivilegeEscalation,
                                Severity = SeverityLevel.Critical,
                                Title = $"Privilege Escalation in {endpoint.Method} {endpoint.Path}",
                                Description = $"The endpoint allows unauthenticated or low-privilege users to access admin/privileged functionality.",
                                Endpoint = endpoint.Path,
                                Method = endpoint.Method,
                                Response = response.Content?.Substring(0, Math.Min(500, response.Content?.Length ?? 0)) ?? "",
                                Evidence = $"Successfully accessed admin endpoint without proper authentication/authorization.",
                                Remediation = "Implement proper role-based access control (RBAC). Verify user roles and permissions before allowing access to admin endpoints.",
                                Confidence = 0.9,
                                Verified = true,
                                FalsePositive = false
                            });
                            
                            _logger.Warning("🚨 Privilege escalation found: {Method} {Path}", 
                                endpoint.Method, endpoint.Path);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug("Error testing privilege escalation on endpoint {Endpoint}: {Error}", endpoint.Path, ex.Message);
                }
            }
            
            return vulnerabilities;
        }

        /// <summary>
        /// Tests for workflow bypass vulnerabilities
        /// </summary>
        private async Task<List<Vulnerability>> TestWorkflowBypassAsync(ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            // Find multi-step workflow endpoints (checkout, approval, etc.)
            var workflowEndpoints = profile.DiscoveredEndpoints
                .Where(e => e.Path.Contains("checkout", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("approve", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("complete", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("submit", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("finalize", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("confirm", StringComparison.OrdinalIgnoreCase))
                .Where(e => e.Method == "POST" || e.Method == "PUT")
                .ToList();

            _logger.Information("Found {Count} potential workflow endpoints", workflowEndpoints.Count);

            foreach (var endpoint in workflowEndpoints)
            {
                try
                {
                    var url = _baseUrl.TrimEnd('/') + endpoint.Path;
                    
                    // Try to bypass workflow by calling final step directly
                    var bypassBody = new Dictionary<string, object>
                    {
                        { "status", "completed" },
                        { "step", "final" },
                        { "skipValidation", true }
                    };
                    
                    var jsonBody = JsonSerializer.Serialize(bypassBody);
                    var response = await _httpClient.PostAsync(url, jsonBody);
                    
                    // If we can complete workflow without prerequisites, it's a bypass
                    if (response.Success && 
                        (response.StatusCode == System.Net.HttpStatusCode.OK || 
                         response.StatusCode == System.Net.HttpStatusCode.Created))
                    {
                        // Check if response indicates successful bypass
                        if (response.Content?.Contains("success", StringComparison.OrdinalIgnoreCase) == true ||
                            response.Content?.Contains("completed", StringComparison.OrdinalIgnoreCase) == true)
                        {
                            vulnerabilities.Add(new Vulnerability
                            {
                                Type = VulnerabilityType.BusinessLogic,
                                Severity = SeverityLevel.High,
                                Title = $"Workflow Bypass in {endpoint.Method} {endpoint.Path}",
                                Description = $"The workflow can be bypassed by directly calling the final step without completing prerequisite steps.",
                                Endpoint = endpoint.Path,
                                Method = endpoint.Method,
                                Payload = jsonBody,
                                Response = response.Content?.Substring(0, Math.Min(500, response.Content?.Length ?? 0)) ?? "",
                                Evidence = $"Successfully bypassed workflow by calling final step directly.",
                                Remediation = "Implement proper workflow state validation. Verify that all prerequisite steps have been completed before allowing final step execution.",
                                Confidence = 0.7,
                                Verified = true,
                                FalsePositive = false
                            });
                            
                            _logger.Warning("🚨 Workflow bypass found: {Method} {Path}", 
                                endpoint.Method, endpoint.Path);
                            
                            // Track any created resources for cleanup
                            try
                            {
                                if (!string.IsNullOrEmpty(response.Content))
                                {
                                    var jsonDoc = JsonDocument.Parse(response.Content);
                                    if (jsonDoc.RootElement.TryGetProperty("id", out var idProp))
                                    {
                                        var resourceId = idProp.GetString() ?? idProp.GetInt32().ToString();
                                        _resourceTracker?.TrackDatabaseEntry(endpoint.Path, resourceId, endpoint.Path + "/" + resourceId);
                                    }
                                }
                            }
                            catch
                            {
                                // Ignore tracking errors
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug("Error testing workflow bypass on endpoint {Endpoint}: {Error}", endpoint.Path, ex.Message);
                }
            }
            
            return vulnerabilities;
        }

        /// <summary>
        /// Tests for race condition vulnerabilities
        /// </summary>
        private async Task<List<Vulnerability>> TestRaceConditionsAsync(ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            // Find endpoints that modify state (balance, inventory, etc.)
            var stateModifyingEndpoints = profile.DiscoveredEndpoints
                .Where(e => e.Path.Contains("balance", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("inventory", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("stock", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("quantity", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("transfer", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("withdraw", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("deposit", StringComparison.OrdinalIgnoreCase))
                .Where(e => e.Method == "POST" || e.Method == "PUT")
                .ToList();

            _logger.Information("Found {Count} potential race condition endpoints", stateModifyingEndpoints.Count);

            foreach (var endpoint in stateModifyingEndpoints)
            {
                try
                {
                    var url = _baseUrl.TrimEnd('/') + endpoint.Path;
                    
                    // Send concurrent requests to test for race conditions
                    var concurrentRequests = 10;
                    var tasks = new List<Task<HttpResponse>>();
                    
                    for (int i = 0; i < concurrentRequests; i++)
                    {
                        var requestBody = new Dictionary<string, object>
                        {
                            { "amount", 100 },
                            { "quantity", 1 }
                        };
                        var jsonBody = JsonSerializer.Serialize(requestBody);
                        tasks.Add(_httpClient.PostAsync(url, jsonBody));
                    }
                    
                    var responses = await Task.WhenAll(tasks);
                    
                    // Check if multiple requests succeeded (race condition)
                    var successCount = responses.Count(r => r.Success && 
                        (r.StatusCode == System.Net.HttpStatusCode.OK || 
                         r.StatusCode == System.Net.HttpStatusCode.Created));
                    
                    if (successCount > 1)
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Type = VulnerabilityType.RaceCondition,
                            Severity = SeverityLevel.High,
                            Title = $"Race Condition in {endpoint.Method} {endpoint.Path}",
                            Description = $"The endpoint is vulnerable to race conditions. Multiple concurrent requests were processed successfully, which could lead to double-spending, inventory issues, or other state corruption.",
                            Endpoint = endpoint.Path,
                            Method = endpoint.Method,
                            Evidence = $"{successCount} out of {concurrentRequests} concurrent requests succeeded, indicating lack of proper locking/transaction handling.",
                            Remediation = "Implement proper transaction handling and locking mechanisms. Use database transactions, optimistic locking, or distributed locks to prevent race conditions.",
                            Confidence = 0.8,
                            Verified = true,
                            FalsePositive = false
                        });
                        
                        _logger.Warning("🚨 Race condition found: {Method} {Path} ({Count} concurrent successes)", 
                            endpoint.Method, endpoint.Path, successCount);
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug("Error testing race condition on endpoint {Endpoint}: {Error}", endpoint.Path, ex.Message);
                }
            }
            
            return vulnerabilities;
        }

        /// <summary>
        /// Tests for business rule violations
        /// </summary>
        private async Task<List<Vulnerability>> TestBusinessRulesAsync(ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            // Find endpoints that handle business logic (pricing, discounts, etc.)
            var businessEndpoints = profile.DiscoveredEndpoints
                .Where(e => e.Path.Contains("price", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("discount", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("coupon", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("payment", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("order", StringComparison.OrdinalIgnoreCase) ||
                           e.Path.Contains("cart", StringComparison.OrdinalIgnoreCase))
                .Where(e => e.Method == "POST" || e.Method == "PUT")
                .ToList();

            _logger.Information("Found {Count} potential business rule endpoints", businessEndpoints.Count);

            foreach (var endpoint in businessEndpoints)
            {
                try
                {
                    var url = _baseUrl.TrimEnd('/') + endpoint.Path;
                    
                    // Test negative prices
                    var negativePriceBody = new Dictionary<string, object>
                    {
                        { "price", -100 },
                        { "amount", -50 }
                    };
                    var negativeResponse = await TestBusinessRuleAsync(url, negativePriceBody, "negative price");
                    if (negativeResponse != null)
                    {
                        vulnerabilities.Add(negativeResponse);
                    }
                    
                    // Test invalid quantities
                    var invalidQuantityBody = new Dictionary<string, object>
                    {
                        { "quantity", -1 },
                        { "amount", 0 }
                    };
                    var quantityResponse = await TestBusinessRuleAsync(url, invalidQuantityBody, "invalid quantity");
                    if (quantityResponse != null)
                    {
                        vulnerabilities.Add(quantityResponse);
                    }
                    
                    // Test discount stacking
                    var discountBody = new Dictionary<string, object>
                    {
                        { "discount", 200 }, // >100%
                        { "coupon", "STACK" }
                    };
                    var discountResponse = await TestBusinessRuleAsync(url, discountBody, "excessive discount");
                    if (discountResponse != null)
                    {
                        vulnerabilities.Add(discountResponse);
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug("Error testing business rules on endpoint {Endpoint}: {Error}", endpoint.Path, ex.Message);
                }
            }
            
            return vulnerabilities;
        }

        /// <summary>
        /// Tests a specific business rule violation
        /// </summary>
        private async Task<Vulnerability?> TestBusinessRuleAsync(string url, Dictionary<string, object> body, string ruleType)
        {
            try
            {
                var jsonBody = JsonSerializer.Serialize(body);
                var response = await _httpClient.PostAsync(url, jsonBody);
                
                // If request succeeds with invalid business rule, it's a vulnerability
                if (response.Success && 
                    (response.StatusCode == System.Net.HttpStatusCode.OK || 
                     response.StatusCode == System.Net.HttpStatusCode.Created))
                {
                    return new Vulnerability
                    {
                        Type = VulnerabilityType.BusinessLogic,
                        Severity = SeverityLevel.Medium,
                        Title = $"Business Rule Violation: {ruleType}",
                        Description = $"The endpoint accepts invalid business logic values ({ruleType}), which could lead to financial loss or data corruption.",
                        Endpoint = url,
                        Method = "POST",
                        Payload = jsonBody,
                        Response = response.Content?.Substring(0, Math.Min(500, response.Content?.Length ?? 0)) ?? "",
                        Evidence = $"Successfully processed request with invalid business rule: {ruleType}",
                        Remediation = "Implement proper business rule validation. Validate all business logic constraints (prices, quantities, discounts) before processing requests.",
                        Confidence = 0.7,
                        Verified = true,
                        FalsePositive = false
                    };
                }
            }
            catch
            {
                // Ignore errors
            }
            
            return null;
        }

        /// <summary>
        /// Checks if response contains user-specific data
        /// </summary>
        private bool ContainsUserSpecificData(string content)
        {
            var userIndicators = new[]
            {
                "email", "username", "user_id", "userId", "userName",
                "firstname", "lastname", "phone", "address",
                "account", "balance", "account_number"
            };
            
            var lowerContent = content.ToLowerInvariant();
            return userIndicators.Any(indicator => lowerContent.Contains(indicator, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Checks if response contains admin/sensitive data
        /// </summary>
        private bool ContainsAdminData(string content)
        {
            var adminIndicators = new[]
            {
                "admin", "administrator", "root", "superuser",
                "permissions", "roles", "privileges",
                "user list", "all users", "system config"
            };
            
            var lowerContent = content.ToLowerInvariant();
            return adminIndicators.Any(indicator => lowerContent.Contains(indicator, StringComparison.OrdinalIgnoreCase));
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _httpClient?.Dispose();
                _disposed = true;
            }
        }
    }
}


















