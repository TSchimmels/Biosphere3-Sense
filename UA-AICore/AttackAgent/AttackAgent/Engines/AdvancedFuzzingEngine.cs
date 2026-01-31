using AttackAgent.Models;
using AttackAgent.Services;
using Serilog;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Web;

namespace AttackAgent.Engines
{
    /// <summary>
    /// Advanced fuzzing engine with encoding variations, parameter pollution, and structure manipulation
    /// Tests for edge cases and input validation bypasses
    /// </summary>
    public class AdvancedFuzzingEngine : IDisposable
    {
        private readonly SecurityHttpClient _httpClient;
        private readonly ILogger _logger;
        private readonly ResourceTracker? _resourceTracker;
        private readonly string _baseUrl;
        private bool _disposed = false;

        public AdvancedFuzzingEngine(string baseUrl, ResourceTracker? resourceTracker = null)
        {
            _baseUrl = baseUrl;
            _httpClient = new SecurityHttpClient(baseUrl);
            _logger = Log.ForContext<AdvancedFuzzingEngine>();
            _resourceTracker = resourceTracker;
        }

        /// <summary>
        /// Performs advanced fuzzing on all discovered endpoints
        /// </summary>
        public async Task<List<Vulnerability>> FuzzEndpointsAsync(ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            _logger.Information("🔬 Starting advanced fuzzing...");
            
            try
            {
                // Get endpoints with parameters
                var parameterizedEndpoints = profile.DiscoveredEndpoints
                    .Where(e => e.Parameters.Any() || e.Path.Contains("{") || e.Path.Contains("?"))
                    .ToList();

                _logger.Information("Found {Count} endpoints with parameters to fuzz", parameterizedEndpoints.Count);

                foreach (var endpoint in parameterizedEndpoints)
                {
                    try
                    {
                        // 1. Encoding Variations
                        var encodingVulns = await TestEncodingVariationsAsync(endpoint, profile);
                        vulnerabilities.AddRange(encodingVulns);
                        
                        // 2. Parameter Pollution
                        var pollutionVulns = await TestParameterPollutionAsync(endpoint, profile);
                        vulnerabilities.AddRange(pollutionVulns);
                        
                        // 3. Array/Object Injection
                        var arrayVulns = await TestArrayObjectInjectionAsync(endpoint, profile);
                        vulnerabilities.AddRange(arrayVulns);
                        
                        // 4. HTTP Method Tampering
                        var methodVulns = await TestHttpMethodTamperingAsync(endpoint, profile);
                        vulnerabilities.AddRange(methodVulns);
                        
                        // 5. Header Injection
                        var headerVulns = await TestHeaderInjectionAsync(endpoint, profile);
                        vulnerabilities.AddRange(headerVulns);
                    }
                    catch (Exception ex)
                    {
                        _logger.Debug("Error fuzzing endpoint {Endpoint}: {Error}", endpoint.Path, ex.Message);
                    }
                }
                
                _logger.Information("✅ Advanced fuzzing completed. Found {Count} vulnerabilities", vulnerabilities.Count);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error during advanced fuzzing");
            }
            
            return vulnerabilities;
        }

        /// <summary>
        /// Tests encoding variations (URL, double-URL, Unicode, Base64, HTML entities)
        /// </summary>
        private async Task<List<Vulnerability>> TestEncodingVariationsAsync(EndpointInfo endpoint, ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            var basePayload = "<script>alert(1)</script>"; // Test payload
            
            var encodingVariations = new[]
            {
                ("URL Encoding", Uri.EscapeDataString(basePayload)),
                ("Double URL Encoding", Uri.EscapeDataString(Uri.EscapeDataString(basePayload))),
                ("Unicode Encoding", EncodeUnicode(basePayload)),
                ("Base64 Encoding", Convert.ToBase64String(Encoding.UTF8.GetBytes(basePayload))),
                ("HTML Entity Encoding", HttpUtility.HtmlEncode(basePayload)),
                ("Mixed Encoding", Uri.EscapeDataString(HttpUtility.HtmlEncode(basePayload)))
            };

            foreach (var (encodingType, encodedPayload) in encodingVariations)
            {
                try
                {
                    var url = _baseUrl.TrimEnd('/') + endpoint.Path;
                    
                    // Test in query parameters
                    if (endpoint.Path.Contains("?"))
                    {
                        url += "&test=" + encodedPayload;
                    }
                    else
                    {
                        url += "?test=" + encodedPayload;
                    }
                    
                    var response = await _httpClient.GetAsync(url);
                    
                    // Check if encoded payload bypassed validation
                    if (response.Success && 
                        response.Content?.Contains(basePayload, StringComparison.OrdinalIgnoreCase) == true)
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Type = VulnerabilityType.InputValidation,
                            Severity = SeverityLevel.Medium,
                            Title = $"Encoding Bypass: {encodingType} in {endpoint.Method} {endpoint.Path}",
                            Description = $"The endpoint is vulnerable to encoding bypass using {encodingType}. The encoded payload bypassed input validation and was executed.",
                            Endpoint = endpoint.Path,
                            Method = endpoint.Method,
                            Parameter = "test",
                            Payload = encodedPayload,
                            Response = response.Content?.Substring(0, Math.Min(500, response.Content?.Length ?? 0)) ?? "",
                            Evidence = $"Encoded payload using {encodingType} bypassed validation and was reflected in response.",
                            Remediation = "Implement proper input validation that decodes and validates all encoded inputs. Use whitelist validation instead of blacklist filtering.",
                            Confidence = 0.8,
                            Verified = true,
                            FalsePositive = false
                        });
                        
                        _logger.Warning("🚨 Encoding bypass found: {EncodingType} on {Method} {Path}", 
                            encodingType, endpoint.Method, endpoint.Path);
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug("Error testing encoding {EncodingType}: {Error}", encodingType, ex.Message);
                }
            }
            
            return vulnerabilities;
        }

        /// <summary>
        /// Tests parameter pollution (multiple values for same parameter)
        /// </summary>
        private async Task<List<Vulnerability>> TestParameterPollutionAsync(EndpointInfo endpoint, ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            if (!endpoint.Parameters.Any())
                return vulnerabilities;

            try
            {
                var url = _baseUrl.TrimEnd('/') + endpoint.Path;
                var firstParam = endpoint.Parameters.First();
                
                // Test parameter pollution
                var pollutionTests = new[]
                {
                    $"{firstParam.Name}=1&{firstParam.Name}=2", // Multiple values
                    $"{firstParam.Name}[]=1&{firstParam.Name}[]=2", // Array notation
                    $"{firstParam.Name}[0]=1&{firstParam.Name}[1]=2", // Indexed array
                    $"{firstParam.Name}=admin&{firstParam.Name}=user", // Different values
                };

                foreach (var pollutionPayload in pollutionTests)
                {
                    var testUrl = url;
                    if (url.Contains("?"))
                        testUrl += "&" + pollutionPayload;
                    else
                        testUrl += "?" + pollutionPayload;
                    
                    var response = await _httpClient.GetAsync(testUrl);
                    
                    // Check if parameter pollution caused unexpected behavior
                    if (response.Success && 
                        (response.Content?.Contains("admin", StringComparison.OrdinalIgnoreCase) == true ||
                         response.Content?.Contains("2", StringComparison.OrdinalIgnoreCase) == true))
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Type = VulnerabilityType.InputValidation,
                            Severity = SeverityLevel.Medium,
                            Title = $"Parameter Pollution in {endpoint.Method} {endpoint.Path}",
                            Description = $"The endpoint is vulnerable to parameter pollution. Multiple values for the same parameter caused unexpected behavior.",
                            Endpoint = endpoint.Path,
                            Method = endpoint.Method,
                            Parameter = firstParam.Name,
                            Payload = pollutionPayload,
                            Response = response.Content?.Substring(0, Math.Min(500, response.Content?.Length ?? 0)) ?? "",
                            Evidence = $"Parameter pollution with multiple values caused unexpected response behavior.",
                            Remediation = "Implement proper parameter handling. Use the first or last value consistently, or reject requests with duplicate parameters.",
                            Confidence = 0.7,
                            Verified = true,
                            FalsePositive = false
                        });
                        
                        _logger.Warning("🚨 Parameter pollution found: {Method} {Path}", 
                            endpoint.Method, endpoint.Path);
                        break; // Only report once per endpoint
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Debug("Error testing parameter pollution: {Error}", ex.Message);
            }
            
            return vulnerabilities;
        }

        /// <summary>
        /// Tests array and object injection
        /// </summary>
        private async Task<List<Vulnerability>> TestArrayObjectInjectionAsync(EndpointInfo endpoint, ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            if (endpoint.Method != "POST" && endpoint.Method != "PUT")
                return vulnerabilities;

            try
            {
                var url = _baseUrl.TrimEnd('/') + endpoint.Path;
                
                // Test array injection
                var arrayBody = new Dictionary<string, object>
                {
                    { "ids[]", new[] { 1, 2, 999 } },
                    { "users[0][id]", 1 },
                    { "users[0][role]", "admin" },
                    { "users[1][id]", 2 },
                    { "users[1][role]", "user" }
                };
                
                var jsonBody = JsonSerializer.Serialize(arrayBody);
                var response = await _httpClient.PostAsync(url, jsonBody);
                
                // Check if array injection caused privilege escalation
                if (response.Success && 
                    response.Content?.Contains("admin", StringComparison.OrdinalIgnoreCase) == true)
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Type = VulnerabilityType.MassAssignment,
                        Severity = SeverityLevel.High,
                        Title = $"Array/Object Injection in {endpoint.Method} {endpoint.Path}",
                        Description = $"The endpoint is vulnerable to array/object injection, which could lead to mass assignment or privilege escalation.",
                        Endpoint = endpoint.Path,
                        Method = endpoint.Method,
                        Payload = jsonBody,
                        Response = response.Content?.Substring(0, Math.Min(500, response.Content?.Length ?? 0)) ?? "",
                        Evidence = $"Array/object injection with nested structures was accepted and processed.",
                        Remediation = "Implement proper input validation. Use whitelist-based mass assignment protection. Only allow assignment of explicitly permitted fields.",
                        Confidence = 0.8,
                        Verified = true,
                        FalsePositive = false
                    });
                    
                    _logger.Warning("🚨 Array/object injection found: {Method} {Path}", 
                        endpoint.Method, endpoint.Path);
                }
            }
            catch (Exception ex)
            {
                _logger.Debug("Error testing array/object injection: {Error}", ex.Message);
            }
            
            return vulnerabilities;
        }

        /// <summary>
        /// Tests HTTP method tampering
        /// </summary>
        private async Task<List<Vulnerability>> TestHttpMethodTamperingAsync(EndpointInfo endpoint, ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            // Test method override headers
            var methodOverrideHeaders = new Dictionary<string, string>
            {
                { "X-HTTP-Method-Override", "DELETE" },
                { "X-Method-Override", "DELETE" },
                { "X-HTTP-Method", "DELETE" }
            };

            try
            {
                var url = _baseUrl.TrimEnd('/') + endpoint.Path;
                
                // If endpoint is GET, try to override to DELETE
                if (endpoint.Method == "GET")
                {
                    foreach (var header in methodOverrideHeaders)
                    {
                        var headers = new Dictionary<string, string> { { header.Key, header.Value } };
                        var response = await _httpClient.PostAsync(url, "{}", headers);
                        
                        // If we get success with method override, it's a vulnerability
                        if (response.Success && 
                            (response.StatusCode == System.Net.HttpStatusCode.OK || 
                             response.StatusCode == System.Net.HttpStatusCode.NoContent))
                        {
                            vulnerabilities.Add(new Vulnerability
                            {
                                Type = VulnerabilityType.InsecureApiDesign,
                                Severity = SeverityLevel.Medium,
                                Title = $"HTTP Method Override in {endpoint.Method} {endpoint.Path}",
                                Description = $"The endpoint accepts HTTP method override headers, which could allow unauthorized method execution.",
                                Endpoint = endpoint.Path,
                                Method = endpoint.Method,
                                Payload = $"{header.Key}: {header.Value}",
                                Evidence = $"HTTP method override header {header.Key} was accepted and executed.",
                                Remediation = "Disable HTTP method override functionality or implement strict validation of override headers.",
                                Confidence = 0.7,
                                Verified = true,
                                FalsePositive = false
                            });
                            
                            _logger.Warning("🚨 HTTP method override found: {Method} {Path} with {Header}", 
                                endpoint.Method, endpoint.Path, header.Key);
                            break; // Only report once
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Debug("Error testing HTTP method tampering: {Error}", ex.Message);
            }
            
            return vulnerabilities;
        }

        /// <summary>
        /// Tests header injection
        /// </summary>
        private async Task<List<Vulnerability>> TestHeaderInjectionAsync(EndpointInfo endpoint, ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            // Test various header injection techniques
            var injectionHeaders = new Dictionary<string, string>
            {
                { "X-Forwarded-For", "127.0.0.1" },
                { "X-Real-IP", "127.0.0.1" },
                { "X-Originating-IP", "127.0.0.1" },
                { "X-Remote-IP", "127.0.0.1" },
                { "X-Remote-Addr", "127.0.0.1" },
                { "Host", "evil.com" },
                { "X-Forwarded-Host", "evil.com" },
                { "X-Original-Host", "evil.com" }
            };

            try
            {
                var url = _baseUrl.TrimEnd('/') + endpoint.Path;
                
                foreach (var header in injectionHeaders)
                {
                    var headers = new Dictionary<string, string> { { header.Key, header.Value } };
                    var response = await _httpClient.GetAsync(url, headers);
                    
                    // Check if injected header affected response
                    if (response.Success && 
                        (response.Content?.Contains(header.Value, StringComparison.OrdinalIgnoreCase) == true ||
                         response.Headers.ContainsKey(header.Key)))
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Type = VulnerabilityType.InformationDisclosure,
                            Severity = SeverityLevel.Medium,
                            Title = $"Header Injection in {endpoint.Method} {endpoint.Path}",
                            Description = $"The endpoint is vulnerable to header injection. The {header.Key} header value was reflected in the response or affected server behavior.",
                            Endpoint = endpoint.Path,
                            Method = endpoint.Method,
                            Payload = $"{header.Key}: {header.Value}",
                            Response = response.Content?.Substring(0, Math.Min(500, response.Content?.Length ?? 0)) ?? "",
                            Evidence = $"Header injection with {header.Key} was accepted and affected response.",
                            Remediation = "Validate and sanitize all HTTP headers. Do not trust client-provided headers for security-critical operations.",
                            Confidence = 0.7,
                            Verified = true,
                            FalsePositive = false
                        });
                        
                        _logger.Warning("🚨 Header injection found: {Method} {Path} with {Header}", 
                            endpoint.Method, endpoint.Path, header.Key);
                        break; // Only report once per endpoint
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Debug("Error testing header injection: {Error}", ex.Message);
            }
            
            return vulnerabilities;
        }

        /// <summary>
        /// Encodes string to Unicode format
        /// </summary>
        private string EncodeUnicode(string input)
        {
            var sb = new StringBuilder();
            foreach (var c in input)
            {
                sb.Append($"%u{((int)c):X4}");
            }
            return sb.ToString();
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

