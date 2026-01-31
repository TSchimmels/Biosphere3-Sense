using AttackAgent.Models;
using Serilog;

namespace AttackAgent
{
    /// <summary>
    /// Tests for CORS (Cross-Origin Resource Sharing) vulnerabilities
    /// </summary>
    public class CorsTester
    {
        private readonly SecurityHttpClient _httpClient;
        private readonly ILogger _logger;
        
        private readonly string[] _testOrigins = new[]
        {
            "https://evil.com",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "https://attacker.com",
            "https://malicious-site.com",
            "null",
            "*",
            "https://subdomain.evil.com",
            "http://192.168.1.100:8080"
        };
        
        private readonly string[] _testMethods = new[]
        {
            "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"
        };
        
        private readonly string[] _testHeaders = new[]
        {
            "Content-Type", "Authorization", "X-Requested-With", "X-Custom-Header",
            "Accept", "Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"
        };

        public CorsTester(string baseUrl = "")
        {
            _httpClient = new SecurityHttpClient(baseUrl);
            _logger = Log.ForContext<CorsTester>();
        }

        /// <summary>
        /// Tests CORS configuration for all discovered endpoints
        /// </summary>
        public async Task<List<Vulnerability>> TestCorsConfigurationAsync(ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            _logger.Information("🔍 Starting CORS configuration testing...");
            _logger.Information("🔍 Testing {EndpointCount} endpoints for CORS vulnerabilities...", profile.DiscoveredEndpoints.Count);

            foreach (var endpoint in profile.DiscoveredEndpoints)
            {
                try
                {
                    var endpointVulns = await TestEndpointCorsAsync(endpoint, profile.BaseUrl);
                    vulnerabilities.AddRange(endpointVulns);
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, "Error testing CORS for endpoint {Endpoint}", endpoint.Path);
                }
            }

            _logger.Information("✅ CORS testing completed. Found {Count} CORS vulnerabilities", vulnerabilities.Count);
            return vulnerabilities;
        }

        /// <summary>
        /// Tests CORS configuration for a specific endpoint
        /// </summary>
        private async Task<List<Vulnerability>> TestEndpointCorsAsync(EndpointInfo endpoint, string baseUrl)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            foreach (var origin in _testOrigins)
            {
                try
                {
                    // Test CORS preflight request
                    var preflightVulns = await TestCorsPreflightAsync(endpoint, baseUrl, origin);
                    vulnerabilities.AddRange(preflightVulns);
                    
                    // Test actual CORS request
                    var actualVulns = await TestCorsActualRequestAsync(endpoint, baseUrl, origin);
                    vulnerabilities.AddRange(actualVulns);
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Error testing CORS with origin {Origin} for endpoint {Endpoint}", origin, endpoint.Path);
                }
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Tests CORS preflight (OPTIONS) requests
        /// </summary>
        private async Task<List<Vulnerability>> TestCorsPreflightAsync(EndpointInfo endpoint, string baseUrl, string origin)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            try
            {
                var url = $"{baseUrl.TrimEnd('/')}{endpoint.Path}";
                
                // Create CORS preflight request
                var request = new HttpRequestMessage(HttpMethod.Options, url);
                request.Headers.Add("Origin", origin);
                request.Headers.Add("Access-Control-Request-Method", endpoint.Method);
                request.Headers.Add("Access-Control-Request-Headers", "Content-Type");
                
                var response = await _httpClient.SendAsync(request);
                
                if (response.Success)
                {
                    var allowOrigin = response.Headers.GetValueOrDefault("Access-Control-Allow-Origin", "");
                    var allowMethods = response.Headers.GetValueOrDefault("Access-Control-Allow-Methods", "");
                    var allowHeaders = response.Headers.GetValueOrDefault("Access-Control-Allow-Headers", "");
                    var allowCredentials = response.Headers.GetValueOrDefault("Access-Control-Allow-Credentials", "");
                    
                    // Check for dangerous CORS configurations
                    if (allowOrigin == "*")
                    {
                        vulnerabilities.Add(CreateCorsVulnerability(
                            endpoint, 
                            "Wildcard Origin Allowed", 
                            SeverityLevel.High,
                            $"CORS allows requests from any origin (*). Origin tested: {origin}",
                            "Access-Control-Allow-Origin: *"));
                    }
                    else if (allowOrigin == origin)
                    {
                        vulnerabilities.Add(CreateCorsVulnerability(
                            endpoint, 
                            "Origin Reflected", 
                            SeverityLevel.Medium,
                            $"CORS reflects the requesting origin. Origin tested: {origin}",
                            $"Access-Control-Allow-Origin: {origin}"));
                    }
                    
                    // Check for overly permissive methods
                    if (allowMethods.Contains("*") || allowMethods.Contains("DELETE") || allowMethods.Contains("PUT"))
                    {
                        vulnerabilities.Add(CreateCorsVulnerability(
                            endpoint, 
                            "Overly Permissive Methods", 
                            SeverityLevel.Medium,
                            $"CORS allows dangerous HTTP methods. Methods: {allowMethods}",
                            $"Access-Control-Allow-Methods: {allowMethods}"));
                    }
                    
                    // Check for credentials with wildcard origin
                    if (allowCredentials == "true" && allowOrigin == "*")
                    {
                        vulnerabilities.Add(CreateCorsVulnerability(
                            endpoint, 
                            "Credentials with Wildcard Origin", 
                            SeverityLevel.Critical,
                            "CORS allows credentials with wildcard origin - this is not allowed by browsers",
                            "Access-Control-Allow-Credentials: true, Access-Control-Allow-Origin: *"));
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Debug(ex, "Error testing CORS preflight for endpoint {Endpoint} with origin {Origin}", 
                    endpoint.Path, origin);
            }
            
            return vulnerabilities;
        }

        /// <summary>
        /// Tests actual CORS requests
        /// </summary>
        private async Task<List<Vulnerability>> TestCorsActualRequestAsync(EndpointInfo endpoint, string baseUrl, string origin)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            try
            {
                var url = $"{baseUrl.TrimEnd('/')}{endpoint.Path}";
                
                // Create request with Origin header
                var request = new HttpRequestMessage(GetHttpMethod(endpoint.Method), url);
                request.Headers.Add("Origin", origin);
                request.Headers.Add("Content-Type", "application/json");
                
                // Add some test data for POST/PUT requests
                if (endpoint.Method == "POST" || endpoint.Method == "PUT")
                {
                    request.Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json");
                }
                
                var response = await _httpClient.SendAsync(request);
                
                if (response.Success)
                {
                    var allowOrigin = response.Headers.GetValueOrDefault("Access-Control-Allow-Origin", "");
                    var allowCredentials = response.Headers.GetValueOrDefault("Access-Control-Allow-Credentials", "");
                    
                    // Check if the response includes CORS headers (indicating CORS is configured)
                    if (!string.IsNullOrEmpty(allowOrigin))
                    {
                        // Test for null origin bypass
                        if (origin == "null" && allowOrigin == "null")
                        {
                            vulnerabilities.Add(CreateCorsVulnerability(
                                endpoint, 
                                "Null Origin Allowed", 
                                SeverityLevel.Medium,
                                "CORS allows null origin, which can be exploited by sandboxed iframes",
                                "Access-Control-Allow-Origin: null"));
                        }
                        
                        // Test for subdomain wildcard
                        if (allowOrigin.Contains("*") && !allowOrigin.Equals("*"))
                        {
                            vulnerabilities.Add(CreateCorsVulnerability(
                                endpoint, 
                                "Subdomain Wildcard", 
                                SeverityLevel.Medium,
                                $"CORS uses subdomain wildcard: {allowOrigin}",
                                $"Access-Control-Allow-Origin: {allowOrigin}"));
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Debug(ex, "Error testing actual CORS request for endpoint {Endpoint} with origin {Origin}", 
                    endpoint.Path, origin);
            }
            
            return vulnerabilities;
        }

        /// <summary>
        /// Creates a CORS vulnerability
        /// </summary>
        private Vulnerability CreateCorsVulnerability(EndpointInfo endpoint, string title, SeverityLevel severity, 
            string description, string evidence)
        {
            return new Vulnerability
            {
                Type = VulnerabilityType.CorsMisconfiguration,
                Severity = severity,
                Title = $"CORS Vulnerability: {title}",
                Description = description,
                Evidence = evidence,
                Endpoint = endpoint.Path,
                Method = endpoint.Method,
                Remediation = GetCorsRemediation(title),
                Confidence = 0.9
            };
        }

        /// <summary>
        /// Gets remediation advice for CORS vulnerabilities
        /// </summary>
        private string GetCorsRemediation(string vulnerabilityType)
        {
            return vulnerabilityType switch
            {
                "Wildcard Origin Allowed" => "🔒 RECOMMENDED FIX: Configure specific allowed origins instead of using wildcard (*).\n\n" +
                                          "❌ VULNERABLE CODE:\n" +
                                          "// Dangerous wildcard CORS\n" +
                                          "services.AddCors(options =>\n" +
                                          "{\n" +
                                          "    options.AddPolicy(\"AllowAll\", builder =>\n" +
                                          "        builder.AllowAnyOrigin()\n" +
                                          "               .AllowAnyMethod()\n" +
                                          "               .AllowAnyHeader());\n" +
                                          "});\n" +
                                          "// Or in middleware\n" +
                                          "app.UseCors(builder => builder.AllowAnyOrigin());\n\n" +
                                          "✅ SECURE CODE:\n" +
                                          "// Specific origin whitelist\n" +
                                          "services.AddCors(options =>\n" +
                                          "{\n" +
                                          "    options.AddPolicy(\"SecurePolicy\", builder =>\n" +
                                          "        builder.WithOrigins(\"https://trusted-domain.com\", \"https://app.example.com\")\n" +
                                          "               .WithMethods(\"GET\", \"POST\")\n" +
                                          "               .WithHeaders(\"Content-Type\", \"Authorization\")\n" +
                                          "               .AllowCredentials());\n" +
                                          "});\n" +
                                          "// Environment-specific configuration\n" +
                                          "var allowedOrigins = Configuration.GetSection(\"AllowedOrigins\").Get<string[]>();\n" +
                                          "builder.WithOrigins(allowedOrigins);\n\n" +
                                          "📋 ADDITIONAL MEASURES:\n" +
                                          "• Use environment-specific CORS policies\n" +
                                          "• Implement origin validation middleware\n" +
                                          "• Use HTTPS for all allowed origins\n" +
                                          "• Regular review of allowed origins\n" +
                                          "• Implement CORS logging and monitoring\n" +
                                          "• Use Content Security Policy (CSP) headers\n" +
                                          "• Consider using SameSite cookies",

                "Origin Reflected" => "🔒 RECOMMENDED FIX: Avoid reflecting the requesting origin. Use a whitelist of allowed origins.\n\n" +
                                    "❌ VULNERABLE CODE:\n" +
                                    "// Reflecting origin (dangerous)\n" +
                                    "app.UseCors(builder =>\n" +
                                    "    builder.SetIsOriginAllowed(origin => true)\n" +
                                    "           .AllowAnyMethod()\n" +
                                    "           .AllowAnyHeader());\n" +
                                    "// Dynamic origin reflection\n" +
                                    "builder.SetIsOriginAllowed(origin => IsValidOrigin(origin));\n\n" +
                                    "✅ SECURE CODE:\n" +
                                    "// Whitelist-based origin validation\n" +
                                    "var allowedOrigins = new[] { \"https://trusted-domain.com\", \"https://app.example.com\" };\n" +
                                    "app.UseCors(builder =>\n" +
                                    "    builder.WithOrigins(allowedOrigins)\n" +
                                    "           .WithMethods(\"GET\", \"POST\")\n" +
                                    "           .WithHeaders(\"Content-Type\")\n" +
                                    "           .AllowCredentials());\n" +
                                    "// Strict origin validation\n" +
                                    "builder.SetIsOriginAllowed(origin => allowedOrigins.Contains(origin));\n\n" +
                                    "📋 ADDITIONAL MEASURES:\n" +
                                    "• Implement strict origin whitelisting\n" +
                                    "• Validate origin against known domains\n" +
                                    "• Use environment variables for allowed origins\n" +
                                    "• Implement origin validation logging\n" +
                                    "• Regular security audits of CORS policies\n" +
                                    "• Monitor for suspicious origin requests",

                "Overly Permissive Methods" => "🔒 RECOMMENDED FIX: Only allow necessary HTTP methods. Restrict dangerous methods.\n\n" +
                                            "❌ VULNERABLE CODE:\n" +
                                            "// Allowing all methods (dangerous)\n" +
                                            "builder.AllowAnyMethod();\n" +
                                            "// Allowing dangerous methods\n" +
                                            "builder.WithMethods(\"GET\", \"POST\", \"PUT\", \"DELETE\", \"PATCH\");\n\n" +
                                            "✅ SECURE CODE:\n" +
                                            "// Restrict to necessary methods only\n" +
                                            "builder.WithMethods(\"GET\", \"POST\");\n" +
                                            "// Method-specific policies\n" +
                                            "options.AddPolicy(\"ReadOnly\", builder =>\n" +
                                            "    builder.WithOrigins(allowedOrigins)\n" +
                                            "           .WithMethods(\"GET\", \"HEAD\", \"OPTIONS\"));\n" +
                                            "options.AddPolicy(\"WriteAccess\", builder =>\n" +
                                            "    builder.WithOrigins(allowedOrigins)\n" +
                                            "           .WithMethods(\"GET\", \"POST\", \"PUT\")\n" +
                                            "           .AllowCredentials());\n\n" +
                                            "📋 ADDITIONAL MEASURES:\n" +
                                            "• Use principle of least privilege for methods\n" +
                                            "• Implement method-specific CORS policies\n" +
                                            "• Avoid allowing DELETE unless necessary\n" +
                                            "• Use proper HTTP method validation\n" +
                                            "• Implement method-based access controls\n" +
                                            "• Regular review of allowed methods",

                "Credentials with Wildcard Origin" => "🔒 RECOMMENDED FIX: Cannot use wildcard origin with credentials. Specify exact origins.\n\n" +
                                                   "❌ VULNERABLE CODE:\n" +
                                                   "// Invalid CORS configuration\n" +
                                                   "builder.AllowAnyOrigin()\n" +
                                                   "       .AllowCredentials(); // This is invalid!\n" +
                                                   "// Browser will reject this\n" +
                                                   "builder.WithOrigins(\"*\")\n" +
                                                   "       .AllowCredentials();\n\n" +
                                                   "✅ SECURE CODE:\n" +
                                                   "// Valid CORS with credentials\n" +
                                                   "builder.WithOrigins(\"https://trusted-domain.com\", \"https://app.example.com\")\n" +
                                                   "       .WithMethods(\"GET\", \"POST\")\n" +
                                                   "       .WithHeaders(\"Content-Type\", \"Authorization\")\n" +
                                                   "       .AllowCredentials();\n" +
                                                   "// Or disable credentials if not needed\n" +
                                                   "builder.AllowAnyOrigin()\n" +
                                                   "       .WithMethods(\"GET\")\n" +
                                                   "       .WithHeaders(\"Content-Type\");\n\n" +
                                                   "📋 ADDITIONAL MEASURES:\n" +
                                                   "• Never use wildcard with credentials\n" +
                                                   "• Specify exact origins when using credentials\n" +
                                                   "• Use HTTPS for all credentialed requests\n" +
                                                   "• Implement proper session management\n" +
                                                   "• Use secure cookies with SameSite attribute\n" +
                                                   "• Regular security testing of CORS policies",

                "Null Origin Allowed" => "🔒 RECOMMENDED FIX: Avoid allowing null origin unless specifically required.\n\n" +
                                      "❌ VULNERABLE CODE:\n" +
                                      "// Allowing null origin (risky)\n" +
                                      "builder.SetIsOriginAllowed(origin => origin == null || IsValidOrigin(origin));\n" +
                                      "// Permissive null handling\n" +
                                      "builder.AllowAnyOrigin(); // Allows null\n\n" +
                                      "✅ SECURE CODE:\n" +
                                      "// Explicit null origin handling\n" +
                                      "builder.SetIsOriginAllowed(origin => \n" +
                                      "    origin != null && allowedOrigins.Contains(origin));\n" +
                                      "// Or handle null specifically if needed\n" +
                                      "builder.SetIsOriginAllowed(origin => \n" +
                                      "    origin == null ? allowNullOrigin : allowedOrigins.Contains(origin));\n\n" +
                                      "📋 ADDITIONAL MEASURES:\n" +
                                      "• Explicitly handle null origin cases\n" +
                                      "• Only allow null for sandboxed iframes\n" +
                                      "• Implement proper null origin validation\n" +
                                      "• Use Content Security Policy (CSP)\n" +
                                      "• Regular security audits\n" +
                                      "• Monitor for null origin abuse",

                "Subdomain Wildcard" => "🔒 RECOMMENDED FIX: Be careful with subdomain wildcards. Use specific domains.\n\n" +
                                     "❌ VULNERABLE CODE:\n" +
                                     "// Dangerous subdomain wildcard\n" +
                                     "builder.WithOrigins(\"https://*.example.com\");\n" +
                                     "// Can be exploited with evil.example.com\n" +
                                     "builder.SetIsOriginAllowed(origin => origin.EndsWith(\".example.com\"));\n\n" +
                                     "✅ SECURE CODE:\n" +
                                     "// Specific subdomains only\n" +
                                     "builder.WithOrigins(\n" +
                                     "    \"https://app.example.com\",\n" +
                                     "    \"https://api.example.com\",\n" +
                                     "    \"https://admin.example.com\");\n" +
                                     "// Or use strict subdomain validation\n" +
                                     "builder.SetIsOriginAllowed(origin => \n" +
                                     "    IsValidSubdomain(origin, \"example.com\"));\n\n" +
                                     "📋 ADDITIONAL MEASURES:\n" +
                                     "• Use specific subdomain whitelists\n" +
                                     "• Implement strict subdomain validation\n" +
                                     "• Monitor for subdomain takeover attacks\n" +
                                     "• Use DNS security measures\n" +
                                     "• Regular review of allowed subdomains\n" +
                                     "• Implement subdomain monitoring",

                _ => "🔒 RECOMMENDED FIX: Implement secure CORS configuration following best practices.\n\n" +
                     "❌ VULNERABLE CODE:\n" +
                     "// Any permissive CORS configuration\n" +
                     "builder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader();\n" +
                     "// Missing CORS configuration\n" +
                     "// No CORS headers set\n\n" +
                     "✅ SECURE CODE:\n" +
                     "// Comprehensive secure CORS\n" +
                     "services.AddCors(options =>\n" +
                     "{\n" +
                     "    options.AddPolicy(\"SecurePolicy\", builder =>\n" +
                     "        builder.WithOrigins(allowedOrigins)\n" +
                     "               .WithMethods(\"GET\", \"POST\")\n" +
                     "               .WithHeaders(\"Content-Type\", \"Authorization\")\n" +
                     "               .AllowCredentials()\n" +
                     "               .SetPreflightMaxAge(TimeSpan.FromMinutes(10)));\n" +
                     "});\n\n" +
                     "📋 COMPREHENSIVE MEASURES:\n" +
                     "• Use specific origin whitelists\n" +
                     "• Restrict HTTP methods to necessary ones\n" +
                     "• Limit allowed headers\n" +
                     "• Use credentials only when needed\n" +
                     "• Implement environment-specific policies\n" +
                     "• Use HTTPS for all CORS requests\n" +
                     "• Regular security audits of CORS policies\n" +
                     "• Monitor CORS request patterns\n" +
                     "• Implement proper error handling\n" +
                     "• Use Content Security Policy (CSP) headers"
            };
        }

        /// <summary>
        /// Converts string method to HttpMethod
        /// </summary>
        private HttpMethod GetHttpMethod(string method)
        {
            return method.ToUpper() switch
            {
                "GET" => HttpMethod.Get,
                "POST" => HttpMethod.Post,
                "PUT" => HttpMethod.Put,
                "DELETE" => HttpMethod.Delete,
                "PATCH" => HttpMethod.Patch,
                "OPTIONS" => HttpMethod.Options,
                "HEAD" => HttpMethod.Head,
                _ => HttpMethod.Get
            };
        }

        /// <summary>
        /// Disposes of resources
        /// </summary>
        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
}
