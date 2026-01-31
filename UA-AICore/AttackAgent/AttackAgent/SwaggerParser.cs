using System.Text.Json;
using System.Text.RegularExpressions;
using AttackAgent.Models;
using Serilog;

namespace AttackAgent
{
    /// <summary>
    /// Parses Swagger/OpenAPI documentation to discover all available endpoints
    /// </summary>
    public class SwaggerParser
    {
        private readonly SecurityHttpClient _httpClient;
        private readonly ILogger _logger;

        public SwaggerParser(string baseUrl = "")
        {
            _httpClient = new SecurityHttpClient(baseUrl);
            _logger = Log.ForContext<SwaggerParser>();
        }

        /// <summary>
        /// Discovers all endpoints from Swagger/OpenAPI documentation
        /// </summary>
        public async Task<List<EndpointInfo>> DiscoverEndpointsFromSwaggerAsync(string baseUrl)
        {
            var endpoints = new List<EndpointInfo>();
            
            _logger.Information("🔍 Starting Swagger/OpenAPI endpoint discovery...");

            // Common Swagger/OpenAPI endpoints
            var swaggerEndpoints = new[]
            {
                "/swagger/v1/swagger.json",
                "/swagger/swagger.json", 
                "/api-docs",
                "/api-docs/swagger.json",
                "/openapi.json",
                "/swagger.json",
                "/v1/swagger.json",
                "/docs/swagger.json"
            };

            foreach (var swaggerPath in swaggerEndpoints)
            {
                try
                {
                    var url = baseUrl.TrimEnd('/') + swaggerPath;
                    _logger.Debug("Testing Swagger endpoint: {Url}", url);
                    
                    var response = await _httpClient.GetAsync(url);
                    
                    if (response.Success && !string.IsNullOrEmpty(response.Content))
                    {
                        _logger.Information("✅ Found Swagger documentation at: {Url}", url);
                        var discoveredEndpoints = await ParseSwaggerJsonAsync(response.Content, baseUrl);
                        endpoints.AddRange(discoveredEndpoints);
                        _logger.Information("📊 Discovered {Count} endpoints from Swagger", discoveredEndpoints.Count);
                        break; // Found Swagger, no need to test others
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Error testing Swagger endpoint {Path}", swaggerPath);
                }
            }

            if (endpoints.Count == 0)
            {
                _logger.Warning("⚠️ No Swagger/OpenAPI documentation found");
            }

            return endpoints;
        }

        /// <summary>
        /// Parses Swagger JSON to extract endpoint information
        /// </summary>
        private Task<List<EndpointInfo>> ParseSwaggerJsonAsync(string swaggerJson, string baseUrl)
        {
            var endpoints = new List<EndpointInfo>();

            try
            {
                using var document = JsonDocument.Parse(swaggerJson);
                var root = document.RootElement;

                if (root.TryGetProperty("paths", out var paths))
                {
                    foreach (var path in paths.EnumerateObject())
                    {
                        var pathValue = path.Value;
                        var pathName = path.Name;

                        // Extract HTTP methods and their details
                        foreach (var method in pathValue.EnumerateObject())
                        {
                            var methodName = method.Name.ToUpper();
                            var methodValue = method.Value;

                            // Skip non-HTTP method properties
                            if (!IsHttpMethod(methodName))
                                continue;

                            var endpoint = new EndpointInfo
                            {
                                Path = pathName,
                                Method = methodName,
                                IsParameterized = pathName.Contains('{'),
                                ResponseTime = TimeSpan.Zero
                            };

                            // Extract parameters if present
                            if (methodValue.TryGetProperty("parameters", out var parameters))
                            {
                                var paramList = new List<ParameterInfo>();
                                foreach (var param in parameters.EnumerateArray())
                                {
                                    if (param.TryGetProperty("name", out var paramName))
                                    {
                                        paramList.Add(new ParameterInfo
                                        {
                                            Name = paramName.GetString() ?? "",
                                            Type = param.TryGetProperty("schema", out var schema) && 
                                                   schema.TryGetProperty("type", out var type) ? 
                                                   type.GetString() ?? "string" : "string"
                                        });
                                    }
                                }
                                endpoint.Parameters = paramList;
                            }

                            endpoints.Add(endpoint);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error parsing Swagger JSON");
            }

            return Task.FromResult(endpoints);
        }

        /// <summary>
        /// Checks if a string represents a valid HTTP method
        /// </summary>
        private static bool IsHttpMethod(string method)
        {
            return method is "GET" or "POST" or "PUT" or "DELETE" or "PATCH" or "HEAD" or "OPTIONS";
        }

        /// <summary>
        /// Tests discovered endpoints to verify they're accessible
        /// </summary>
        public async Task<List<EndpointInfo>> TestDiscoveredEndpointsAsync(List<EndpointInfo> endpoints, string baseUrl)
        {
            var verifiedEndpoints = new List<EndpointInfo>();
            
            _logger.Information("🔍 Testing {Count} discovered endpoints for accessibility...", endpoints.Count);

            foreach (var endpoint in endpoints)
            {
                try
                {
                    var testUrl = endpoint.Path;
                    
                    // Handle parameterized endpoints
                    if (endpoint.IsParameterized)
                    {
                        testUrl = ReplaceParametersWithTestValues(endpoint.Path);
                    }

                    var fullUrl = baseUrl.TrimEnd('/') + testUrl;
                    
                    // Test the endpoint using its actual HTTP method
                    HttpResponse response = endpoint.Method switch
                    {
                        "GET" => await _httpClient.GetAsync(testUrl),
                        "POST" => await _httpClient.PostAsync(testUrl, "{}"),
                        "PUT" => await _httpClient.PutAsync(testUrl, "{}"),
                        "DELETE" => await _httpClient.DeleteAsync(testUrl),
                        "PATCH" => await _httpClient.PatchAsync(testUrl, "{}"),
                        "HEAD" => await _httpClient.HeadAsync(testUrl),
                        "OPTIONS" => await _httpClient.OptionsAsync(testUrl),
                        _ => await _httpClient.GetAsync(testUrl) // Default to GET
                    };
                    
                    if (response.Success)
                    {
                        endpoint.ResponseTime = response.ResponseTime;
                        verifiedEndpoints.Add(endpoint);
                        _logger.Debug("✅ Verified endpoint: {Method} {Path}", endpoint.Method, endpoint.Path);
                    }
                    else
                    {
                        _logger.Debug("❌ Endpoint not accessible: {Method} {Path} ({StatusCode})", 
                            endpoint.Method, endpoint.Path, response.StatusCode);
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Error testing endpoint {Method} {Path}", endpoint.Method, endpoint.Path);
                }
            }

            _logger.Information("✅ Verified {Count} accessible endpoints out of {Total}", 
                verifiedEndpoints.Count, endpoints.Count);

            return verifiedEndpoints;
        }

        /// <summary>
        /// Replaces parameter placeholders with test values
        /// </summary>
        private static string ReplaceParametersWithTestValues(string path)
        {
            var testValues = new Dictionary<string, string>
            {
                { "id", "1" },
                { "userId", "1" },
                { "productId", "1" },
                { "orderId", "1" },
                { "categoryId", "1" },
                { "name", "test" },
                { "slug", "test" },
                { "key", "test" }
            };

            var result = path;
            foreach (var kvp in testValues)
            {
                result = result.Replace($"{{{kvp.Key}}}", kvp.Value);
            }

            // Replace any remaining parameters with generic test values
            result = Regex.Replace(result, @"\{[^}]+\}", "1");
            
            return result;
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
}
