using AttackAgent.Core;
using AttackAgent.Data;
using AttackAgent.Models;
using AttackAgent.Services;
using Serilog;
using System.Text.Json;

namespace AttackAgent.Engines
{
    /// <summary>
    /// Enhanced SQL Injection Engine with AI learning capabilities and RAG payload generation
    /// </summary>
    public class EnhancedSqlInjectionEngine : IDisposable
    {
        private readonly LearningEngine _learningEngine;
        private readonly AttackPatternDatabase _database;
        private readonly SecurityHttpClient _httpClient;
        private readonly RAGPayloadGenerator _ragGenerator;
        private readonly ResourceTracker? _resourceTracker;
        private readonly ILogger _logger;
        private bool _disposed = false;

        public EnhancedSqlInjectionEngine(string baseUrl = "", ResourceTracker? resourceTracker = null)
        {
            _database = new AttackPatternDatabase();
            _learningEngine = new LearningEngine();
            _httpClient = new SecurityHttpClient(baseUrl);
            _ragGenerator = new RAGPayloadGenerator();
            _resourceTracker = resourceTracker;
            _logger = Log.ForContext<EnhancedSqlInjectionEngine>();
        }

        /// <summary>
        /// Test for SQL injection vulnerabilities using AI-optimized patterns
        /// </summary>
        public async Task<List<Vulnerability>> TestForSqlInjectionAsync(ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            _logger.Information("🔍 Starting enhanced SQL injection testing with AI learning...");
            
            // Get optimized patterns for the detected technology
            var technology = profile.TechnologyStack.Framework ?? "Unknown";
            var optimizedPatterns = await _learningEngine.GetOptimizedPatternsAsync(
                technology, VulnerabilityType.SqlInjection, 10);

            _logger.Information("Using {PatternCount} AI-optimized patterns for {Technology}", 
                optimizedPatterns.Count, technology);

            // Calculate total expected tests for progress tracking
            var testableEndpoints = profile.DiscoveredEndpoints.Where(e => IsTestableEndpoint(e)).ToList();
            var totalExpectedTests = CalculateTotalSqlTests(testableEndpoints, optimizedPatterns);
            _logger.Information("📊 Estimated {TotalTests} SQL injection tests to perform across {EndpointCount} endpoints", 
                totalExpectedTests, testableEndpoints.Count);

            // Progress tracking
            var completedTests = 0;
            var lastProgressPercent = 0;
            var lastHundredTests = 0;
            var progressLock = new object();

            foreach (var endpoint in testableEndpoints)
            {
                _logger.Debug("Testing endpoint: {Method} {Path}", endpoint.Method, endpoint.Path);

                var endpointVulns = await TestEndpointWithLearningAsync(endpoint, profile.BaseUrl, optimizedPatterns,
                    (testsCompleted) => {
                        lock (progressLock)
                        {
                            completedTests += testsCompleted;
                            
                            // Log every 100 tests
                            if (completedTests - lastHundredTests >= 100)
                            {
                                var hundreds = completedTests / 100;
                                _logger.Information("📊 SQL Injection Testing Progress: {Completed} tests completed ({Hundreds}00+ tests)", 
                                    completedTests, hundreds);
                                lastHundredTests = (hundreds * 100);
                            }
                            
                            // Log every 10% completion
                            if (totalExpectedTests > 0)
                            {
                                var currentPercent = (int)((completedTests * 100.0) / totalExpectedTests);
                                if (currentPercent >= lastProgressPercent + 10 && currentPercent <= 100)
                                {
                                    _logger.Information("📊 SQL Injection Testing Progress: {Percent}% complete ({Completed}/{Total} tests)", 
                                        currentPercent, completedTests, totalExpectedTests);
                                    lastProgressPercent = (currentPercent / 10) * 10;
                                }
                            }
                        }
                    });
                vulnerabilities.AddRange(endpointVulns);
            }

            _logger.Information("Enhanced SQL injection testing completed. Found {VulnCount} vulnerabilities", 
                vulnerabilities.Count);
            
            return vulnerabilities;
        }

        /// <summary>
        /// Calculates total expected SQL injection tests for progress tracking
        /// </summary>
        private int CalculateTotalSqlTests(List<EndpointInfo> endpoints, List<AttackPattern> patterns)
        {
            int total = 0;
            foreach (var endpoint in endpoints)
            {
                // Pattern-based payloads
                foreach (var pattern in patterns)
                {
                    total += pattern.Payloads.Count;
                }
                // RAG payloads (estimated ~46 per endpoint based on logs)
                total += 46;
            }
            return total;
        }

        /// <summary>
        /// Test an endpoint using AI-optimized patterns and RAG-generated payloads
        /// </summary>
        private async Task<List<Vulnerability>> TestEndpointWithLearningAsync(
            EndpointInfo endpoint, 
            string baseUrl, 
            List<AttackPattern> patterns,
            Action<int>? progressCallback = null)
        {
            var vulnerabilities = new List<Vulnerability>();
            var technology = endpoint.ResponseHeaders.GetValueOrDefault("Server", "Unknown");

            // Step 1: Test with pattern-based payloads (existing behavior)
            var patternTestsCompleted = 0;
            foreach (var pattern in patterns)
            {
                foreach (var payload in pattern.Payloads)
                {
                    try
                    {
                        var result = await TestPayloadAsync(endpoint, baseUrl, payload, pattern);
                        
                        if (result.Success)
                        {
                            var vulnerability = CreateVulnerabilityFromResult(endpoint, payload, result, pattern);
                            vulnerabilities.Add(vulnerability);
                            
                            _logger.Warning("💉 SQL Injection detected: {Endpoint} with payload: {Payload}", 
                                endpoint.Path, payload.Payload);
                        }

                        // Learn from the result
                        await _learningEngine.LearnFromResultAsync(new AttackResult
                        {
                            PatternId = pattern.Id,
                            TargetUrl = baseUrl,
                            TargetTechnology = technology,
                            Payload = payload.Payload,
                            Success = result.Success,
                            ResponseCode = result.ResponseCode,
                            ResponseBody = result.ResponseBody,
                            Confidence = result.Confidence,
                            VulnerabilityType = VulnerabilityType.SqlInjection,
                            AttackMode = AttackMode.Aggressive
                        });
                        
                        patternTestsCompleted++;
                    }
                    catch (Exception ex)
                    {
                        _logger.Error(ex, "Error testing payload {Payload} on endpoint {Endpoint}", 
                            payload.Payload, endpoint.Path);
                        patternTestsCompleted++;
                    }
                }
            }
            
            // Report progress for pattern-based tests
            progressCallback?.Invoke(patternTestsCompleted);

            // Step 2: Generate and test RAG-based payloads (context-aware)
            var ragTestsCompleted = 0;
            try
            {
                var parameterName = GetParameterNameForEndpoint(endpoint.Path);
                if (endpoint.IsParameterized && !string.IsNullOrEmpty(endpoint.ParameterName))
                {
                    parameterName = endpoint.ParameterName;
                }

                var ragPayloads = await _ragGenerator.GenerateSqlInjectionPayloadsAsync(
                    technology, 
                    endpoint.Path, 
                    parameterName);

                _logger.Debug("Generated {Count} RAG payloads for {Endpoint}", ragPayloads.Count, endpoint.Path);

                // Convert RAG payloads to AttackPayload objects and test them
                foreach (var ragPayload in ragPayloads)
                {
                    // Skip if we already tested this payload from patterns
                    if (patterns.Any(p => p.Payloads.Any(ap => ap.Payload == ragPayload)))
                    {
                        continue;
                    }

                    var attackPayload = new AttackPayload
                    {
                        Payload = ragPayload,
                        ParameterType = endpoint.IsParameterized ? "path" : "query",
                        TargetParameter = parameterName,
                        Method = endpoint.Method
                    };

                    // Use a default pattern for RAG payloads
                    var defaultPattern = patterns.FirstOrDefault() ?? new AttackPattern
                    {
                        Id = "rag-generated",
                        Name = "RAG-Generated Payload",
                        VulnerabilityType = VulnerabilityType.SqlInjection
                    };

                    try
                    {
                        var result = await TestPayloadAsync(endpoint, baseUrl, attackPayload, defaultPattern);
                        
                        if (result.Success)
                        {
                            var vulnerability = CreateVulnerabilityFromResult(endpoint, attackPayload, result, defaultPattern);
                            vulnerability.Description = $"[RAG-Generated] {vulnerability.Description}";
                            vulnerabilities.Add(vulnerability);
                            
                            _logger.Warning("💉 SQL Injection detected (RAG): {Endpoint} with payload: {Payload}", 
                                endpoint.Path, ragPayload);
                        }

                        // Learn from RAG payload results too
                        await _learningEngine.LearnFromResultAsync(new AttackResult
                        {
                            PatternId = defaultPattern.Id,
                            TargetUrl = baseUrl,
                            TargetTechnology = technology,
                            Payload = ragPayload,
                            Success = result.Success,
                            ResponseCode = result.ResponseCode,
                            ResponseBody = result.ResponseBody,
                            Confidence = result.Confidence,
                            VulnerabilityType = VulnerabilityType.SqlInjection,
                            AttackMode = AttackMode.Aggressive
                        });
                    }
                    catch (Exception ex)
                    {
                        _logger.Debug(ex, "Error testing RAG payload {Payload} on endpoint {Endpoint}", 
                            ragPayload, endpoint.Path);
                    }
                    finally
                    {
                        ragTestsCompleted++;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Warning(ex, "Error generating RAG payloads for endpoint {Endpoint}", endpoint.Path);
            }
            
            // Report progress for RAG tests
            progressCallback?.Invoke(ragTestsCompleted);

            return vulnerabilities;
        }

        /// <summary>
        /// Test a specific payload against an endpoint
        /// </summary>
        private async Task<AttackTestResult> TestPayloadAsync(
            EndpointInfo endpoint, 
            string baseUrl, 
            AttackPayload payload, 
            AttackPattern pattern)
        {
            var startTime = DateTime.UtcNow;
            string responseBody = "";
            int statusCode = 0;

            try
            {
                HttpResponse response;

                // Handle parameterized endpoints (e.g., /api/desserts/{id})
                if (endpoint.IsParameterized && !string.IsNullOrEmpty(endpoint.ParameterName))
                {
                    response = await TestParameterizedEndpointAsync(endpoint, baseUrl, payload);
                }
                else if (endpoint.Method == "GET")
                {
                    // Use specific parameter names based on endpoint path
                    var parameterName = GetParameterNameForEndpoint(endpoint.Path);
                    var url = $"{baseUrl.TrimEnd('/')}{endpoint.Path}?{parameterName}={Uri.EscapeDataString(payload.Payload)}";
                    response = await _httpClient.GetAsync(url);
                }
                else if (endpoint.Method == "POST")
                {
                    // Use specific parameter names based on endpoint path
                    var parameterName = GetParameterNameForEndpoint(endpoint.Path);
                    var requestBody = new Dictionary<string, string> 
                    { 
                        { parameterName, payload.Payload } 
                    };
                    var jsonBody = JsonSerializer.Serialize(requestBody);
                    response = await _httpClient.PostAsync(endpoint.Path, jsonBody);
                }
                else if (endpoint.Method == "PUT")
                {
                    // Use specific parameter names based on endpoint path
                    var parameterName = GetParameterNameForEndpoint(endpoint.Path);
                    var requestBody = new Dictionary<string, string> 
                    { 
                        { parameterName, payload.Payload } 
                    };
                    var jsonBody = JsonSerializer.Serialize(requestBody);
                    response = await _httpClient.PutAsync(endpoint.Path, jsonBody);
                }
                else if (endpoint.Method == "DELETE")
                {
                    response = await _httpClient.DeleteAsync(endpoint.Path);
                }
                else
                {
                    return new AttackTestResult { Success = false, Confidence = 0.0 };
                }

                statusCode = (int)response.StatusCode;
                responseBody = response.Content;
                var responseTime = (int)response.ResponseTime.TotalMilliseconds;

                // Use AI learning engine to analyze the response
                var analysis = await _learningEngine.AnalyzeResponseAsync(
                    payload.Payload, 
                    responseBody, 
                    statusCode, 
                    VulnerabilityType.SqlInjection,
                    endpoint.ResponseHeaders.GetValueOrDefault("Server", "Unknown"));

                return new AttackTestResult
                {
                    Success = analysis.Success,
                    Confidence = analysis.Confidence,
                    ResponseCode = statusCode,
                    ResponseBody = responseBody,
                    ResponseTime = responseTime,
                    Evidence = analysis.Evidence,
                    MatchedIndicator = analysis.MatchedIndicator
                };
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error testing payload {Payload}", payload.Payload);
                return new AttackTestResult
                {
                    Success = false,
                    Confidence = 0.0,
                    ResponseCode = statusCode,
                    ResponseBody = responseBody,
                    ErrorMessage = ex.Message
                };
            }
        }

        /// <summary>
        /// Get the appropriate parameter name for an endpoint based on its path
        /// </summary>
        private string GetParameterNameForEndpoint(string path)
        {
            return path.ToLower() switch
            {
                var p when p.Contains("search-products") => "search",
                var p when p.Contains("search") => "q",
                var p when p.Contains("user-products") => "userId",
                var p when p.Contains("login") => "username",
                var p when p.Contains("upload") => "file",
                var p when p.Contains("download") => "filename",
                var p when p.Contains("list-directory") => "path",
                var p when p.Contains("add-comment") => "content",
                var p when p.Contains("check-username") => "username",
                _ => "id" // Default parameter name
            };
        }

        /// <summary>
        /// Tests parameterized endpoints with SQL injection payloads
        /// </summary>
        private async Task<HttpResponse> TestParameterizedEndpointAsync(
            EndpointInfo endpoint, 
            string baseUrl, 
            AttackPayload payload)
        {
            // Replace the parameter placeholder with the SQL injection payload
            var testUrl = endpoint.Path.Replace($"{{{endpoint.ParameterName}}}", payload.Payload);
            var fullUrl = $"{baseUrl.TrimEnd('/')}{testUrl}";

            _logger.Debug("Testing parameterized endpoint: {Method} {Url} with payload: {Payload}", 
                endpoint.Method, fullUrl, payload.Payload);

            return endpoint.Method switch
            {
                "GET" => await _httpClient.GetAsync(fullUrl),
                "POST" => await _httpClient.PostAsync(fullUrl, "{}"),
                "PUT" => await _httpClient.PutAsync(fullUrl, "{}"),
                "DELETE" => await _httpClient.DeleteAsync(fullUrl),
                "PATCH" => await _httpClient.PatchAsync(fullUrl, "{}"),
                _ => throw new NotSupportedException($"HTTP method {endpoint.Method} not supported for parameterized endpoints")
            };
        }

        /// <summary>
        /// Create a vulnerability from test result
        /// </summary>
        private Vulnerability CreateVulnerabilityFromResult(
            EndpointInfo endpoint, 
            AttackPayload payload, 
            AttackTestResult result, 
            AttackPattern pattern)
        {
            return new Vulnerability
            {
                Type = VulnerabilityType.SqlInjection,
                Severity = DetermineSeverity(result.Confidence),
                Title = $"SQL Injection in {endpoint.Method} {endpoint.Path}",
                Description = $"The application is vulnerable to SQL injection through the '{payload.ParameterType}' parameter. " +
                             $"This could lead to unauthorized data access, modification, or even remote code execution.",
                Endpoint = endpoint.Path,
                Method = endpoint.Method,
                Parameter = payload.ParameterType,
                Payload = payload.Payload,
                Response = result.ResponseBody,
                Evidence = result.Evidence,
                Remediation = "🔒 RECOMMENDED FIX: Use SqlCommand.Parameters.AddWithValue() for secure SQL injection prevention.\n\n" +
                             "❌ VULNERABLE CODE:\n" +
                             "string sql = \"SELECT * FROM Users WHERE Username = '\" + username + \"'\";\n" +
                             "SqlCommand command = new SqlCommand(sql, connection);\n\n" +
                             "✅ SECURE CODE:\n" +
                             "string sql = \"SELECT * FROM Users WHERE Username = @Username\";\n" +
                             "SqlCommand command = new SqlCommand(sql, connection);\n" +
                             "command.Parameters.AddWithValue(\"@Username\", username);\n\n" +
                             "📋 ADDITIONAL MEASURES:\n" +
                             "• Use parameterized queries for ALL database operations\n" +
                             "• Validate and sanitize all user input\n" +
                             "• Use Entity Framework or other ORMs that handle SQL injection automatically\n" +
                             "• Implement proper input validation and output encoding\n" +
                             "• Follow the principle of least privilege for database access",
                AttackMode = AttackMode.Aggressive,
                Confidence = result.Confidence,
                Verified = result.Confidence > 0.8
            };
        }

        /// <summary>
        /// Determine severity based on confidence level
        /// </summary>
        private SeverityLevel DetermineSeverity(double confidence)
        {
            if (confidence >= 0.9) return SeverityLevel.Critical;
            if (confidence >= 0.7) return SeverityLevel.High;
            if (confidence >= 0.5) return SeverityLevel.Medium;
            return SeverityLevel.Low;
        }

        /// <summary>
        /// Check if endpoint is suitable for SQL injection testing
        /// </summary>
        private bool IsTestableEndpoint(EndpointInfo endpoint)
        {
            // Test API endpoints and forms that likely accept user input
            return endpoint.Path.Contains("/api/") || 
                   endpoint.Path.Contains("/search") ||
                   endpoint.Path.Contains("/login") ||
                   endpoint.Path.Contains("/register") ||
                   endpoint.Method == "POST";
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _learningEngine?.Dispose();
                _database?.Dispose();
                _httpClient?.Dispose();
                _ragGenerator?.Dispose();
                _disposed = true;
            }
        }
    }

    /// <summary>
    /// Result of testing a payload against an endpoint
    /// </summary>
    public class AttackTestResult
    {
        public bool Success { get; set; }
        public double Confidence { get; set; }
        public int ResponseCode { get; set; }
        public string ResponseBody { get; set; } = string.Empty;
        public int ResponseTime { get; set; }
        public string Evidence { get; set; } = string.Empty;
        public string MatchedIndicator { get; set; } = string.Empty;
        public string ErrorMessage { get; set; } = string.Empty;
    }
}
