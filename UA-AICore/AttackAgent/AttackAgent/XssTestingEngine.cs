using AttackAgent.Models;
using AttackAgent.Services;
using Serilog;
using System.Text.RegularExpressions;

namespace AttackAgent
{
    /// <summary>
    /// XSS testing engine with comprehensive payload database and RAG-based payload generation
    /// Tests for reflected, stored, and DOM-based XSS vulnerabilities
    /// </summary>
    public class XssTestingEngine : IDisposable
    {
        private readonly SecurityHttpClient _httpClient;
        private readonly ILogger _logger;
        private readonly List<XssPayload> _payloads;
        private readonly RAGPayloadGenerator _ragGenerator;
        private readonly SemaphoreSlim _concurrencySemaphore;
        private readonly ResourceTracker? _resourceTracker;
        private bool _disposed = false;

        public XssTestingEngine(ResourceTracker? resourceTracker = null)
        {
            _httpClient = new SecurityHttpClient();
            _logger = Log.ForContext<XssTestingEngine>();
            _payloads = InitializeXssPayloads();
            _ragGenerator = new RAGPayloadGenerator();
            _concurrencySemaphore = new SemaphoreSlim(10, 10); // Allow 10 concurrent XSS tests
            _resourceTracker = resourceTracker;
        }

        /// <summary>
        /// Tests all discovered endpoints for XSS vulnerabilities
        /// </summary>
        public async Task<List<Vulnerability>> TestForXssAsync(ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            _logger.Information("🔍 Starting XSS testing...");
            _logger.Information("Testing {EndpointCount} endpoints with {PayloadCount} XSS payloads", 
                profile.DiscoveredEndpoints.Count, _payloads.Count);

            // Add known WebsiteTest endpoints if not discovered
            var knownEndpoints = new List<EndpointInfo>
            {
                new EndpointInfo { Path = "/api/chatbot/chat", Method = "POST", StatusCode = 200 },
                new EndpointInfo { Path = "/api/chatbot/recipe", Method = "POST", StatusCode = 200 },
                new EndpointInfo { Path = "/api/spell-check/country", Method = "POST", StatusCode = 200 },
                new EndpointInfo { Path = "/api/chatbot/history", Method = "GET", StatusCode = 200 }
            };

            var allEndpoints = profile.DiscoveredEndpoints.ToList();
            foreach (var known in knownEndpoints)
            {
                if (!allEndpoints.Any(e => e.Path == known.Path && e.Method == known.Method))
                {
                    _logger.Information("🔍 Adding known endpoint for testing: {Method} {Path}", known.Method, known.Path);
                    allEndpoints.Add(known);
                }
            }

            // Calculate total expected tests for progress tracking
            var testableEndpoints = allEndpoints.Where(e => IsTestableEndpoint(e)).ToList();
            var totalExpectedTests = CalculateTotalXssTests(testableEndpoints);
            _logger.Information("📊 Estimated {TotalTests} XSS tests to perform across {EndpointCount} endpoints", 
                totalExpectedTests, testableEndpoints.Count);

            // Progress tracking
            var completedTests = 0;
            var lastProgressPercent = 0;
            var lastHundredTests = 0;
            var progressLock = new object();

            foreach (var endpoint in testableEndpoints)
            {
                _logger.Debug("🔍 Testing XSS endpoint: {Method} {Path}", endpoint.Method, endpoint.Path);

                var endpointVulns = await TestEndpointForXssAsync(endpoint, profile.BaseUrl, 
                    (testsCompleted) => {
                        lock (progressLock)
                        {
                            completedTests += testsCompleted;
                            
                            // Log every 100 tests
                            if (completedTests - lastHundredTests >= 100)
                            {
                                var hundreds = completedTests / 100;
                                _logger.Information("📊 XSS Testing Progress: {Completed} tests completed ({Hundreds}00+ tests)", 
                                    completedTests, hundreds);
                                lastHundredTests = (hundreds * 100);
                            }
                            
                            // Log every 10% completion
                            if (totalExpectedTests > 0)
                            {
                                var currentPercent = (int)((completedTests * 100.0) / totalExpectedTests);
                                if (currentPercent >= lastProgressPercent + 10 && currentPercent <= 100)
                                {
                                    _logger.Information("📊 XSS Testing Progress: {Percent}% complete ({Completed}/{Total} tests)", 
                                        currentPercent, completedTests, totalExpectedTests);
                                    lastProgressPercent = (currentPercent / 10) * 10;
                                }
                            }
                        }
                    });
                vulnerabilities.AddRange(endpointVulns);
            }

            // Test for stored XSS (POST then GET flow)
            _logger.Information("🔍 Testing for stored XSS vulnerabilities...");
            var storedXssVulns = await TestForStoredXssAsync(profile);
            vulnerabilities.AddRange(storedXssVulns);

            _logger.Information("XSS testing completed. Found {VulnCount} vulnerabilities", vulnerabilities.Count);
            return vulnerabilities;
        }

        /// <summary>
        /// Tests for stored XSS vulnerabilities (POST payload then GET to retrieve)
        /// </summary>
        private async Task<List<Vulnerability>> TestForStoredXssAsync(ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            // Add known endpoints if not discovered
            var allEndpoints = profile.DiscoveredEndpoints.ToList();
            var knownChatbotChat = new EndpointInfo { Path = "/api/chatbot/chat", Method = "POST", StatusCode = 200 };
            var knownChatbotRecipe = new EndpointInfo { Path = "/api/chatbot/recipe", Method = "POST", StatusCode = 200 };
            var knownChatbotHistory = new EndpointInfo { Path = "/api/chatbot/history", Method = "GET", StatusCode = 200 };

            if (!allEndpoints.Any(e => e.Path == knownChatbotChat.Path && e.Method == knownChatbotChat.Method))
                allEndpoints.Add(knownChatbotChat);
            if (!allEndpoints.Any(e => e.Path == knownChatbotRecipe.Path && e.Method == knownChatbotRecipe.Method))
                allEndpoints.Add(knownChatbotRecipe);
            if (!allEndpoints.Any(e => e.Path == knownChatbotHistory.Path && e.Method == knownChatbotHistory.Method))
                allEndpoints.Add(knownChatbotHistory);
            
            // Look for endpoints that store data and have retrieval endpoints
            var storeEndpoints = allEndpoints
                .Where(e => e.Method == "POST" && 
                           (e.Path.Contains("chatbot/chat", StringComparison.OrdinalIgnoreCase) ||
                            e.Path.Contains("chatbot/recipe", StringComparison.OrdinalIgnoreCase)))
                .ToList();

            var retrieveEndpoints = allEndpoints
                .Where(e => e.Method == "GET" && 
                           e.Path.Contains("chatbot/history", StringComparison.OrdinalIgnoreCase))
                .ToList();

            foreach (var storeEndpoint in storeEndpoints)
            {
                foreach (var retrieveEndpoint in retrieveEndpoints)
                {
                    // Test stored XSS flow
                    foreach (var payload in _payloads.Take(5)) // Test top 5 payloads
                    {
                        try
                        {
                            var stored = await TestStoredXssFlowAsync(
                                profile.BaseUrl, storeEndpoint, retrieveEndpoint, payload);
                            
                            if (stored.IsVulnerable)
                            {
                                var vulnerability = CreateStoredXssVulnerability(
                                    storeEndpoint, retrieveEndpoint, payload, stored);
                                vulnerabilities.Add(vulnerability);
                                
                                _logger.Warning("🚨 Stored XSS found: POST {StorePath} → GET {RetrievePath} with payload '{Payload}'", 
                                    storeEndpoint.Path, retrieveEndpoint.Path, payload.Payload);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.Debug("Error testing stored XSS: {Error}", ex.Message);
                        }
                    }
                }
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Tests stored XSS flow: POST payload then GET to retrieve
        /// </summary>
        private async Task<XssTestResult> TestStoredXssFlowAsync(
            string baseUrl, EndpointInfo storeEndpoint, EndpointInfo retrieveEndpoint, XssPayload payload)
        {
            var result = new XssTestResult
            {
                Payload = payload,
                IsVulnerable = false,
                Confidence = 0.0
            };

            try
            {
                // Step 1: Store XSS payload via POST
                var storeUrl = baseUrl.TrimEnd('/') + storeEndpoint.Path;
                var paramName = storeEndpoint.Path.Contains("chatbot/chat") ? "message" : "dessertName";
                
                var requestBody = new Dictionary<string, string>();
                if (storeEndpoint.Path.Contains("chatbot/chat"))
                {
                    requestBody["message"] = payload.Payload;
                    requestBody["sessionId"] = Guid.NewGuid().ToString();
                }
                else if (storeEndpoint.Path.Contains("chatbot/recipe"))
                {
                    requestBody["dessertName"] = payload.Payload;
                    requestBody["userMessage"] = "recipe";
                    requestBody["sessionId"] = Guid.NewGuid().ToString();
                }

                var jsonBody = System.Text.Json.JsonSerializer.Serialize(requestBody);
                var storeResponse = await _httpClient.PostAsync(storeUrl, jsonBody);
                
                if (!storeResponse.Success)
                    return result;

                // Track stored database entry for cleanup
                try
                {
                    string? entryId = null;
                    if (!string.IsNullOrEmpty(storeResponse.Content))
                    {
                        // Try to extract ID from response
                        var jsonDoc = System.Text.Json.JsonDocument.Parse(storeResponse.Content);
                        if (jsonDoc.RootElement.TryGetProperty("id", out var idProp))
                        {
                            entryId = idProp.GetString() ?? idProp.GetInt32().ToString();
                        }
                    }
                    
                    // Use sessionId or entryId as identifier
                    var identifier = entryId ?? requestBody.GetValueOrDefault("sessionId") ?? Guid.NewGuid().ToString();
                    var deleteEndpoint = retrieveEndpoint.Path.Contains("{id}") 
                        ? retrieveEndpoint.Path 
                        : retrieveEndpoint.Path + "/{id}";
                    
                    _resourceTracker?.TrackDatabaseEntry(storeEndpoint.Path, identifier, deleteEndpoint);
                }
                catch
                {
                    // If tracking fails, continue anyway - cleanup will still work via aggressive cleanup
                }

                // Step 2: Wait a bit for storage (reduced from 500ms to 200ms for performance)
                await Task.Delay(200);

                // Step 3: Retrieve stored data via GET
                var retrieveUrl = baseUrl.TrimEnd('/') + retrieveEndpoint.Path;
                var retrieveResponse = await _httpClient.GetAsync(retrieveUrl);

                // Step 4: Check if payload is in retrieved data
                if (retrieveResponse.Success && 
                    retrieveResponse.Content.Contains(payload.Payload, StringComparison.OrdinalIgnoreCase))
                {
                    // Check if it's in JSON value context
                    if (IsJsonResponse(retrieveResponse))
                    {
                        if (IsPayloadInJsonValue(retrieveResponse.Content, payload.Payload))
                        {
                            result.IsVulnerable = true;
                            result.Confidence = 0.9; // High confidence for stored XSS
                            result.Evidence = $"Stored XSS: Payload stored via {storeEndpoint.Path} and retrieved via {retrieveEndpoint.Path}";
                            result.PayloadResponse = retrieveResponse;
                        }
                    }
                    else
                    {
                        // HTML response
                        if (ContainsScriptExecution(retrieveResponse.Content, payload))
                        {
                            result.IsVulnerable = true;
                            result.Confidence = 0.9;
                            result.Evidence = $"Stored XSS: Payload stored via {storeEndpoint.Path} and retrieved via {retrieveEndpoint.Path}";
                            result.PayloadResponse = retrieveResponse;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Debug("Error testing stored XSS flow: {Error}", ex.Message);
            }

            return result;
        }

        /// <summary>
        /// Creates a stored XSS vulnerability report
        /// </summary>
        private Vulnerability CreateStoredXssVulnerability(
            EndpointInfo storeEndpoint, EndpointInfo retrieveEndpoint, XssPayload payload, XssTestResult result)
        {
            return new Vulnerability
            {
                Type = VulnerabilityType.ReflectedXss,
                Severity = SeverityLevel.High,
                Title = "Stored XSS Vulnerability",
                Description = $"XSS payload stored via {storeEndpoint.Path} and retrieved via {retrieveEndpoint.Path}. " +
                             "The payload is persisted in the database and returned in subsequent requests.",
                Endpoint = $"{storeEndpoint.Path} → {retrieveEndpoint.Path}",
                Method = $"{storeEndpoint.Method} → {retrieveEndpoint.Method}",
                Parameter = "message/dessertName",
                Payload = payload.Payload,
                Response = result.PayloadResponse?.Content ?? "",
                Evidence = result.Evidence ?? "Stored XSS payload detected in retrieved data",
                Remediation = "Sanitize all user input before storing in database. Use output encoding when rendering stored data. " +
                            "Implement Content Security Policy (CSP) headers.",
                Confidence = result.Confidence,
                Verified = true,
                FalsePositive = false
            };
        }

        /// <summary>
        /// Calculates total expected XSS tests for progress tracking
        /// </summary>
        private int CalculateTotalXssTests(List<EndpointInfo> endpoints)
        {
            int total = 0;
            foreach (var endpoint in endpoints)
            {
                if (endpoint.Parameters.Any())
                {
                    // Static payloads + RAG payloads per parameter
                    total += endpoint.Parameters.Count * (_payloads.Count + 12); // ~12 RAG payloads estimated
                }
                else
                {
                    // Common parameter testing (10 payloads × common params)
                    var commonParams = GetParameterNamesForEndpoint(endpoint.Path);
                    total += commonParams.Length * 10; // Top 10 payloads
                    total += commonParams.Length * 10; // RAG payloads
                }
            }
            return total;
        }

        /// <summary>
        /// Tests a specific endpoint for XSS vulnerabilities using both static and RAG-generated payloads
        /// </summary>
        private async Task<List<Vulnerability>> TestEndpointForXssAsync(EndpointInfo endpoint, string baseUrl, Action<int>? progressCallback = null)
        {
            var vulnerabilities = new List<Vulnerability>();
            var url = baseUrl.TrimEnd('/') + endpoint.Path;
            var technology = endpoint.ResponseHeaders.GetValueOrDefault("Server", "Unknown");

            // Step 1: Test with static payloads (PARALLELIZED for performance)
            var staticPayloadTasks = new List<Task<Vulnerability?>>();
            
            foreach (var parameter in endpoint.Parameters)
            {
                foreach (var payload in _payloads)
                {
                    var param = parameter; // Capture for closure
                    var pay = payload; // Capture for closure
                    
                    var task = Task.Run(async () =>
                    {
                        await _concurrencySemaphore.WaitAsync();
                        try
                        {
                            var result = await TestParameterWithXssPayloadAsync(url, endpoint.Method, param, pay);
                            
                            if (result.IsVulnerable)
                            {
                                var vulnerability = CreateXssVulnerability(endpoint, param, pay, result);
                                _logger.Warning("🚨 XSS found: {Method} {Path} parameter '{Parameter}' with payload '{Payload}'", 
                                    endpoint.Method, endpoint.Path, param.Name, pay.Payload);
                                return vulnerability;
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.Debug("Error testing {Parameter} with XSS payload {Payload}: {Error}", 
                                param.Name, pay.Payload, ex.Message);
                        }
                        finally
                        {
                            _concurrencySemaphore.Release();
                        }
                        return (Vulnerability?)null;
                    });
                    
                    staticPayloadTasks.Add(task);
                }
            }
            
            // Wait for all static payload tests to complete
            var staticResults = await Task.WhenAll(staticPayloadTasks);
            vulnerabilities.AddRange(staticResults.Where(v => v != null)!);
            
            // Report progress
            progressCallback?.Invoke(staticPayloadTasks.Count);

            // Step 2: Generate and test RAG-based payloads (context-aware)
            try
            {
                foreach (var parameter in endpoint.Parameters)
                {
                    // Determine context (HTML, attribute, or JavaScript)
                    var context = DetermineXssContext(endpoint, parameter);
                    
                    // Generate RAG payloads
                    var ragPayloads = await _ragGenerator.GenerateXssPayloadsAsync(
                        technology,
                        endpoint.Path,
                        context
                    );

                    _logger.Debug("Generated {Count} RAG XSS payloads for {Endpoint} parameter '{Parameter}' (context: {Context})",
                        ragPayloads.Count, endpoint.Path, parameter.Name, context);

                    // Test each RAG payload (PARALLELIZED for performance)
                    var ragPayloadTasks = new List<Task<Vulnerability?>>();
                    
                    foreach (var ragPayloadStr in ragPayloads)
                    {
                        // Skip if we already tested this payload
                        if (_payloads.Any(p => p.Payload == ragPayloadStr))
                            continue;

                        var ragPayload = new XssPayload
                        {
                            Type = DetermineXssTypeFromContext(context),
                            Payload = ragPayloadStr
                        };
                        
                        var param = parameter; // Capture for closure
                        var pay = ragPayload; // Capture for closure
                        var payStr = ragPayloadStr; // Capture for closure

                        var task = Task.Run(async () =>
                        {
                            await _concurrencySemaphore.WaitAsync();
                            try
                            {
                                var result = await TestParameterWithXssPayloadAsync(url, endpoint.Method, param, pay);
                                
                                if (result.IsVulnerable)
                                {
                                    var vulnerability = CreateXssVulnerability(endpoint, param, pay, result);
                                    vulnerability.Description = $"[RAG-Generated] {vulnerability.Description}";
                                    _logger.Warning("🚨 XSS found (RAG): {Method} {Path} parameter '{Parameter}' with payload '{Payload}'", 
                                        endpoint.Method, endpoint.Path, param.Name, payStr);
                                    return vulnerability;
                                }
                            }
                            catch (Exception ex)
                            {
                                _logger.Debug("Error testing RAG XSS payload {Payload}: {Error}", payStr, ex.Message);
                            }
                            finally
                            {
                                _concurrencySemaphore.Release();
                            }
                            return (Vulnerability?)null;
                        });
                        
                        ragPayloadTasks.Add(task);
                    }
                    
                    // Wait for all RAG payload tests to complete
                    var ragResults = await Task.WhenAll(ragPayloadTasks);
                    vulnerabilities.AddRange(ragResults.Where(v => v != null)!);
                    
                    // Report progress
                    progressCallback?.Invoke(ragPayloadTasks.Count);
                }
            }
            catch (Exception ex)
            {
                _logger.Warning(ex, "Error generating RAG XSS payloads for endpoint {Endpoint}", endpoint.Path);
            }

            // Step 3: If no parameters found, test with common parameter names
            if (!endpoint.Parameters.Any())
            {
                // Enhanced parameter names based on endpoint patterns
                var commonParams = GetParameterNamesForEndpoint(endpoint.Path);
                _logger.Debug("🔍 No parameters found for {Path}, testing with: {Params}", endpoint.Path, string.Join(", ", commonParams));
                
                // Test with static payloads (PARALLELIZED for performance)
                var commonParamTasks = new List<Task<Vulnerability?>>();
                
                foreach (var paramName in commonParams)
                {
                    foreach (var payload in _payloads.Take(10)) // Test with top 10 payloads
                    {
                        var pName = paramName; // Capture for closure
                        var pay = payload; // Capture for closure
                        
                        var task = Task.Run(async () =>
                        {
                            await _concurrencySemaphore.WaitAsync();
                            try
                            {
                                var result = await TestParameterWithXssPayloadAsync(url, endpoint.Method, 
                                    new ParameterInfo { Name = pName, Location = ParameterLocation.Query }, pay);
                                
                                if (result.IsVulnerable)
                                {
                                    var vulnerability = CreateXssVulnerability(endpoint, 
                                        new ParameterInfo { Name = pName, Location = ParameterLocation.Query }, pay, result);
                                    _logger.Warning("🚨 XSS found: {Method} {Path} parameter '{Parameter}' with payload '{Payload}'", 
                                        endpoint.Method, endpoint.Path, pName, pay.Payload);
                                    return vulnerability;
                                }
                            }
                            catch (Exception ex)
                            {
                                _logger.Debug("Error testing {Parameter} with XSS payload {Payload}: {Error}", 
                                    pName, pay.Payload, ex.Message);
                            }
                            finally
                            {
                                _concurrencySemaphore.Release();
                            }
                            return (Vulnerability?)null;
                        });
                        
                        commonParamTasks.Add(task);
                    }
                }
                
                // Wait for all common parameter tests to complete
                var commonParamResults = await Task.WhenAll(commonParamTasks);
                vulnerabilities.AddRange(commonParamResults.Where(v => v != null)!);
                
                // Report progress
                progressCallback?.Invoke(commonParamTasks.Count);

                // Test with RAG payloads for common parameters
                foreach (var paramName in commonParams)
                {
                    try
                    {
                        var context = "html"; // Default context
                        var ragPayloads = await _ragGenerator.GenerateXssPayloadsAsync(technology, endpoint.Path, context);
                        
                        // Test RAG payloads (PARALLELIZED for performance)
                        var commonRagTasks = new List<Task<Vulnerability?>>();
                        
                        foreach (var ragPayloadStr in ragPayloads.Take(10))
                        {
                            if (_payloads.Any(p => p.Payload == ragPayloadStr))
                                continue;

                            var ragPayload = new XssPayload
                            {
                                Type = XssType.Reflected,
                                Payload = ragPayloadStr
                            };
                            
                            var pName = paramName; // Capture for closure
                            var pay = ragPayload; // Capture for closure
                            var payStr = ragPayloadStr; // Capture for closure

                            var task = Task.Run(async () =>
                            {
                                await _concurrencySemaphore.WaitAsync();
                                try
                                {
                                    var result = await TestParameterWithXssPayloadAsync(url, endpoint.Method,
                                        new ParameterInfo { Name = pName, Location = ParameterLocation.Query }, pay);
                                    
                                    if (result.IsVulnerable)
                                    {
                                        var vulnerability = CreateXssVulnerability(endpoint,
                                            new ParameterInfo { Name = pName, Location = ParameterLocation.Query }, pay, result);
                                        vulnerability.Description = $"[RAG-Generated] {vulnerability.Description}";
                                        _logger.Warning("🚨 XSS found (RAG): {Method} {Path} parameter '{Parameter}' with payload '{Payload}'",
                                            endpoint.Method, endpoint.Path, pName, payStr);
                                        return vulnerability;
                                    }
                                }
                                catch (Exception ex)
                                {
                                    _logger.Debug("Error testing RAG XSS payload {Payload}: {Error}", payStr, ex.Message);
                                }
                                finally
                                {
                                    _concurrencySemaphore.Release();
                                }
                                return (Vulnerability?)null;
                            });
                            
                            commonRagTasks.Add(task);
                        }
                        
                        // Wait for all common RAG tests to complete
                        var commonRagResults = await Task.WhenAll(commonRagTasks);
                        vulnerabilities.AddRange(commonRagResults.Where(v => v != null)!);
                        
                        // Report progress
                        progressCallback?.Invoke(commonRagTasks.Count);
                    }
                    catch (Exception ex)
                    {
                        _logger.Debug("Error generating RAG payloads for parameter {Parameter}: {Error}", paramName, ex.Message);
                    }
                }
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Determines XSS context (HTML, attribute, or JavaScript) based on endpoint and parameter
        /// </summary>
        private string DetermineXssContext(EndpointInfo endpoint, ParameterInfo parameter)
        {
            var path = endpoint.Path.ToLower();
            var paramName = parameter.Name.ToLower();

            // Attribute context indicators
            if (paramName.Contains("href") || paramName.Contains("src") || paramName.Contains("url") || 
                paramName.Contains("link") || paramName.Contains("redirect"))
                return "attribute";

            // JavaScript context indicators
            if (paramName.Contains("callback") || paramName.Contains("jsonp") || 
                path.Contains("json") || path.Contains("api"))
                return "javascript";

            // Default to HTML context
            return "html";
        }

        /// <summary>
        /// Determines XSS type from context
        /// </summary>
        private XssType DetermineXssTypeFromContext(string context)
        {
            return context switch
            {
                "javascript" => XssType.Dom,
                _ => XssType.Reflected
            };
        }

        /// <summary>
        /// Gets appropriate parameter names based on endpoint path
        /// </summary>
        private string[] GetParameterNamesForEndpoint(string path)
        {
            var lowerPath = path.ToLower();
            
            // WebsiteTest-specific endpoints
            if (lowerPath.Contains("chatbot/chat"))
                return new[] { "message", "userMessage", "input", "text" };
            if (lowerPath.Contains("chatbot/recipe"))
                return new[] { "dessertName", "name", "dessert", "message", "userMessage" };
            if (lowerPath.Contains("spell-check/country"))
                return new[] { "country", "countryName", "name" };
            if (lowerPath.Contains("chatbot/history"))
                return new[] { "sessionId", "id" };
            
            // Generic patterns
            return lowerPath switch
            {
                var p when p.Contains("search") => new[] { "q", "search", "query", "term" },
                var p when p.Contains("comment") => new[] { "content", "comment", "message", "text" },
                var p when p.Contains("login") => new[] { "username", "password", "email" },
                var p when p.Contains("upload") => new[] { "file", "filename", "name" },
                var p when p.Contains("download") => new[] { "filename", "file", "path" },
                var p when p.Contains("list") => new[] { "path", "directory", "dir" },
                var p when p.Contains("user") => new[] { "userId", "id", "username" },
                var p when p.Contains("check") => new[] { "username", "email", "id" },
                var p when p.Contains("debug") => new[] { "level", "type", "info" },
                var p when p.Contains("chatbot") => new[] { "message", "userMessage", "dessertName", "input", "text" },
                _ => new[] { "search", "query", "q", "input", "text", "message", "comment", "name", "email", "id", "dessertName", "country", "userMessage" }
            };
        }

        /// <summary>
        /// Creates appropriate request body based on endpoint type
        /// </summary>
        private Dictionary<string, string> CreateRequestBodyForEndpoint(string url, string parameterName, string payload)
        {
            var lowerUrl = url.ToLower();
            
            // WebsiteTest-specific endpoints
            if (lowerUrl.Contains("chatbot/chat"))
            {
                return new Dictionary<string, string>
                {
                    { "message", parameterName == "message" || parameterName == "userMessage" ? payload : "test message" },
                    { "sessionId", Guid.NewGuid().ToString() }
                };
            }
            
            if (lowerUrl.Contains("chatbot/recipe"))
            {
                return new Dictionary<string, string>
                {
                    { "dessertName", parameterName == "dessertName" || parameterName == "name" ? payload : "cake" },
                    { "userMessage", parameterName == "userMessage" || parameterName == "message" ? payload : "recipe please" },
                    { "sessionId", Guid.NewGuid().ToString() }
                };
            }
            
            if (lowerUrl.Contains("spell-check/country"))
            {
                return new Dictionary<string, string>
                {
                    { "country", parameterName == "country" || parameterName == "countryName" ? payload : "USA" }
                };
            }
            
            // Generic patterns
            return lowerUrl switch
            {
                var u when u.Contains("add-comment") => new Dictionary<string, string>
                {
                    { "productId", "1" },
                    { "userId", "1" },
                    { "content", parameterName == "content" ? payload : "Test comment" }
                },
                var u when u.Contains("login") => new Dictionary<string, string>
                {
                    { "username", parameterName == "username" ? payload : "testuser" },
                    { "password", parameterName == "password" ? payload : "testpass" }
                },
                var u when u.Contains("check-username") => new Dictionary<string, string>
                {
                    { "username", payload }
                },
                var u when u.Contains("admin-login") => new Dictionary<string, string>
                {
                    { "username", parameterName == "username" ? payload : "admin" },
                    { "password", parameterName == "password" ? payload : "adminpass" }
                },
                _ => new Dictionary<string, string> { { parameterName, payload } }
            };
        }

        /// <summary>
        /// Tests a parameter with a specific XSS payload
        /// </summary>
        private async Task<XssTestResult> TestParameterWithXssPayloadAsync(string url, string method, ParameterInfo parameter, XssPayload payload)
        {
            var result = new XssTestResult
            {
                Parameter = parameter,
                Payload = payload,
                IsVulnerable = false,
                Confidence = 0.0
            };

            try
            {
                HttpResponse response;
                
                if (method.ToUpper() == "GET")
                {
                    // Fix URL construction for parameterized endpoints
                    var testUrl = url;
                    if (url.Contains("{"))
                    {
                        // Handle parameterized URLs like /api/vulnerable/comments/{id}
                        testUrl = url.Replace("{id}", "1").Replace("{productId}", "1").Replace("{userId}", "1");
                    }
                    testUrl = $"{testUrl}?{parameter.Name}={Uri.EscapeDataString(payload.Payload)}";
                    
                    _logger.Debug("🔍 Testing XSS GET request: {TestUrl}", testUrl);
                    response = await _httpClient.GetAsync(testUrl);
                    _logger.Debug("🔍 XSS GET response: {StatusCode} - Content length: {Length}", response.StatusCode, response.Content?.Length ?? 0);
                }
                else if (method.ToUpper() == "POST")
                {
                    // Enhanced POST request handling for different endpoint types
                    var requestBody = CreateRequestBodyForEndpoint(url, parameter.Name, payload.Payload);
                    var jsonBody = System.Text.Json.JsonSerializer.Serialize(requestBody);
                    response = await _httpClient.PostAsync(url, jsonBody);
                }
                else
                {
                    // Default to POST for other methods
                    var requestBody = new Dictionary<string, string> { { parameter.Name, payload.Payload } };
                    var jsonBody = System.Text.Json.JsonSerializer.Serialize(requestBody);
                    response = await _httpClient.PostAsync(url, jsonBody);
                }

                result.BaselineResponse = response;
                result.PayloadResponse = response;

                // Analyze response for XSS indicators
                if (IsReflectedXss(response, payload))
                {
                    result.IsVulnerable = true;
                    result.Confidence = CalculateXssConfidence(response, payload);
                    result.Evidence = ExtractXssEvidence(response, payload);
                }
            }
            catch (Exception ex)
            {
                _logger.Debug("Error testing XSS payload: {Error}", ex.Message);
            }

            return result;
        }

        /// <summary>
        /// Checks for reflected XSS (works for both HTML and JSON responses)
        /// </summary>
        private bool IsReflectedXss(HttpResponse response, XssPayload payload)
        {
            // Check if payload is reflected in response
            if (!response.Content.Contains(payload.Payload, StringComparison.OrdinalIgnoreCase))
                return false;

            // For JSON responses: payload reflection = vulnerability (frontend will render it)
            if (IsJsonResponse(response))
            {
                // Check if payload appears in JSON field values (not just keys)
                if (IsPayloadInJsonValue(response.Content, payload.Payload))
                {
                    return true; // JSON reflection = XSS vulnerability
                }
            }

            // For HTML responses: check for script execution context
            return ContainsScriptExecution(response.Content, payload);
        }

        /// <summary>
        /// Checks if response is JSON
        /// </summary>
        private bool IsJsonResponse(HttpResponse response)
        {
            var contentType = response.Headers.ContainsKey("Content-Type") 
                ? response.Headers["Content-Type"] 
                : "";
            
            return contentType.Contains("application/json", StringComparison.OrdinalIgnoreCase) ||
                   (response.Content?.TrimStart().StartsWith("{") == true) ||
                   (response.Content?.TrimStart().StartsWith("[") == true);
        }

        /// <summary>
        /// Checks if payload appears as a JSON value (indicating reflection)
        /// </summary>
        private bool IsPayloadInJsonValue(string jsonContent, string payload)
        {
            try
            {
                // Check if payload appears in JSON string values
                // Pattern: "fieldName": "payload" or "fieldName": "prefixpayloadsuffix"
                var escapedPayload = System.Text.Json.JsonSerializer.Serialize(payload);
                escapedPayload = escapedPayload.Trim('"'); // Remove quotes from serialization
                
                // Check for payload in JSON value context (after colon)
                var patterns = new[]
                {
                    $":\\s*\"[^\"]*{Regex.Escape(escapedPayload)}[^\"]*\"",  // In quoted string value
                    $":\\s*'[^']*{Regex.Escape(escapedPayload)}[^']*'",     // In single-quoted value
                    $":\\s*{Regex.Escape(escapedPayload)}",                  // Direct value
                };

                foreach (var pattern in patterns)
                {
                    if (Regex.IsMatch(jsonContent, pattern, RegexOptions.IgnoreCase))
                        return true;
                }

                // Also check if payload appears unescaped in JSON (common vulnerability)
                if (jsonContent.Contains(payload, StringComparison.OrdinalIgnoreCase))
                {
                    // Verify it's in a value position (after colon)
                    var payloadIndex = jsonContent.IndexOf(payload, StringComparison.OrdinalIgnoreCase);
                    if (payloadIndex > 0)
                    {
                        var beforePayload = jsonContent.Substring(Math.Max(0, payloadIndex - 100), Math.Min(100, payloadIndex));
                        // Check if there's a colon before the payload (JSON value)
                        if (beforePayload.Contains(":"))
                            return true;
                    }
                }
            }
            catch
            {
                // Fallback: if payload is in response and it's JSON, consider it vulnerable
                if (jsonContent.Contains(payload, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Checks for DOM XSS
        /// </summary>
        private bool IsDomXss(HttpResponse response, XssPayload payload)
        {
            // DOM XSS indicators in JavaScript
            var domPatterns = new[]
            {
                "document\\.write",
                "innerHTML",
                "outerHTML",
                "eval\\(",
                "setTimeout\\(",
                "setInterval\\("
            };

            foreach (var pattern in domPatterns)
            {
                if (Regex.IsMatch(response.Content, pattern, RegexOptions.IgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Checks if response contains script execution indicators
        /// </summary>
        private bool ContainsScriptExecution(string content, XssPayload payload)
        {
            // Check for script tags
            if (payload.Payload.Contains("<script>") && content.Contains("<script>"))
                return true;

            // Check for event handlers
            var eventHandlers = new[] { "onclick", "onload", "onerror", "onmouseover" };
            foreach (var handler in eventHandlers)
            {
                if (payload.Payload.Contains(handler) && content.Contains(handler))
                    return true;
            }

            // Check for JavaScript functions
            var jsFunctions = new[] { "alert(", "confirm(", "prompt(", "eval(" };
            foreach (var func in jsFunctions)
            {
                if (payload.Payload.Contains(func) && content.Contains(func))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Checks if payload is encoded or escaped
        /// </summary>
        private bool IsEncodedOrEscaped(string content, XssPayload payload)
        {
            // Check for HTML encoding
            if (payload.Payload.Contains("<") && content.Contains("&lt;"))
                return true;

            // Check for URL encoding
            if (payload.Payload.Contains(" ") && content.Contains("%20"))
                return true;

            // Check for JavaScript escaping
            if (payload.Payload.Contains("\"") && content.Contains("\\\""))
                return true;

            return false;
        }

        /// <summary>
        /// Calculates confidence level for XSS detection
        /// </summary>
        private double CalculateXssConfidence(HttpResponse response, XssPayload payload)
        {
            var confidence = 0.0;

            // Base confidence for payload reflection
            if (response.Content.Contains(payload.Payload))
                confidence += 0.3;

            // Higher confidence for script execution
            if (ContainsScriptExecution(response.Content, payload))
                confidence += 0.4;

            // DOM XSS indicators
            if (IsDomXss(response, payload))
                confidence += 0.2;

            // Lower confidence if encoded/escaped
            if (IsEncodedOrEscaped(response.Content, payload))
                confidence -= 0.2;

            return Math.Max(0.0, Math.Min(1.0, confidence));
        }

        /// <summary>
        /// Extracts evidence of XSS vulnerability
        /// </summary>
        private string ExtractXssEvidence(HttpResponse response, XssPayload payload)
        {
            var evidence = new List<string>();

            if (response.Content.Contains(payload.Payload))
                evidence.Add($"Payload '{payload.Payload}' reflected in response");

            if (ContainsScriptExecution(response.Content, payload))
                evidence.Add("Script execution indicators found");

            if (IsDomXss(response, payload))
                evidence.Add("DOM manipulation indicators found");

            return string.Join("; ", evidence);
        }

        /// <summary>
        /// Creates a vulnerability object from XSS test result
        /// </summary>
        private Vulnerability CreateXssVulnerability(EndpointInfo endpoint, ParameterInfo parameter, XssPayload payload, XssTestResult result)
        {
            var xssType = DetermineXssType(endpoint, payload);
            
            return new Vulnerability
            {
                Type = xssType,
                Severity = DetermineXssSeverity(result.Confidence),
                Title = $"Cross-Site Scripting (XSS) in {endpoint.Method} {endpoint.Path}",
                Description = $"The application is vulnerable to {xssType.ToString().ToLower()} XSS through the '{parameter.Name}' parameter. This could allow attackers to execute malicious scripts in users' browsers.",
                Endpoint = endpoint.Path,
                Method = endpoint.Method,
                Parameter = parameter.Name,
                Payload = payload.Payload,
                Response = result.PayloadResponse?.Content,
                Evidence = result.Evidence,
                Remediation = GetXssRemediation(xssType),
                AttackMode = AttackMode.Aggressive,
                Confidence = result.Confidence,
                Verified = result.Confidence > 0.8
            };
        }

        /// <summary>
        /// Determines XSS severity based on confidence
        /// </summary>
        private SeverityLevel DetermineXssSeverity(double confidence)
        {
            if (confidence >= 0.9) return SeverityLevel.Critical;
            if (confidence >= 0.7) return SeverityLevel.High;
            if (confidence >= 0.5) return SeverityLevel.Medium;
            return SeverityLevel.Low;
        }

        /// <summary>
        /// Gets remediation advice for XSS
        /// </summary>
        private string GetXssRemediation(VulnerabilityType xssType)
        {
            return xssType switch
            {
                VulnerabilityType.ReflectedXss => "🔒 RECOMMENDED FIX: Implement proper output encoding for reflected XSS prevention.\n\n" +
                                                "❌ VULNERABLE CODE:\n" +
                                                "return Content(\"<h1>Hello \" + userInput + \"</h1>\");\n" +
                                                "// or\n" +
                                                "@Html.Raw(Model.UserInput)\n\n" +
                                                "✅ SECURE CODE:\n" +
                                                "return Content(\"<h1>Hello \" + HttpUtility.HtmlEncode(userInput) + \"</h1>\");\n" +
                                                "// or\n" +
                                                "@Html.Encode(Model.UserInput)\n" +
                                                "// or\n" +
                                                "@Model.UserInput // Razor automatically encodes\n\n" +
                                                "📋 ADDITIONAL MEASURES:\n" +
                                                "• Always encode user input before displaying\n" +
                                                "• Use Content Security Policy (CSP) headers\n" +
                                                "• Validate and sanitize all user input\n" +
                                                "• Use parameterized queries for database operations\n" +
                                                "• Implement proper input validation with whitelist approach",

                VulnerabilityType.StoredXss => "🔒 RECOMMENDED FIX: Implement proper output encoding for stored XSS prevention.\n\n" +
                                             "❌ VULNERABLE CODE:\n" +
                                             "// Storing without validation\n" +
                                             "var comment = new Comment { Content = userInput };\n" +
                                             "await _context.Comments.AddAsync(comment);\n" +
                                             "// Displaying without encoding\n" +
                                             "@Html.Raw(comment.Content)\n\n" +
                                             "✅ SECURE CODE:\n" +
                                             "// Validate and sanitize before storing\n" +
                                             "var sanitizedInput = HttpUtility.HtmlEncode(userInput);\n" +
                                             "var comment = new Comment { Content = sanitizedInput };\n" +
                                             "await _context.Comments.AddAsync(comment);\n" +
                                             "// Always encode when displaying\n" +
                                             "@Html.Encode(comment.Content)\n" +
                                             "// or\n" +
                                             "@comment.Content // Razor automatically encodes\n\n" +
                                             "📋 ADDITIONAL MEASURES:\n" +
                                             "• Sanitize input before database storage\n" +
                                             "• Always encode output when displaying\n" +
                                             "• Use Content Security Policy (CSP) headers\n" +
                                             "• Implement proper input validation\n" +
                                             "• Consider using HTML sanitization libraries (HtmlSanitizer)",

                VulnerabilityType.DomXss => "🔒 RECOMMENDED FIX: Implement proper client-side validation and encoding for DOM XSS prevention.\n\n" +
                                          "❌ VULNERABLE CODE:\n" +
                                          "// JavaScript - dangerous innerHTML usage\n" +
                                          "document.getElementById('output').innerHTML = userInput;\n" +
                                          "// jQuery - dangerous HTML injection\n" +
                                          "$('#output').html(userInput);\n\n" +
                                          "✅ SECURE CODE:\n" +
                                          "// JavaScript - safe text content\n" +
                                          "document.getElementById('output').textContent = userInput;\n" +
                                          "// jQuery - safe text content\n" +
                                          "$('#output').text(userInput);\n" +
                                          "// If HTML is needed, sanitize first\n" +
                                          "const sanitized = DOMPurify.sanitize(userInput);\n" +
                                          "document.getElementById('output').innerHTML = sanitized;\n\n" +
                                          "📋 ADDITIONAL MEASURES:\n" +
                                          "• Use textContent instead of innerHTML\n" +
                                          "• Implement Content Security Policy (CSP)\n" +
                                          "• Use HTML sanitization libraries (DOMPurify)\n" +
                                          "• Validate all client-side input\n" +
                                          "• Avoid eval() and similar dangerous functions",

                _ => "🔒 RECOMMENDED FIX: Implement comprehensive XSS prevention measures.\n\n" +
                     "❌ VULNERABLE CODE:\n" +
                     "// Any direct user input display without encoding\n" +
                     "@Html.Raw(Model.UserInput)\n" +
                     "document.getElementById('output').innerHTML = userInput;\n\n" +
                     "✅ SECURE CODE:\n" +
                     "// Server-side encoding\n" +
                     "@Html.Encode(Model.UserInput)\n" +
                     "@Model.UserInput // Razor automatically encodes\n" +
                     "// Client-side encoding\n" +
                     "document.getElementById('output').textContent = userInput;\n\n" +
                     "📋 COMPREHENSIVE MEASURES:\n" +
                     "• Always encode user input before displaying\n" +
                     "• Implement Content Security Policy (CSP) headers\n" +
                     "• Validate and sanitize all user input\n" +
                     "• Use parameterized queries for database operations\n" +
                     "• Implement proper input validation with whitelist approach\n" +
                     "• Use HTML sanitization libraries when needed\n" +
                     "• Avoid dangerous JavaScript functions (eval, innerHTML)"
            };
        }

        /// <summary>
        /// Determines if an endpoint is testable for XSS
        /// </summary>
        private bool IsTestableEndpoint(EndpointInfo endpoint)
        {
            // Skip non-HTML endpoints
            if (endpoint.Path.EndsWith(".js") || endpoint.Path.EndsWith(".css") || endpoint.Path.EndsWith(".png") || 
                endpoint.Path.EndsWith(".jpg") || endpoint.Path.EndsWith(".gif") || endpoint.Path.EndsWith(".ico"))
                return false;

            // Skip API endpoints that are known to return JSON only (not HTML)
            // BUT include endpoints that might return HTML like search, comments
            var jsonOnlyEndpoints = new[] { "search-products", "user-products", "login", "admin-login", "upload-file", "download-file", "list-files", "debug-info", "check-user" };
            var htmlEndpoints = new[] { "search", "comments", "add-comment" }; // These might return HTML
            
            if (endpoint.Path.StartsWith("/api/") && jsonOnlyEndpoints.Any(ep => endpoint.Path.Contains(ep)) && 
                !htmlEndpoints.Any(ep => endpoint.Path.Contains(ep)))
                return false;

            // Test all other endpoints including API endpoints that might return HTML
            return true;
        }

        /// <summary>
        /// Determines the type of XSS vulnerability
        /// </summary>
        private VulnerabilityType DetermineXssType(EndpointInfo endpoint, XssPayload payload)
        {
            if (payload.Type == XssType.Stored)
                return VulnerabilityType.StoredXss;
            else if (payload.Type == XssType.Dom)
                return VulnerabilityType.DomXss;
            else
                return VulnerabilityType.ReflectedXss;
        }

        /// <summary>
        /// Initializes XSS payloads
        /// </summary>
        private List<XssPayload> InitializeXssPayloads()
        {
            return new List<XssPayload>
            {
                // Basic XSS payloads
                new XssPayload { Type = XssType.Reflected, Payload = "<script>alert('XSS')</script>" },
                new XssPayload { Type = XssType.Reflected, Payload = "<img src=x onerror=alert('XSS')>" },
                new XssPayload { Type = XssType.Reflected, Payload = "<svg onload=alert('XSS')>" },
                new XssPayload { Type = XssType.Reflected, Payload = "javascript:alert('XSS')" },
                new XssPayload { Type = XssType.Reflected, Payload = "<iframe src=javascript:alert('XSS')></iframe>" },
                
                // Event handler payloads
                new XssPayload { Type = XssType.Reflected, Payload = "<body onload=alert('XSS')>" },
                new XssPayload { Type = XssType.Reflected, Payload = "<input onfocus=alert('XSS') autofocus>" },
                new XssPayload { Type = XssType.Reflected, Payload = "<select onfocus=alert('XSS') autofocus>" },
                new XssPayload { Type = XssType.Reflected, Payload = "<textarea onfocus=alert('XSS') autofocus>" },
                new XssPayload { Type = XssType.Reflected, Payload = "<keygen onfocus=alert('XSS') autofocus>" },
                
                // Media payloads
                new XssPayload { Type = XssType.Reflected, Payload = "<video><source onerror=alert('XSS')>" },
                new XssPayload { Type = XssType.Reflected, Payload = "<audio src=x onerror=alert('XSS')>" },
                new XssPayload { Type = XssType.Reflected, Payload = "<details open ontoggle=alert('XSS')>" },
                
                // Stored XSS payloads
                new XssPayload { Type = XssType.Stored, Payload = "<script>alert('Stored XSS')</script>" },
                new XssPayload { Type = XssType.Stored, Payload = "<img src=x onerror=alert('Stored XSS')>" },
                
                // DOM XSS payloads
                new XssPayload { Type = XssType.Dom, Payload = "javascript:alert('DOM XSS')" },
                new XssPayload { Type = XssType.Dom, Payload = "#<script>alert('DOM XSS')</script>" }
            };
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _httpClient?.Dispose();
                _ragGenerator?.Dispose();
                _concurrencySemaphore?.Dispose();
                _disposed = true;
            }
        }
    }

    /// <summary>
    /// XSS payload definition
    /// </summary>
    public class XssPayload
    {
        public XssType Type { get; set; }
        public string Payload { get; set; } = string.Empty;
    }

    /// <summary>
    /// XSS type enumeration
    /// </summary>
    public enum XssType
    {
        Reflected,
        Stored,
        Dom
    }

    /// <summary>
    /// XSS test result
    /// </summary>
    public class XssTestResult
    {
        public ParameterInfo Parameter { get; set; } = new();
        public XssPayload Payload { get; set; } = new();
        public bool IsVulnerable { get; set; }
        public double Confidence { get; set; }
        public string Evidence { get; set; } = string.Empty;
        public HttpResponse? BaselineResponse { get; set; }
        public HttpResponse? PayloadResponse { get; set; }
    }
} 
