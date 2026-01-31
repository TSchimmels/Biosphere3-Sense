using System.Text.RegularExpressions;
using AttackAgent.Models;
using AttackAgent.Services;
using Serilog;
using System.Net;
using System.Text.Json;

namespace AttackAgent
{
    /// <summary>
    /// Scans the target application to discover endpoints, technologies, and security features
    /// </summary>
    public class ApplicationScanner
    {
        private readonly SecurityHttpClient _httpClient;
        private readonly ILogger _logger;
        private readonly List<string> _commonPaths;
        private readonly List<string> _commonApiPaths;
        private readonly WordlistManager _wordlistManager;

        public ApplicationScanner(string baseUrl = "")
        {
            _httpClient = new SecurityHttpClient(baseUrl);
            _logger = Log.ForContext<ApplicationScanner>();
            _wordlistManager = new WordlistManager();
            
            // Common web application paths to test
            _commonPaths = new List<string>
            {
                "/",
                "/index.html",
                "/home",
                "/about",
                "/contact",
                "/login",
                "/register",
                "/admin",
                "/dashboard",
                "/api",
                "/api/v1",
                "/api/v2",
                "/swagger",
                "/swagger/index.html",
                "/docs",
                "/health",
                "/status",
                "/robots.txt",
                "/sitemap.xml",
                "/favicon.ico",
                "/.well-known/security.txt",
                "/.env",
                "/config",
                "/backup",
                "/test",
                "/debug"
            };

            // Common API endpoints
            _commonApiPaths = new List<string>
            {
                "/api/users",
                "/api/auth",
                "/api/login",
                "/api/register",
                "/api/profile",
                "/api/admin",
                "/api/health",
                "/api/status",
                "/api/version",
                "/api/info",
                "/api/config",
                "/api/test",
                "/api/debug"
            };
        }

        /// <summary>
        /// Performs a comprehensive scan of the target application
        /// </summary>
        public async Task<ApplicationProfile> ScanApplicationAsync(string baseUrl, string? sourceCodePath = null)
        {
            var startTime = DateTime.UtcNow;
            _logger.Information("Starting application scan for {BaseUrl}", baseUrl);
            
            if (!string.IsNullOrEmpty(sourceCodePath))
            {
                _logger.Information("📄 Source code path provided: {Path}", sourceCodePath);
            }

            var profile = new ApplicationProfile
            {
                BaseUrl = baseUrl,
                DiscoveryTimestamp = startTime
            };

            try
            {
                // Step 1: Basic connectivity test
                _logger.Information("Testing basic connectivity...");
                if (!await _httpClient.IsAccessibleAsync(baseUrl))
                {
                    _logger.Error("Target application is not accessible at {BaseUrl}", baseUrl);
                    profile.RiskLevel = RiskLevel.Critical;
                    return profile;
                }

                // Step 1.5: Detect application name
                _logger.Information("Detecting application name...");
                await DetectApplicationNameAsync(profile);

                // Step 2: Discover endpoints (with source code if available)
                _logger.Information("Discovering endpoints...");
                await DiscoverEndpointsAsync(profile, sourceCodePath);

                // Step 3: Analyze technology stack
                _logger.Information("Analyzing technology stack...");
                await AnalyzeTechnologyStackAsync(profile);
                
                // Enhanced technology detection
                await AnalyzeEnhancedTechnologyStackAsync(profile);
                
                // Static file discovery
                await DiscoverStaticFilesAsync(profile);

                // Configuration file scanning
                await ScanConfigurationFilesAsync(profile);

                // Step 4: Detect security features
                _logger.Information("Detecting security features...");
                await DetectSecurityFeaturesAsync(profile);

                // Step 5: Analyze authentication system
                _logger.Information("Analyzing authentication system...");
                await AnalyzeAuthenticationSystemAsync(profile);

                // Step 6: Calculate risk level
                CalculateRiskLevel(profile);

                profile.ScanDuration = DateTime.UtcNow - startTime;
                _logger.Information("Application scan completed in {Duration}ms. Found {EndpointCount} endpoints", 
                    profile.ScanDuration.TotalMilliseconds, profile.TotalEndpoints);

                return profile;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error during application scan");
                profile.ScanDuration = DateTime.UtcNow - startTime;
                return profile;
            }
        }

        /// <summary>
        /// Discovers endpoints by testing common paths and analyzing responses
        /// </summary>
        private async Task DiscoverEndpointsAsync(ApplicationProfile profile, string? sourceCodePath = null)
        {
            var discoveredEndpoints = new List<EndpointInfo>();
            var baseUrl = profile.BaseUrl;

            // PHASE 1: Source Code Analysis (if available) - HIGHEST PRIORITY
            if (!string.IsNullOrEmpty(sourceCodePath))
            {
                _logger.Information("📄 Phase 1: Source Code Analysis");
                _logger.Information("=====================================");
                
                try
                {
                    var sourceCodeParser = new Engines.SourceCodeParser();
                    var codeEndpoints = await sourceCodeParser.ParseSourceCodeAsync(sourceCodePath);
                    
                    if (codeEndpoints.Any())
                    {
                        _logger.Information("✅ Found {Count} endpoints from source code", codeEndpoints.Count);
                        foreach (var endpoint in codeEndpoints)
                        {
                            _logger.Debug("  📍 {Method} {Path} (from {Source})", endpoint.Method, endpoint.Path, endpoint.Source ?? "source code");
                        }
                        
                        // Verify endpoints exist in production (test them)
                        foreach (var endpoint in codeEndpoints)
                        {
                            var fullUrl = baseUrl.TrimEnd('/') + endpoint.Path;
                            var verifiedEndpoint = await TestEndpointAsync(fullUrl, endpoint.Method);
                            
                            if (verifiedEndpoint != null)
                            {
                                // Merge source code info with runtime info
                                verifiedEndpoint.Parameters = endpoint.Parameters.Any() ? endpoint.Parameters : verifiedEndpoint.Parameters;
                                verifiedEndpoint.Source = endpoint.Source ?? "source code";
                                verifiedEndpoint.IsParameterized = endpoint.IsParameterized;
                                verifiedEndpoint.ParameterName = endpoint.ParameterName;
                                
                                if (!discoveredEndpoints.Any(e => e.Path == endpoint.Path && e.Method == endpoint.Method))
                                {
                                    discoveredEndpoints.Add(verifiedEndpoint);
                                }
                            }
                            else
                            {
                                // Endpoint from source code but not accessible in production
                                _logger.Warning("⚠️ Endpoint from source code not accessible in production: {Method} {Path}", 
                                    endpoint.Method, endpoint.Path);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, "Error parsing source code");
                }
            }

            // PHASE 2: Black-Box Discovery (always run)
            _logger.Information("🌐 Phase 2: Black-Box Discovery");
            _logger.Information("=====================================");

            // Step 2.1: Test original common paths (for backward compatibility)
            _logger.Information("Testing {Count} common paths...", _commonPaths.Count);
            foreach (var path in _commonPaths)
            {
                var url = baseUrl.TrimEnd('/') + path;
                var endpoint = await TestEndpointAsync(url, "GET");
                if (endpoint != null && !discoveredEndpoints.Any(e => e.Path == endpoint.Path && e.Method == endpoint.Method))
                {
                    endpoint.Source = "black-box discovery";
                    discoveredEndpoints.Add(endpoint);
                }
            }

            // Step 2.2: Test wordlist-based directory discovery
            _logger.Information("Testing wordlist-based directory discovery...");
            var detectedTech = profile.TechnologyStack?.Framework;
            var directoryWordlist = _wordlistManager.GetDirectoryWordlist(detectedTech);
            _logger.Information("Using {Count} directory wordlist entries", directoryWordlist.Count);

            // Use parallel processing for large wordlists (but limit concurrency)
            var semaphore = new SemaphoreSlim(10); // Max 10 concurrent requests
            var tasks = directoryWordlist.Select(async path =>
            {
                await semaphore.WaitAsync();
                try
                {
                    var url = baseUrl.TrimEnd('/') + path;
                    var endpoint = await TestEndpointAsync(url, "GET");
                    if (endpoint != null)
                    {
                        return endpoint;
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Error testing path: {Path}", path);
                }
                finally
                {
                    semaphore.Release();
                }
                return null;
            });

            var wordlistEndpoints = (await Task.WhenAll(tasks))
                .Where(e => e != null)
                .Where(e => !discoveredEndpoints.Any(ex => ex.Path == e.Path && e.Method == ex.Method))
                .ToList();

            foreach (var endpoint in wordlistEndpoints)
            {
                endpoint.Source = "wordlist discovery";
                discoveredEndpoints.Add(endpoint);
            }

            _logger.Information("✅ Wordlist discovery found {Count} new endpoints", wordlistEndpoints.Count);

            // Step 2.3: Test file wordlist
            _logger.Information("Testing file wordlist...");
            var fileWordlist = _wordlistManager.GetFileWordlist();
            foreach (var file in fileWordlist)
            {
                var url = baseUrl.TrimEnd('/') + "/" + file.TrimStart('/');
                var endpoint = await TestEndpointAsync(url, "GET");
                if (endpoint != null && !discoveredEndpoints.Any(e => e.Path == endpoint.Path && e.Method == endpoint.Method))
                {
                    endpoint.Source = "file wordlist";
                    discoveredEndpoints.Add(endpoint);
                }
            }

            // Step 2.4: Test API wordlist (enhanced)
            _logger.Information("Testing enhanced API wordlist...");
            var apiWordlist = _wordlistManager.GetApiWordlist();
            // Combine with existing _commonApiPaths
            var allApiPaths = _commonApiPaths.Concat(apiWordlist).Distinct().ToList();

            foreach (var path in allApiPaths)
            {
                var url = baseUrl.TrimEnd('/') + path;
                
                // Test GET
                var endpoint = await TestEndpointAsync(url, "GET");
                if (endpoint != null && !discoveredEndpoints.Any(e => e.Path == endpoint.Path && e.Method == endpoint.Method))
                {
                    endpoint.Source = "api wordlist";
                    discoveredEndpoints.Add(endpoint);
                }

                // Test POST
                endpoint = await TestEndpointAsync(url, "POST");
                if (endpoint != null && !discoveredEndpoints.Any(e => e.Path == endpoint.Path && e.Method == endpoint.Method))
                {
                    endpoint.Source = "api wordlist";
                    discoveredEndpoints.Add(endpoint);
                }
            }

            // Swagger/OpenAPI discovery - parse API documentation
            var swaggerParser = new SwaggerParser(baseUrl);
            var swaggerEndpoints = await swaggerParser.DiscoverEndpointsFromSwaggerAsync(baseUrl);
            var verifiedSwaggerEndpoints = await swaggerParser.TestDiscoveredEndpointsAsync(swaggerEndpoints, baseUrl);
            foreach (var endpoint in verifiedSwaggerEndpoints)
            {
                if (!discoveredEndpoints.Any(e => e.Path == endpoint.Path && e.Method == endpoint.Method))
                {
                    endpoint.Source = "swagger/openapi";
                    discoveredEndpoints.Add(endpoint);
                }
            }
            swaggerParser.Dispose();

            // Enhanced API discovery - test comprehensive API patterns
            var enhancedApiEndpoints = await DiscoverEnhancedApiEndpointsAsync(baseUrl);
            foreach (var endpoint in enhancedApiEndpoints)
            {
                if (!discoveredEndpoints.Any(e => e.Path == endpoint.Path && e.Method == endpoint.Method))
                {
                    endpoint.Source = "enhanced discovery";
                    discoveredEndpoints.Add(endpoint);
                }
            }

            // Analyze the main page for additional endpoints
            var mainResponse = await _httpClient.GetAsync(baseUrl);
            if (mainResponse.Success)
            {
                var additionalEndpoints = ExtractEndpointsFromContent(mainResponse.Content, baseUrl);
                foreach (var endpoint in additionalEndpoints)
                {
                    if (!discoveredEndpoints.Any(e => e.Path == endpoint))
                    {
                        var endpointInfo = await TestEndpointAsync(endpoint, "GET");
                        if (endpointInfo != null && !discoveredEndpoints.Any(e => e.Path == endpointInfo.Path && e.Method == endpointInfo.Method))
                        {
                            endpointInfo.Source = "HTML analysis";
                            discoveredEndpoints.Add(endpointInfo);
                        }
                    }
                }
            }

            profile.DiscoveredEndpoints = discoveredEndpoints.DistinctBy(e => new { e.Path, e.Method }).ToList();
            
            _logger.Information("✅ Endpoint discovery completed. Found {Count} total endpoints", profile.DiscoveredEndpoints.Count);
            _logger.Information("  📊 From source code: {SourceCount}", 
                profile.DiscoveredEndpoints.Count(e => e.Source?.Contains("source code") == true || e.Source?.Contains("Program.cs") == true || e.Source?.Contains("Startup.cs") == true));
            _logger.Information("  📊 From black-box: {BlackBoxCount}", 
                profile.DiscoveredEndpoints.Count(e => e.Source?.Contains("black-box") == true || e.Source?.Contains("enhanced") == true));
            _logger.Information("  📊 From wordlist: {WordlistCount}", 
                profile.DiscoveredEndpoints.Count(e => e.Source?.Contains("wordlist") == true));
        }

        /// <summary>
        /// Tests a specific endpoint and returns endpoint information
        /// </summary>
        private async Task<EndpointInfo?> TestEndpointAsync(string url, string method)
        {
            try
            {
                HttpResponse response;
                
                switch (method.ToUpper())
                {
                    case "GET":
                        response = await _httpClient.GetAsync(url);
                        break;
                    case "POST":
                        response = await _httpClient.PostAsync(url, "{}");
                        break;
                    case "PUT":
                        response = await _httpClient.PutAsync(url, "{}");
                        break;
                    case "DELETE":
                        response = await _httpClient.DeleteAsync(url);
                        break;
                    case "PATCH":
                        response = await _httpClient.PatchAsync(url, "{}");
                        break;
                    case "HEAD":
                        response = await _httpClient.HeadAsync(url);
                        break;
                    case "OPTIONS":
                        response = await _httpClient.OptionsAsync(url);
                        break;
                    default:
                        return null;
                }

                // Only include endpoints that return meaningful responses
                if (response.StatusCode == HttpStatusCode.NotFound || 
                    response.StatusCode == HttpStatusCode.MethodNotAllowed)
                {
                    return null;
                }

                // Enhanced endpoint validation: Reject error pages and false positives
                if (!IsValidEndpoint(response))
                {
                    _logger.Debug("Rejecting endpoint {Url} - appears to be error page or invalid response", url);
                    return null;
                }

                var uri = new Uri(url);
                var path = uri.AbsolutePath;

                var endpoint = new EndpointInfo
                {
                    Path = path,
                    Method = method,
                    StatusCode = (int)response.StatusCode,
                    ResponseTime = response.ResponseTime,
                    ResponseHeaders = response.Headers,
                    RequiresAuthentication = IsAuthenticationRequired(response),
                    PotentialVulnerabilities = AnalyzePotentialVulnerabilities(response)
                };

                // Extract parameters from the response if it's an API endpoint
                if (IsApiEndpoint(response))
                {
                    endpoint.Parameters = ExtractParametersFromResponse(response);
                }

                return endpoint;
            }
            catch (Exception ex)
            {
                _logger.Debug("Error testing endpoint {Url}: {Error}", url, ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Validates if an endpoint response is actually a valid endpoint (not an error page)
        /// </summary>
        private bool IsValidEndpoint(HttpResponse response)
        {
            // Reject if response is too small (error pages are usually small)
            if (response.ContentLength < 100)
            {
                return false;
            }

            // Reject if response contains common error indicators
            var content = response.Content?.ToLowerInvariant() ?? "";
            
            // Common error page indicators
            var errorIndicators = new[]
            {
                "404",
                "not found",
                "page not found",
                "resource not found",
                "endpoint not found",
                "route not found",
                "the requested resource was not found",
                "error",
                "error occurred",
                "an error occurred",
                "internal server error",
                "bad request",
                "unauthorized",
                "forbidden",
                "method not allowed",
                "invalid",
                "invalid request",
                "invalid endpoint",
                "no route matched",
                "no matching route",
                "route does not exist",
                "endpoint does not exist",
                "api endpoint not found",
                "invalid api endpoint",
                "the page you are looking for",
                "the page cannot be found",
                "this page doesn't exist",
                "we couldn't find that page",
                "sorry, we couldn't find that page"
            };

            // Check if content contains error indicators (but allow if it's a valid error response structure)
            // Only reject if it's clearly an HTML error page or generic error message
            foreach (var indicator in errorIndicators)
            {
                if (content.Contains(indicator))
                {
                    // Additional check: If it's a JSON error response with proper structure, allow it
                    // (some APIs return {"error": "Not found"} which is valid)
                    if (content.TrimStart().StartsWith("{") && content.Contains("\"error\"") && content.Length < 500)
                    {
                        // This might be a valid API error response, but if it's too generic, reject it
                        // Most valid API error responses have more context
                        if (content.Length < 200)
                        {
                            return false; // Too small and generic, likely not a real endpoint
                        }
                        // Otherwise allow it - might be a real endpoint that returns errors
                    }
                    else if (content.Contains("<html") || content.Contains("<!doctype"))
                    {
                        // HTML error page - definitely reject
                        return false;
                    }
                    else if (content.Length < 300)
                    {
                        // Small text error message - reject
                        return false;
                    }
                }
            }

            // Reject if response is just whitespace or very minimal
            if (string.IsNullOrWhiteSpace(content) || content.Trim().Length < 50)
            {
                return false;
            }

            // Reject common default/placeholder responses
            var placeholderIndicators = new[]
            {
                "welcome to nginx",
                "apache http server",
                "it works!",
                "default page",
                "test page",
                "hello world",
                "placeholder"
            };

            foreach (var placeholder in placeholderIndicators)
            {
                if (content.Contains(placeholder) && content.Length < 500)
                {
                    return false; // Likely a default server page, not a real endpoint
                }
            }

            // If we get here, the endpoint appears valid
            return true;
        }

        /// <summary>
        /// Analyzes the technology stack based on response headers and content
        /// </summary>
        private async Task AnalyzeTechnologyStackAsync(ApplicationProfile profile)
        {
            var techStack = new TechnologyStack();
            var mainResponse = await _httpClient.GetAsync(profile.BaseUrl);

            if (!mainResponse.Success)
            {
                profile.TechnologyStack = techStack;
                return;
            }

            // Analyze headers for technology indicators
            AnalyzeHeadersForTechnology(mainResponse.Headers, techStack);

            // Analyze content for technology indicators
            AnalyzeContentForTechnology(mainResponse.Content, techStack);

            // Analyze specific endpoints for additional technology info
            await AnalyzeEndpointsForTechnologyAsync(profile, techStack);

            profile.TechnologyStack = techStack;
        }

        /// <summary>
        /// Analyzes response headers to identify technologies
        /// </summary>
        private void AnalyzeHeadersForTechnology(Dictionary<string, string> headers, TechnologyStack techStack)
        {
            foreach (var header in headers)
            {
                var key = header.Key.ToLower();
                var value = header.Value.ToLower();

                // ASP.NET Core detection
                if (key == "server" && value.Contains("kestrel"))
                {
                    techStack.Framework = "ASP.NET Core";
                    techStack.ProgrammingLanguage = "C#";
                    techStack.Confidence = 0.9;
                }
                else if (key == "x-powered-by" && value.Contains("asp.net"))
                {
                    techStack.Framework = "ASP.NET";
                    techStack.ProgrammingLanguage = "C#";
                    techStack.Confidence = 0.8;
                }

                // Database detection
                if (key == "x-database" || value.Contains("sql server"))
                {
                    techStack.Database = "SQL Server";
                    techStack.Confidence = Math.Max(techStack.Confidence, 0.7);
                }

                // Web server detection
                if (key == "server")
                {
                    if (value.Contains("iis"))
                        techStack.WebServer = "IIS";
                    else if (value.Contains("nginx"))
                        techStack.WebServer = "Nginx";
                    else if (value.Contains("apache"))
                        techStack.WebServer = "Apache";
                }

                // Authentication framework detection
                if (key == "www-authenticate" || value.Contains("bearer") || value.Contains("jwt"))
                {
                    techStack.AuthenticationFramework = "JWT";
                }
            }
        }

        /// <summary>
        /// Analyzes response content to identify technologies
        /// </summary>
        private void AnalyzeContentForTechnology(string content, TechnologyStack techStack)
        {
            if (string.IsNullOrEmpty(content))
                return;

            var lowerContent = content.ToLower();

            // ASP.NET Core specific indicators
            if (lowerContent.Contains("asp.net core") || lowerContent.Contains("kestrel"))
            {
                techStack.Framework = "ASP.NET Core";
                techStack.ProgrammingLanguage = "C#";
                techStack.Confidence = Math.Max(techStack.Confidence, 0.9);
            }

            // Entity Framework detection
            if (lowerContent.Contains("entity framework") || lowerContent.Contains("ef core"))
            {
                techStack.Orm = "Entity Framework Core";
            }

            // Database indicators
            if (lowerContent.Contains("sql server") || lowerContent.Contains("mssql"))
            {
                techStack.Database = "SQL Server";
            }
            else if (lowerContent.Contains("mysql"))
            {
                techStack.Database = "MySQL";
            }
            else if (lowerContent.Contains("postgresql") || lowerContent.Contains("postgres"))
            {
                techStack.Database = "PostgreSQL";
            }

            // JavaScript framework detection
            if (lowerContent.Contains("react"))
                techStack.DetectedLibraries.Add("React");
            if (lowerContent.Contains("angular"))
                techStack.DetectedLibraries.Add("Angular");
            if (lowerContent.Contains("vue"))
                techStack.DetectedLibraries.Add("Vue.js");
        }

        /// <summary>
        /// Analyzes specific endpoints for additional technology information
        /// </summary>
        private async Task AnalyzeEndpointsForTechnologyAsync(ApplicationProfile profile, TechnologyStack techStack)
        {
            // Check for Swagger/OpenAPI documentation
            var swaggerResponse = await _httpClient.GetAsync(profile.BaseUrl.TrimEnd('/') + "/swagger");
            if (swaggerResponse.Success && swaggerResponse.Content.Contains("swagger"))
            {
                techStack.DetectedLibraries.Add("Swagger/OpenAPI");
                techStack.Confidence = Math.Max(techStack.Confidence, 0.8);
            }

            // Check for health check endpoint (common in ASP.NET Core)
            var healthResponse = await _httpClient.GetAsync(profile.BaseUrl.TrimEnd('/') + "/health");
            if (healthResponse.Success && healthResponse.Content.Contains("healthy"))
            {
                techStack.Framework = "ASP.NET Core";
                techStack.ProgrammingLanguage = "C#";
                techStack.Confidence = Math.Max(techStack.Confidence, 0.7);
            }
        }

        /// <summary>
        /// Detects security features and configurations
        /// </summary>
        private async Task DetectSecurityFeaturesAsync(ApplicationProfile profile)
        {
            var securityFeatures = new SecurityFeatures();
            var mainResponse = await _httpClient.GetAsync(profile.BaseUrl);

            if (!mainResponse.Success)
            {
                profile.SecurityFeatures = securityFeatures;
                return;
            }

            // Check for HTTPS
            securityFeatures.HasHttps = profile.BaseUrl.StartsWith("https://");

            // Check for security headers
            var securityHeaders = new List<string>
            {
                "X-Content-Type-Options",
                "X-Frame-Options",
                "X-XSS-Protection",
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "Referrer-Policy"
            };

            foreach (var header in securityHeaders)
            {
                if (mainResponse.HasHeader(header))
                {
                    securityFeatures.HasSecurityHeaders = true;
                    securityFeatures.SecurityHeaders.Add(header);
                }
            }

            // Check for CORS
            if (mainResponse.HasHeader("Access-Control-Allow-Origin"))
            {
                securityFeatures.HasCors = true;
                securityFeatures.CorsConfiguration = mainResponse.GetHeader("Access-Control-Allow-Origin");
            }

            // Check for rate limiting indicators
            if (mainResponse.HasHeader("X-RateLimit-Limit") || 
                mainResponse.HasHeader("RateLimit-Limit"))
            {
                securityFeatures.HasRateLimiting = true;
            }

            // Check for file upload capabilities
            foreach (var endpoint in profile.DiscoveredEndpoints)
            {
                if (endpoint.Path.ToLower().Contains("upload") || 
                    endpoint.Path.ToLower().Contains("file"))
                {
                    securityFeatures.HasFileUpload = true;
                    break;
                }
            }

            // Check for camera access (specific to your dessert app)
            foreach (var endpoint in profile.DiscoveredEndpoints)
            {
                if (endpoint.Path.ToLower().Contains("camera") || 
                    endpoint.Path.ToLower().Contains("analyze-ingredient"))
                {
                    securityFeatures.HasCameraAccess = true;
                    break;
                }
            }

            profile.SecurityFeatures = securityFeatures;
        }

        /// <summary>
        /// Analyzes the authentication system
        /// </summary>
        private async Task AnalyzeAuthenticationSystemAsync(ApplicationProfile profile)
        {
            var authSystem = new AuthenticationSystem();

            // Check for authentication endpoints
            var authEndpoints = new List<string> { "/login", "/auth", "/signin", "/authenticate" };
            
            foreach (var endpoint in profile.DiscoveredEndpoints)
            {
                if (authEndpoints.Any(auth => endpoint.Path.ToLower().Contains(auth)))
                {
                    authSystem.HasAuthentication = true;
                    authSystem.AuthenticationEndpoints.Add(endpoint.Path);
                }
            }

            // Test authentication endpoints
            foreach (var endpoint in authSystem.AuthenticationEndpoints)
            {
                var url = profile.BaseUrl.TrimEnd('/') + endpoint;
                var response = await _httpClient.GetAsync(url);
                
                if (response.Success)
                {
                    // Analyze response for authentication type
                    if (response.Content.Contains("jwt") || response.Content.Contains("bearer"))
                    {
                        authSystem.Type = AuthenticationType.JWT;
                        authSystem.TokenType = "JWT";
                    }
                    else if (response.Content.Contains("session"))
                    {
                        authSystem.Type = AuthenticationType.Session;
                    }
                    else if (response.Content.Contains("basic"))
                    {
                        authSystem.Type = AuthenticationType.Basic;
                    }
                }
            }

            profile.AuthenticationSystem = authSystem;
        }

        /// <summary>
        /// Calculates the overall risk level based on discovered information
        /// </summary>
        private void CalculateRiskLevel(ApplicationProfile profile)
        {
            var riskScore = 0;

            // No authentication = high risk
            if (!profile.AuthenticationSystem.HasAuthentication)
                riskScore += 3;

            // No HTTPS = high risk
            if (!profile.SecurityFeatures.HasHttps)
                riskScore += 3;

            // No security headers = medium risk
            if (!profile.SecurityFeatures.HasSecurityHeaders)
                riskScore += 2;

            // No rate limiting = medium risk
            if (!profile.SecurityFeatures.HasRateLimiting)
                riskScore += 2;

            // Camera access without proper security = high risk
            if (profile.SecurityFeatures.HasCameraAccess && !profile.SecurityFeatures.HasSecurityHeaders)
                riskScore += 3;

            // File upload without proper security = high risk
            if (profile.SecurityFeatures.HasFileUpload && !profile.SecurityFeatures.HasSecurityHeaders)
                riskScore += 3;

            // Determine risk level
            profile.RiskLevel = riskScore switch
            {
                >= 8 => RiskLevel.Critical,
                >= 6 => RiskLevel.High,
                >= 4 => RiskLevel.Medium,
                >= 2 => RiskLevel.Low,
                _ => RiskLevel.Low
            };
        }

        /// <summary>
        /// Extracts additional endpoints from HTML/JavaScript content
        /// </summary>
        private List<string> ExtractEndpointsFromContent(string content, string baseUrl)
        {
            var endpoints = new List<string>();
            var baseUri = new Uri(baseUrl);

            // Look for API endpoints in JavaScript
            var apiPattern = @"['""]([^'""]*\/api\/[^'""]*)['""]";
            var matches = Regex.Matches(content, apiPattern, RegexOptions.IgnoreCase);
            
            foreach (Match match in matches)
            {
                var endpoint = match.Groups[1].Value;
                if (!endpoints.Contains(endpoint))
                {
                    endpoints.Add(endpoint);
                }
            }

            // Look for form actions
            var formPattern = @"action=['""]([^'""]*)['""]";
            matches = Regex.Matches(content, formPattern, RegexOptions.IgnoreCase);
            
            foreach (Match match in matches)
            {
                var endpoint = match.Groups[1].Value;
                if (endpoint.StartsWith("/") && !endpoints.Contains(endpoint))
                {
                    endpoints.Add(endpoint);
                }
            }

            return endpoints;
        }

        /// <summary>
        /// Checks if authentication is required based on response
        /// </summary>
        private bool IsAuthenticationRequired(HttpResponse response)
        {
            return response.StatusCode == HttpStatusCode.Unauthorized ||
                   response.StatusCode == HttpStatusCode.Forbidden ||
                   response.Content.Contains("login") ||
                   response.Content.Contains("unauthorized") ||
                   response.Content.Contains("authentication required");
        }

        /// <summary>
        /// Checks if the response indicates an API endpoint
        /// </summary>
        private bool IsApiEndpoint(HttpResponse response)
        {
            return response.GetHeader("Content-Type")?.Contains("application/json") == true ||
                   response.Url.Contains("/api/") ||
                   response.Content.StartsWith("{") ||
                   response.Content.StartsWith("[");
        }

        /// <summary>
        /// Analyzes potential vulnerabilities based on response characteristics
        /// </summary>
        private List<string> AnalyzePotentialVulnerabilities(HttpResponse response)
        {
            var vulnerabilities = new List<string>();

            // Check for information disclosure
            if (response.Content.Contains("stack trace") || 
                response.Content.Contains("exception") ||
                response.Content.Contains("error details"))
            {
                vulnerabilities.Add("Information Disclosure");
            }

            // Check for directory listing
            if (response.Content.Contains("Index of") || 
                response.Content.Contains("Directory listing"))
            {
                vulnerabilities.Add("Directory Listing");
            }

            // Check for debug information
            if (response.Content.Contains("debug") || 
                response.Content.Contains("development"))
            {
                vulnerabilities.Add("Debug Information");
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Extracts parameters from API response
        /// </summary>
        private List<ParameterInfo> ExtractParametersFromResponse(HttpResponse response)
        {
            var parameters = new List<ParameterInfo>();

            try
            {
                // Try to parse as JSON and extract parameter information
                var json = System.Text.Json.JsonSerializer.Deserialize<JsonElement>(response.Content);
                
                if (json.ValueKind == JsonValueKind.Object)
                {
                    foreach (var property in json.EnumerateObject())
                    {
                        parameters.Add(new ParameterInfo
                        {
                            Name = property.Name,
                            Type = property.Value.ValueKind.ToString(),
                            Location = ParameterLocation.Body,
                            Required = false
                        });
                    }
                }
            }
            catch
            {
                // If not JSON, try to extract from other patterns
            }

            return parameters;
        }

        /// <summary>
        /// Enhanced technology stack analysis for databases, ORMs, and AI services
        /// </summary>
        private async Task AnalyzeEnhancedTechnologyStackAsync(ApplicationProfile profile)
        {
            _logger.Information("🔍 Performing enhanced technology stack analysis...");
            
            // Analyze all discovered endpoints for technology indicators
            foreach (var endpoint in profile.DiscoveredEndpoints)
            {
                try
                {
                    var response = await _httpClient.GetAsync(endpoint.Path);
                    if (response.Success)
                    {
                        // Analyze response for database technologies
                        AnalyzeDatabaseTechnologies(profile, response.Content, endpoint.Path);
                        
                        // Analyze response for AI/ML services
                        AnalyzeAIServices(profile, response.Content, endpoint.Path);
                        
                        // Analyze response for ORM frameworks
                        AnalyzeORMTechnologies(profile, response.Content, endpoint.Path);
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Error analyzing endpoint {Endpoint} for technology", endpoint.Path);
                }
            }
            
            // Test specific technology endpoints
            await TestTechnologyEndpointsAsync(profile);
        }

        /// <summary>
        /// Analyzes content for database technology indicators
        /// </summary>
        private void AnalyzeDatabaseTechnologies(ApplicationProfile profile, string content, string endpoint)
        {
            // SQL Server indicators
            if (content.Contains("Microsoft.Data.SqlClient") || content.Contains("SqlConnection") || 
                content.Contains("sql5111.site4now.net") || content.Contains("SQL Server"))
            {
                profile.TechnologyStack.Database = "SQL Server";
                profile.TechnologyStack.Confidence = Math.Max(profile.TechnologyStack.Confidence, 0.95f);
                _logger.Information("🔍 Detected SQL Server database from {Endpoint}", endpoint);
            }
            
            // Entity Framework indicators
            if (content.Contains("EntityFramework") || content.Contains("Microsoft.EntityFrameworkCore") ||
                content.Contains("DbContext") || content.Contains("DbSet"))
            {
                profile.TechnologyStack.Orm = "Entity Framework Core";
                profile.TechnologyStack.Confidence = Math.Max(profile.TechnologyStack.Confidence, 0.90f);
                _logger.Information("🔍 Detected Entity Framework Core ORM from {Endpoint}", endpoint);
            }
        }

        /// <summary>
        /// Analyzes content for AI service indicators
        /// </summary>
        private void AnalyzeAIServices(ApplicationProfile profile, string content, string endpoint)
        {
            // OpenAI indicators
            if (content.Contains("OpenAI") || content.Contains("sk-proj-") || content.Contains("ChatGPT") ||
                content.Contains("DALL-E") || content.Contains("GPT-"))
            {
                if (!profile.TechnologyStack.DetectedLibraries.Contains("OpenAI"))
                {
                    profile.TechnologyStack.DetectedLibraries.Add("OpenAI");
                }
                _logger.Information("🔍 Detected OpenAI integration from {Endpoint}", endpoint);
            }
            
            // AI/ML service indicators
            if (content.Contains("artificial intelligence") || content.Contains("machine learning") ||
                content.Contains("neural network") || content.Contains("AI model"))
            {
                if (!profile.TechnologyStack.DetectedLibraries.Contains("AI/ML Services"))
                {
                    profile.TechnologyStack.DetectedLibraries.Add("AI/ML Services");
                }
                _logger.Information("🔍 Detected AI/ML services from {Endpoint}", endpoint);
            }
        }

        /// <summary>
        /// Analyzes content for ORM technology indicators
        /// </summary>
        private void AnalyzeORMTechnologies(ApplicationProfile profile, string content, string endpoint)
        {
            // Entity Framework Core specific indicators
            if (content.Contains("Microsoft.EntityFrameworkCore.SqlServer") || 
                content.Contains("UseSqlServer") || content.Contains("AddDbContext"))
            {
                profile.TechnologyStack.Orm = "Entity Framework Core";
                profile.TechnologyStack.Database = "SQL Server";
                profile.TechnologyStack.Confidence = Math.Max(profile.TechnologyStack.Confidence, 0.95f);
                _logger.Information("🔍 Detected Entity Framework Core with SQL Server from {Endpoint}", endpoint);
            }
        }

        /// <summary>
        /// Tests specific technology endpoints
        /// </summary>
        private async Task TestTechnologyEndpointsAsync(ApplicationProfile profile)
        {
            var baseUrl = profile.BaseUrl;
            
            // Test database connection endpoints
            var dbEndpoints = new[] { "/api/db-test", "/api/database", "/api/connection", "/api/health" };
            foreach (var endpoint in dbEndpoints)
            {
                try
                {
                    var response = await _httpClient.GetAsync(baseUrl.TrimEnd('/') + endpoint);
                    if (response.Success && response.Content.Contains("database"))
                    {
                        profile.TechnologyStack.Database = "SQL Server";
                        _logger.Information("🔍 Confirmed database technology from {Endpoint}", endpoint);
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Error testing database endpoint {Endpoint}", endpoint);
                }
            }
            
            // Test AI service endpoints
            var aiEndpoints = new[] { "/api/chatbot", "/api/ai", "/api/chat", "/api/recipe" };
            foreach (var endpoint in aiEndpoints)
            {
                try
                {
                    var response = await _httpClient.GetAsync(baseUrl.TrimEnd('/') + endpoint);
                    if (response.Success && (response.Content.Contains("OpenAI") || response.Content.Contains("AI")))
                    {
                        if (!profile.TechnologyStack.DetectedLibraries.Contains("OpenAI"))
                        {
                            profile.TechnologyStack.DetectedLibraries.Add("OpenAI");
                        }
                        _logger.Information("🔍 Confirmed AI services from {Endpoint}", endpoint);
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Error testing AI endpoint {Endpoint}", endpoint);
                }
            }
        }

        /// <summary>
        /// Discovers static files and directories
        /// </summary>
        private async Task DiscoverStaticFilesAsync(ApplicationProfile profile)
        {
            _logger.Information("🔍 Discovering static files and directories...");
            
            var baseUrl = profile.BaseUrl;
            var staticFiles = new List<string>();
            
            // Common static file patterns
            var staticFilePatterns = new[]
            {
                // Images
                "/images/", "/img/", "/assets/images/", "/static/images/", "/wwwroot/images/",
                "/pics/", "/photos/", "/media/images/", "/uploads/images/",
                
                // CSS and JS
                "/css/", "/js/", "/scripts/", "/styles/", "/assets/css/", "/assets/js/",
                "/static/css/", "/static/js/", "/wwwroot/css/", "/wwwroot/js/",
                
                // Documents
                "/docs/", "/documents/", "/files/", "/downloads/", "/uploads/",
                "/static/files/", "/assets/files/", "/media/files/",
                
                // Common static files
                "/favicon.ico", "/robots.txt", "/sitemap.xml", "/manifest.json",
                "/apple-touch-icon.png", "/android-chrome-192x192.png",
                
                // Common directories
                "/public/", "/static/", "/assets/", "/media/", "/uploads/", "/files/",
                "/wwwroot/", "/content/", "/resources/"
            };

            foreach (var pattern in staticFilePatterns)
            {
                try
                {
                    var url = baseUrl.TrimEnd('/') + pattern;
                    var response = await _httpClient.GetAsync(url);
                    
                    if (response.Success)
                    {
                        staticFiles.Add(pattern);
                        _logger.Information("📁 Found static resource: {Pattern}", pattern);
                        
                        // If it's a directory, try to discover files within it
                        if (pattern.EndsWith("/"))
                        {
                            await DiscoverFilesInDirectoryAsync(profile, pattern, baseUrl);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Error testing static file pattern {Pattern}", pattern);
                }
            }
            
            // Store discovered static files in profile
            profile.StaticFiles = staticFiles;
            _logger.Information("✅ Discovered {Count} static resources", staticFiles.Count);
        }

        /// <summary>
        /// Discovers files within a directory
        /// </summary>
        private async Task DiscoverFilesInDirectoryAsync(ApplicationProfile profile, string directory, string baseUrl)
        {
            var commonFiles = new[]
            {
                "index.html", "index.htm", "default.html", "home.html",
                "style.css", "main.css", "app.css", "bootstrap.css",
                "script.js", "main.js", "app.js", "jquery.js",
                "favicon.ico", "logo.png", "banner.jpg", "hero.jpg",
                "apple_pie.png", "chocolate_cake.png", "ice_cream.png"
            };

            foreach (var file in commonFiles)
            {
                try
                {
                    var url = baseUrl.TrimEnd('/') + directory + file;
                    var response = await _httpClient.GetAsync(url);
                    
                    if (response.Success)
                    {
                        profile.StaticFiles.Add(directory + file);
                        _logger.Information("📄 Found file: {Directory}{File}", directory, file);
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Error testing file {Directory}{File}", directory, file);
                }
            }
        }

        /// <summary>
        /// Enhanced API endpoint discovery using comprehensive patterns
        /// </summary>
        private async Task<List<EndpointInfo>> DiscoverEnhancedApiEndpointsAsync(string baseUrl)
        {
            var discoveredEndpoints = new List<EndpointInfo>();
            
            // Comprehensive API endpoint patterns
            var apiPatterns = new[]
            {
                // Common API endpoints
                "/api/hello", "/api/status", "/api/health", "/api/ping", "/api/version",
                "/api/users", "/api/user", "/api/auth", "/api/login", "/api/logout",
                "/api/data", "/api/items", "/api/products", "/api/orders", "/api/customers",
                "/api/admin", "/api/config", "/api/settings", "/api/info", "/api/test",
                
                // Database and connection testing
                "/api/db-test", "/api/database", "/api/connection", "/api/db-status",
                
                // CRUD operations for common entities
                "/api/desserts", "/api/recipes", "/api/foods", "/api/menu", "/api/catalog",
                "/api/chat", "/api/chatbot", "/api/ai", "/api/bot", "/api/assistant",
                "/api/messages", "/api/history", "/api/logs", "/api/audit",
                
                // File and media operations
                "/api/upload", "/api/files", "/api/images", "/api/media", "/api/assets",
                "/api/generate", "/api/create", "/api/process",
                
                // Utility endpoints
                "/api/spell-check", "/api/validate", "/api/check", "/api/verify",
                "/api/loading", "/api/status", "/api/progress", "/api/queue",
                
                // Authentication and security
                "/api/token", "/api/refresh", "/api/validate-token", "/api/session",
                "/api/permissions", "/api/roles", "/api/access",
                
                // Monitoring and diagnostics
                "/api/metrics", "/api/stats", "/api/performance", "/api/diagnostics",
                "/api/debug", "/api/trace", "/api/logs",
                
                // VULNERABILITY TESTING ENDPOINTS - Critical for testing
                "/api/vulnerable", "/api/vulnerable/search-products", "/api/vulnerable/user-products",
                "/api/vulnerable/search", "/api/vulnerable/add-comment", "/api/vulnerable/comments",
                "/api/vulnerable/upload-file", "/api/vulnerable/download", "/api/vulnerable/list-directory",
                "/api/vulnerable/login", "/api/vulnerable/check-username", "/api/vulnerable/api-key",
                "/api/vulnerable/env-info", "/api/vulnerable/test", "/api/vulnerable/debug",
                
                // MISSING ENDPOINTS - Add these specific patterns
                "/api/vulnerable/admin-login", "/api/vulnerable/download-file", "/api/vulnerable/list-files",
                "/api/vulnerable/debug-info", "/api/vulnerable/check-user", "/api/vulnerable/api-key",
                "/api/vulnerable/env-info", "/api/vulnerable/check-username",
                
                // Additional vulnerability patterns
                "/api/security", "/api/security/test", "/api/security/scan", "/api/security/check",
                "/api/test/sql", "/api/test/xss", "/api/test/upload", "/api/test/auth",
                "/api/demo", "/api/demo/sql", "/api/demo/xss", "/api/demo/upload",
                "/api/sample", "/api/sample/data", "/api/sample/users", "/api/sample/files",
                
                // Additional common patterns that might be missed
                "/api/vulnerable/api-key", "/api/vulnerable/env-info", "/api/vulnerable/debug-info",
                "/api/vulnerable/download-file", "/api/vulnerable/list-files", "/api/vulnerable/check-user",
                "/api/vulnerable/admin-login", "/api/vulnerable/check-username"
            };

            // Enhanced parameterized endpoint patterns
            var parameterizedPatterns = new[]
            {
                // CRUD operations with ID parameters
                "/api/desserts/{id}", "/api/users/{id}", "/api/products/{id}", "/api/orders/{id}",
                "/api/chatbot/history/{id}", "/api/messages/{id}", "/api/files/{id}",
                
                // Nested resource patterns
                "/api/desserts/{id}/generate-image", "/api/users/{id}/profile", "/api/orders/{id}/items",
                "/api/chatbot/{id}/messages", "/api/products/{id}/reviews",
                
                // Action-based patterns
                "/api/desserts/{id}/update", "/api/users/{id}/delete", "/api/orders/{id}/cancel",
                "/api/chatbot/{id}/clear-history", "/api/files/{id}/download",
                
                // VULNERABILITY TESTING PARAMETERIZED ENDPOINTS
                "/api/vulnerable/user-products/{userId}", "/api/vulnerable/products/{id}",
                "/api/vulnerable/users/{id}", "/api/vulnerable/files/{id}",
                "/api/vulnerable/comments/{id}", "/api/vulnerable/messages/{id}",
                
                // Additional parameterized patterns
                "/api/test/{id}", "/api/demo/{id}", "/api/sample/{id}",
                "/api/security/{id}", "/api/debug/{id}"
            };

            _logger.Information("🔍 Testing {Count} enhanced API patterns...", apiPatterns.Length);

            // Test basic API patterns with all HTTP methods
            foreach (var pattern in apiPatterns)
            {
                try
                {
                    var url = baseUrl.TrimEnd('/') + pattern;
                    
                    // Test all HTTP methods for each pattern
                    var methods = new[] { "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS" };
                    foreach (var method in methods)
                    {
                        var endpoint = await TestEndpointAsync(url, method);
                        if (endpoint != null)
                        {
                            discoveredEndpoints.Add(endpoint);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Error testing API pattern {Pattern}", pattern);
                }
            }

            // Test parameterized endpoints with actual ID values
            _logger.Information("🔍 Testing {Count} parameterized endpoint patterns...", parameterizedPatterns.Length);
            
            foreach (var pattern in parameterizedPatterns)
            {
                try
                {
                    // Test with common ID values
                    var testIds = new[] { "1", "2", "3", "123", "999", "test", "admin", "user" };
                    
                    foreach (var testId in testIds)
                    {
                        var url = baseUrl.TrimEnd('/') + pattern.Replace("{id}", testId);
                        
                        // Test all HTTP methods for parameterized endpoints
                        var methods = new[] { "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS" };
                        foreach (var method in methods)
                        {
                            var endpoint = await TestEndpointAsync(url, method);
                            if (endpoint != null)
                            {
                                // Mark this as a parameterized endpoint
                                endpoint.Path = pattern; // Store the pattern, not the specific URL
                                endpoint.IsParameterized = true;
                                endpoint.ParameterName = "id";
                                endpoint.ParameterValue = testId;
                                discoveredEndpoints.Add(endpoint);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Error testing parameterized pattern {Pattern}", pattern);
                }
            }

            _logger.Information("✅ Enhanced API discovery found {Count} additional endpoints", discoveredEndpoints.Count);
            return discoveredEndpoints;
        }

        /// <summary>
        /// Detects the application name from various sources
        /// </summary>
        private async Task DetectApplicationNameAsync(ApplicationProfile profile)
        {
            try
            {
                var baseUrl = profile.BaseUrl;
                var applicationName = string.Empty;

                // Try to get the main page content
                var mainResponse = await _httpClient.GetAsync(baseUrl);
                if (mainResponse.Success && !string.IsNullOrEmpty(mainResponse.Content))
                {
                    applicationName = ExtractApplicationNameFromContent(mainResponse.Content);
                }

                // If not found on main page, try common endpoints
                if (string.IsNullOrEmpty(applicationName))
                {
                    var commonEndpoints = new[] { "/", "/index.html", "/home", "/about" };
                    
                    foreach (var endpoint in commonEndpoints)
                    {
                        try
                        {
                            var url = baseUrl.TrimEnd('/') + endpoint;
                            var response = await _httpClient.GetAsync(url);
                            
                            if (response.Success && !string.IsNullOrEmpty(response.Content))
                            {
                                applicationName = ExtractApplicationNameFromContent(response.Content);
                                if (!string.IsNullOrEmpty(applicationName))
                                {
                                    break;
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.Debug(ex, "Error detecting application name from {Endpoint}", endpoint);
                        }
                    }
                }

                // If still not found, try to extract from URL or use default
                if (string.IsNullOrEmpty(applicationName))
                {
                    var uri = new Uri(baseUrl);
                    var hostName = uri.Host;
                    
                    // Remove common TLDs and subdomains
                    if (hostName.Contains("localhost") || hostName.Contains("127.0.0.1"))
                    {
                        applicationName = "Local Web Application";
                    }
                    else
                    {
                        applicationName = hostName.Split('.')[0];
                        if (string.IsNullOrEmpty(applicationName))
                        {
                            applicationName = "Web Application";
                        }
                    }
                }

                profile.ApplicationName = applicationName;
                _logger.Information("📱 Application Name: {ApplicationName}", applicationName);
            }
            catch (Exception ex)
            {
                _logger.Warning(ex, "Error detecting application name");
                profile.ApplicationName = "Unknown Application";
            }
        }

        /// <summary>
        /// Extracts application name from HTML content
        /// </summary>
        private string ExtractApplicationNameFromContent(string content)
        {
            try
            {
                // Try to extract from <title> tag
                var titleMatch = System.Text.RegularExpressions.Regex.Match(
                    content, 
                    @"<title[^>]*>(.*?)</title>", 
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Singleline);
                
                if (titleMatch.Success)
                {
                    var title = titleMatch.Groups[1].Value.Trim();
                    if (!string.IsNullOrEmpty(title))
                    {
                        // Clean up the title
                        title = System.Text.RegularExpressions.Regex.Replace(title, @"\s+", " ");
                        return title;
                    }
                }

                // Try to extract from <h1> tag
                var h1Match = System.Text.RegularExpressions.Regex.Match(
                    content, 
                    @"<h1[^>]*>(.*?)</h1>", 
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Singleline);
                
                if (h1Match.Success)
                {
                    var h1Text = h1Match.Groups[1].Value.Trim();
                    if (!string.IsNullOrEmpty(h1Text))
                    {
                        h1Text = System.Text.RegularExpressions.Regex.Replace(h1Text, @"<[^>]+>", ""); // Remove HTML tags
                        h1Text = System.Text.RegularExpressions.Regex.Replace(h1Text, @"\s+", " ");
                        return h1Text;
                    }
                }

                // Try to extract from meta description
                var metaMatch = System.Text.RegularExpressions.Regex.Match(
                    content, 
                    @"<meta[^>]*name=[""']description[""'][^>]*content=[""']([^""']*)[""']", 
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                
                if (metaMatch.Success)
                {
                    var description = metaMatch.Groups[1].Value.Trim();
                    if (!string.IsNullOrEmpty(description) && description.Length > 10)
                    {
                        return description.Substring(0, Math.Min(50, description.Length)) + "...";
                    }
                }

                // Try to extract from JSON response (for API endpoints)
                if (content.TrimStart().StartsWith("{"))
                {
                    try
                    {
                        var jsonDoc = System.Text.Json.JsonDocument.Parse(content);
                        if (jsonDoc.RootElement.TryGetProperty("name", out var nameElement))
                        {
                            return nameElement.GetString() ?? string.Empty;
                        }
                        if (jsonDoc.RootElement.TryGetProperty("title", out var titleElement))
                        {
                            return titleElement.GetString() ?? string.Empty;
                        }
                        if (jsonDoc.RootElement.TryGetProperty("application", out var appElement))
                        {
                            return appElement.GetString() ?? string.Empty;
                        }
                    }
                    catch
                    {
                        // Not valid JSON, continue with other methods
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Debug(ex, "Error extracting application name from content");
            }

            return string.Empty;
        }

        /// <summary>
        /// Scans for configuration files and exposed credentials
        /// </summary>
        private async Task ScanConfigurationFilesAsync(ApplicationProfile profile)
        {
            try
            {
                _logger.Information("🔍 Scanning for configuration files and exposed credentials...");
                
                var configurationScanner = new ConfigurationScanner(profile.BaseUrl);
                var configVulnerabilities = await configurationScanner.ScanConfigurationFilesAsync(profile.BaseUrl);
                
                // Store configuration vulnerabilities in the profile for later reporting
                profile.ConfigurationVulnerabilities = configVulnerabilities;
                
                _logger.Information("✅ Configuration scanning completed. Found {Count} configuration vulnerabilities", 
                    configVulnerabilities.Count);
                
                configurationScanner.Dispose();
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error during configuration file scanning");
            }
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
}
