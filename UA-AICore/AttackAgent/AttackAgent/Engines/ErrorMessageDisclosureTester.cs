using AttackAgent.Models;
using Serilog;
using System.Text.RegularExpressions;

namespace AttackAgent.Engines
{
    /// <summary>
    /// Tests for error message disclosure vulnerabilities
    /// </summary>
    public class ErrorMessageDisclosureTester : IDisposable
    {
        private readonly SecurityHttpClient _httpClient;
        private readonly ILogger _logger;
        private readonly string _baseUrl;
        private bool _disposed = false;

        public ErrorMessageDisclosureTester(string baseUrl)
        {
            _baseUrl = baseUrl;
            _httpClient = new SecurityHttpClient(baseUrl);
            _logger = Log.ForContext<ErrorMessageDisclosureTester>();
        }

        /// <summary>
        /// Tests all endpoints for error message disclosure
        /// </summary>
        public async Task<List<Vulnerability>> TestForErrorDisclosureAsync(ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            _logger.Information("🔍 Starting error message disclosure testing...");
            _logger.Information("Testing {EndpointCount} endpoints for detailed error messages", 
                profile.DiscoveredEndpoints.Count);

            var testPayloads = GenerateErrorTriggeringPayloads();

            foreach (var endpoint in profile.DiscoveredEndpoints)
            {
                if (!IsTestableEndpoint(endpoint))
                    continue;

                var endpointVulns = await TestEndpointForErrorDisclosureAsync(endpoint, testPayloads);
                vulnerabilities.AddRange(endpointVulns);
            }

            _logger.Information("Error message disclosure testing completed. Found {VulnCount} vulnerabilities", 
                vulnerabilities.Count);
            
            return vulnerabilities;
        }

        /// <summary>
        /// Tests a specific endpoint for error message disclosure
        /// </summary>
        private async Task<List<Vulnerability>> TestEndpointForErrorDisclosureAsync(EndpointInfo endpoint, List<string> testPayloads)
        {
            var vulnerabilities = new List<Vulnerability>();
            var url = _baseUrl.TrimEnd('/') + endpoint.Path;

            try
            {
                // Test with various invalid inputs to trigger errors
                foreach (var payload in testPayloads)
                {
                    HttpResponse response;
                    
                    if (endpoint.Method == "POST" || endpoint.Method == "PUT")
                    {
                        // Try to send invalid JSON or data
                        var invalidJson = $"{{ \"invalid\": {payload} }}";
                        response = await _httpClient.PostAsync(url, invalidJson);
                    }
                    else
                    {
                        // For GET, try invalid query parameters
                        var separator = url.Contains("?") ? "&" : "?";
                        response = await _httpClient.GetAsync($"{url}{separator}id={Uri.EscapeDataString(payload)}");
                    }

                    // Check for detailed error messages
                    var hasDetailedError = HasDetailedErrorMessage(response);
                    
                    if (hasDetailedError)
                    {
                        var vuln = CreateErrorDisclosureVulnerability(endpoint, response, payload);
                        vulnerabilities.Add(vuln);
                        
                        _logger.Warning("🚨 Error message disclosure found: {Method} {Path}", 
                            endpoint.Method, endpoint.Path);
                        
                        // Only report once per endpoint
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Debug("Error testing {Path} for error disclosure: {Error}", endpoint.Path, ex.Message);
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Checks if response contains detailed error messages
        /// </summary>
        private bool HasDetailedErrorMessage(HttpResponse response)
        {
            if (!response.Success || string.IsNullOrEmpty(response.Content))
                return false;

            var content = response.Content;

            // Check for detailed error patterns
            var errorPatterns = new[]
            {
                // .NET exception messages
                @"Exception\s*:\s*",
                @"at\s+.*\.\w+\(.*\)",
                @"System\.\w+\.\w+Exception",
                @"Stack\s+Trace",
                @"Source:\s+\w+",
                @"Line\s+\d+",
                
                // Database errors
                @"SQL\s+Server",
                @"MySQL\s+error",
                @"PostgreSQL\s+ERROR",
                @"ORA-\d+",
                @"SQLSTATE",
                @"Database\s+connection",
                
                // File system errors
                @"FileNotFoundException",
                @"DirectoryNotFoundException",
                @"Path\s+not\s+found",
                @"Access\s+to\s+the\s+path",
                
                // Detailed error messages (not generic)
                @"\.Message",
                @"InnerException",
                @"Inner\s+Message",
                
                // Configuration errors
                @"ConnectionString",
                @"Configuration",
                @"appsettings",
                
                // Detailed stack traces
                @"at\s+System\.",
                @"at\s+Microsoft\.",
                @"at\s+\w+\.\w+\.\w+",
                
                // SQL query details
                @"SELECT\s+.*FROM",
                @"INSERT\s+INTO",
                @"UPDATE\s+.*SET",
                @"DELETE\s+FROM",
                
                // File paths exposed
                @"C:\\",
                @"/var/",
                @"/app/",
                @"C:\Users\",
                @"C:\Windows\",
                
                // Internal server details
                @"Server\s+Version",
                @"Database\s+Version",
                @"Framework\s+Version"
            };

            var hasDetailedError = errorPatterns.Any(pattern =>
                Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase));

            // Also check for generic error messages (should NOT trigger)
            var genericErrors = new[]
            {
                "An error occurred",
                "Something went wrong",
                "Internal server error",
                "Bad request",
                "Not found"
            };

            var hasGenericError = genericErrors.Any(error =>
                content.Contains(error, StringComparison.OrdinalIgnoreCase));

            // Only flag if detailed error AND not just generic
            return hasDetailedError && !hasGenericError;
        }

        /// <summary>
        /// Generates payloads to trigger errors
        /// </summary>
        private List<string> GenerateErrorTriggeringPayloads()
        {
            return new List<string>
            {
                // Invalid JSON
                "null",
                "undefined",
                "NaN",
                "invalid",
                
                // SQL injection attempts (to trigger SQL errors)
                "' OR '1'='1",
                "'; DROP TABLE--",
                
                // Path traversal (to trigger file errors)
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32",
                
                // Invalid types
                "999999999999999999999999",
                "-999999999999999999999999",
                
                // Special characters
                "<script>",
                "{{{{{{",
                "}}}}}}",
                
                // Empty/null
                "",
                "null",
                
                // Very long strings
                new string('A', 10000)
            };
        }

        /// <summary>
        /// Creates error disclosure vulnerability
        /// </summary>
        private Vulnerability CreateErrorDisclosureVulnerability(EndpointInfo endpoint, HttpResponse response, string payload)
        {
            // Extract error message snippet (first 200 chars)
            var errorSnippet = response.Content?.Length > 200 
                ? response.Content.Substring(0, 200) + "..."
                : response.Content ?? "";

            return new Vulnerability
            {
                Type = VulnerabilityType.InformationDisclosure,
                Severity = SeverityLevel.Medium,
                Title = $"Error Message Disclosure in {endpoint.Method} {endpoint.Path}",
                Description = $"The endpoint {endpoint.Path} exposes detailed error messages that may reveal sensitive information about the application's internal structure, database schema, file paths, or stack traces.",
                Endpoint = endpoint.Path,
                Method = endpoint.Method,
                Parameter = "various",
                Payload = payload,
                Response = errorSnippet,
                Evidence = $"Detailed error message exposed: {errorSnippet}",
                Remediation = "Implement generic error messages for production. Use structured logging for detailed errors instead of exposing them to clients. Configure custom error pages.",
                AttackMode = AttackMode.Stealth,
                Confidence = 0.8,
                FalsePositive = false,
                Verified = true
            };
        }

        /// <summary>
        /// Checks if endpoint is testable
        /// </summary>
        private bool IsTestableEndpoint(EndpointInfo endpoint)
        {
            var skipPaths = new[] { ".css", ".js", ".png", ".jpg", ".ico", ".svg" };
            return !skipPaths.Any(path => endpoint.Path.Contains(path, StringComparison.OrdinalIgnoreCase));
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


























