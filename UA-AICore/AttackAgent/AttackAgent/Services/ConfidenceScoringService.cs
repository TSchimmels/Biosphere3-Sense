using AttackAgent.Models;
using Serilog;
using System.Text.RegularExpressions;

namespace AttackAgent.Services
{
    /// <summary>
    /// Enhanced confidence scoring system for vulnerability assessment
    /// </summary>
    public class ConfidenceScoringService
    {
        private readonly ILogger _logger;

        public ConfidenceScoringService()
        {
            _logger = Log.ForContext<ConfidenceScoringService>();
        }

        /// <summary>
        /// Calculates enhanced confidence score for SQL injection vulnerabilities
        /// </summary>
        public double CalculateSqlInjectionConfidence(string payload, string responseBody, int statusCode, string technology)
        {
            var baseConfidence = 0.0;
            var confidenceFactors = new List<string>();

            // Check for SQL error messages (highest confidence)
            var sqlErrorPatterns = new[]
            {
                @"SQLite Error \d+",
                @"MySQL server version",
                @"PostgreSQL error",
                @"SQL Server error",
                @"Oracle error",
                @"database error",
                @"query failed",
                @"syntax error",
                @"invalid column",
                @"table.*doesn't exist",
                @"column.*doesn't exist"
            };

            foreach (var pattern in sqlErrorPatterns)
            {
                if (Regex.IsMatch(responseBody, pattern, RegexOptions.IgnoreCase))
                {
                    baseConfidence += 0.3;
                    confidenceFactors.Add($"SQL error detected: {pattern}");
                    break; // Only count the first match
                }
            }

            // Check for successful UNION injection
            if (payload.Contains("UNION") && responseBody.Contains("success"))
            {
                baseConfidence += 0.25;
                confidenceFactors.Add("Successful UNION injection");
            }

            // Check for time-based blind SQL injection
            if (payload.Contains("SLEEP") || payload.Contains("WAITFOR DELAY"))
            {
                // This would require timing analysis in a real implementation
                baseConfidence += 0.2;
                confidenceFactors.Add("Time-based payload detected");
            }

            // Check for boolean-based blind SQL injection
            if (payload.Contains("OR '1'='1") || payload.Contains("OR 1=1"))
            {
                if (responseBody.Length > 0 && statusCode == 200)
                {
                    baseConfidence += 0.2;
                    confidenceFactors.Add("Boolean-based injection successful");
                }
            }

            // Technology-specific confidence adjustments
            switch (technology.ToLower())
            {
                case "sqlite":
                    if (responseBody.Contains("SQLite"))
                    {
                        baseConfidence += 0.1;
                        confidenceFactors.Add("SQLite-specific error");
                    }
                    break;
                case "mysql":
                    if (responseBody.Contains("MySQL"))
                    {
                        baseConfidence += 0.1;
                        confidenceFactors.Add("MySQL-specific error");
                    }
                    break;
                case "postgresql":
                    if (responseBody.Contains("PostgreSQL"))
                    {
                        baseConfidence += 0.1;
                        confidenceFactors.Add("PostgreSQL-specific error");
                    }
                    break;
            }

            // Check for stack trace exposure (increases confidence)
            if (responseBody.Contains("at ") && responseBody.Contains("line "))
            {
                baseConfidence += 0.15;
                confidenceFactors.Add("Stack trace exposure");
            }

            // Penalize generic error responses
            if (responseBody.Contains("Internal Server Error") && !responseBody.Contains("SQL"))
            {
                baseConfidence -= 0.1;
                confidenceFactors.Add("Generic error response");
            }

            // Cap confidence at 1.0
            var finalConfidence = Math.Min(1.0, baseConfidence);

            _logger.Debug("SQL Injection confidence: {Confidence:P1} - Factors: {Factors}", 
                finalConfidence, string.Join(", ", confidenceFactors));

            return finalConfidence;
        }

        /// <summary>
        /// Calculates confidence score for XSS vulnerabilities
        /// </summary>
        public double CalculateXssConfidence(string payload, string responseBody, int statusCode)
        {
            var baseConfidence = 0.0;
            var confidenceFactors = new List<string>();

            // Check if payload is reflected in response
            if (responseBody.Contains(payload))
            {
                baseConfidence += 0.4;
                confidenceFactors.Add("Payload reflected in response");
            }

            // Check for script execution indicators
            if (payload.Contains("<script>") && responseBody.Contains("<script>"))
            {
                baseConfidence += 0.3;
                confidenceFactors.Add("Script tag execution");
            }

            // Check for event handler execution
            var eventHandlers = new[] { "onerror", "onload", "onclick", "onfocus", "onmouseover" };
            foreach (var handler in eventHandlers)
            {
                if (payload.Contains(handler) && responseBody.Contains(handler))
                {
                    baseConfidence += 0.25;
                    confidenceFactors.Add($"Event handler {handler} execution");
                    break;
                }
            }

            // Check for JavaScript URL execution
            if (payload.Contains("javascript:") && responseBody.Contains("javascript:"))
            {
                baseConfidence += 0.2;
                confidenceFactors.Add("JavaScript URL execution");
            }

            // Check for successful HTTP status
            if (statusCode == 200)
            {
                baseConfidence += 0.1;
                confidenceFactors.Add("Successful HTTP response");
            }

            // Penalize if payload is encoded/escaped
            if (responseBody.Contains("&lt;") || responseBody.Contains("&gt;") || responseBody.Contains("&amp;"))
            {
                baseConfidence -= 0.2;
                confidenceFactors.Add("Payload appears to be encoded");
            }

            var finalConfidence = Math.Min(1.0, Math.Max(0.0, baseConfidence));

            _logger.Debug("XSS confidence: {Confidence:P1} - Factors: {Factors}", 
                finalConfidence, string.Join(", ", confidenceFactors));

            return finalConfidence;
        }

        /// <summary>
        /// Calculates confidence score for authentication bypass vulnerabilities
        /// </summary>
        public double CalculateAuthBypassConfidence(string payload, string responseBody, int statusCode, string endpoint)
        {
            var baseConfidence = 0.0;
            var confidenceFactors = new List<string>();

            // Check for successful authentication bypass
            if (responseBody.Contains("success") && responseBody.Contains("true"))
            {
                baseConfidence += 0.4;
                confidenceFactors.Add("Authentication bypass successful");
            }

            // Check for admin access indicators
            if (responseBody.Contains("admin") || responseBody.Contains("Admin"))
            {
                baseConfidence += 0.3;
                confidenceFactors.Add("Admin access detected");
            }

            // Check for session/token creation
            if (responseBody.Contains("sessionId") || responseBody.Contains("token"))
            {
                baseConfidence += 0.25;
                confidenceFactors.Add("Session/token creation");
            }

            // Check for user information disclosure
            if (responseBody.Contains("username") || responseBody.Contains("email"))
            {
                baseConfidence += 0.2;
                confidenceFactors.Add("User information disclosed");
            }

            // Check for successful HTTP status
            if (statusCode == 200)
            {
                baseConfidence += 0.1;
                confidenceFactors.Add("Successful HTTP response");
            }

            // Penalize for authentication failure responses
            if (responseBody.Contains("unauthorized") || responseBody.Contains("forbidden"))
            {
                baseConfidence -= 0.3;
                confidenceFactors.Add("Authentication failure response");
            }

            // Check endpoint type for additional context
            if (endpoint.Contains("admin") || endpoint.Contains("login"))
            {
                baseConfidence += 0.1;
                confidenceFactors.Add("Authentication endpoint");
            }

            var finalConfidence = Math.Min(1.0, Math.Max(0.0, baseConfidence));

            _logger.Debug("Auth Bypass confidence: {Confidence:P1} - Factors: {Factors}", 
                finalConfidence, string.Join(", ", confidenceFactors));

            return finalConfidence;
        }

        /// <summary>
        /// Calculates confidence score for information disclosure vulnerabilities
        /// </summary>
        public double CalculateInformationDisclosureConfidence(string responseBody, int statusCode, string endpoint)
        {
            var baseConfidence = 0.0;
            var confidenceFactors = new List<string>();

            // Check for stack trace exposure
            if (responseBody.Contains("at ") && responseBody.Contains("line "))
            {
                baseConfidence += 0.4;
                confidenceFactors.Add("Stack trace exposure");
            }

            // Check for database information
            var dbKeywords = new[] { "connection string", "database", "sql server", "mysql", "postgresql" };
            foreach (var keyword in dbKeywords)
            {
                if (responseBody.ToLower().Contains(keyword))
                {
                    baseConfidence += 0.3;
                    confidenceFactors.Add($"Database information: {keyword}");
                    break;
                }
            }

            // Check for system information
            var systemKeywords = new[] { "machine name", "user name", "process id", "working directory" };
            foreach (var keyword in systemKeywords)
            {
                if (responseBody.ToLower().Contains(keyword))
                {
                    baseConfidence += 0.2;
                    confidenceFactors.Add($"System information: {keyword}");
                    break;
                }
            }

            // Check for environment variables
            if (responseBody.Contains("Environment") && responseBody.Contains("Variables"))
            {
                baseConfidence += 0.35;
                confidenceFactors.Add("Environment variables exposed");
            }

            // Check for debug information
            if (endpoint.Contains("debug") || endpoint.Contains("info"))
            {
                baseConfidence += 0.2;
                confidenceFactors.Add("Debug endpoint");
            }

            // Check for internal server error with details
            if (statusCode == 500 && responseBody.Length > 100)
            {
                baseConfidence += 0.15;
                confidenceFactors.Add("Detailed error response");
            }

            var finalConfidence = Math.Min(1.0, baseConfidence);

            _logger.Debug("Information Disclosure confidence: {Confidence:P1} - Factors: {Factors}", 
                finalConfidence, string.Join(", ", confidenceFactors));

            return finalConfidence;
        }

        /// <summary>
        /// Calculates confidence score for path traversal vulnerabilities
        /// </summary>
        public double CalculatePathTraversalConfidence(string payload, string responseBody, int statusCode)
        {
            var baseConfidence = 0.0;
            var confidenceFactors = new List<string>();

            // Check for successful file access
            if (responseBody.Contains("Content-Type:") || responseBody.Contains("Content-Length:"))
            {
                baseConfidence += 0.4;
                confidenceFactors.Add("File content returned");
            }

            // Check for directory listing
            if (responseBody.Contains("<html>") && responseBody.Contains("<body>"))
            {
                baseConfidence += 0.3;
                confidenceFactors.Add("Directory listing returned");
            }

            // Check for file system error messages
            var fsErrorPatterns = new[] { "file not found", "access denied", "permission denied", "no such file" };
            foreach (var pattern in fsErrorPatterns)
            {
                if (responseBody.ToLower().Contains(pattern))
                {
                    baseConfidence += 0.2;
                    confidenceFactors.Add($"File system error: {pattern}");
                    break;
                }
            }

            // Check for successful HTTP status
            if (statusCode == 200)
            {
                baseConfidence += 0.1;
                confidenceFactors.Add("Successful HTTP response");
            }

            // Check payload effectiveness
            if (payload.Contains("../") || payload.Contains("..\\"))
            {
                baseConfidence += 0.1;
                confidenceFactors.Add("Path traversal payload used");
            }

            var finalConfidence = Math.Min(1.0, baseConfidence);

            _logger.Debug("Path Traversal confidence: {Confidence:P1} - Factors: {Factors}", 
                finalConfidence, string.Join(", ", confidenceFactors));

            return finalConfidence;
        }

        /// <summary>
        /// Calculates overall confidence score based on multiple factors
        /// </summary>
        public double CalculateOverallConfidence(Vulnerability vulnerability)
        {
            var baseConfidence = vulnerability.Confidence;
            var adjustments = 0.0;

            // Adjust based on verification status
            if (vulnerability.Verified)
            {
                adjustments += 0.1;
            }

            // Adjust based on attack mode
            if (vulnerability.AttackMode == AttackMode.Aggressive)
            {
                adjustments += 0.05;
            }

            // Adjust based on severity (higher severity = higher confidence)
            switch (vulnerability.Severity)
            {
                case SeverityLevel.Critical:
                    adjustments += 0.1;
                    break;
                case SeverityLevel.High:
                    adjustments += 0.05;
                    break;
                case SeverityLevel.Low:
                    adjustments -= 0.05;
                    break;
            }

            // Adjust based on evidence quality
            if (!string.IsNullOrEmpty(vulnerability.Evidence) && vulnerability.Evidence.Length > 20)
            {
                adjustments += 0.05;
            }

            var finalConfidence = Math.Min(1.0, Math.Max(0.0, baseConfidence + adjustments));

            _logger.Debug("Overall confidence adjustment: {BaseConfidence:P1} + {Adjustments:P1} = {FinalConfidence:P1}", 
                baseConfidence, adjustments, finalConfidence);

            return finalConfidence;
        }
    }
}
