using AttackAgent.Data;
using AttackAgent.Models;
using Serilog;
using System.Text.RegularExpressions;

namespace AttackAgent.Core
{
    /// <summary>
    /// AI Learning Engine that adapts attack patterns based on application responses
    /// </summary>
    public class LearningEngine : IDisposable
    {
        private readonly AttackPatternDatabase _database;
        private readonly ReinforcementLearningEngine? _rlEngine;
        private readonly ILogger _logger;
        private bool _disposed = false;

        public LearningEngine(string databasePath = "attack_patterns.db", bool enableRL = true)
        {
            _database = new AttackPatternDatabase(databasePath);
            _logger = Log.ForContext<LearningEngine>();
            
            // Initialize RL engine if enabled
            if (enableRL)
            {
                try
                {
                    _rlEngine = new ReinforcementLearningEngine(databasePath);
                    _logger.Information("Reinforcement Learning enabled in LearningEngine");
                }
                catch (Exception ex)
                {
                    _logger.Warning(ex, "Failed to initialize RL engine, continuing without RL");
                }
            }
        }

        /// <summary>
        /// Learn from an attack result and update patterns accordingly
        /// </summary>
        public async Task LearnFromResultAsync(AttackResult result)
        {
            try
            {
                // Store the result in the database
                await _database.StoreAttackResultAsync(result);

                // Update the pattern's success rate
                await _database.UpdatePatternSuccessRateAsync(result.PatternId);

                // Update Q-value using reinforcement learning
                if (_rlEngine != null && !string.IsNullOrEmpty(result.TargetTechnology))
                {
                    await _rlEngine.UpdateQValueAsync(
                        result.TargetTechnology,
                        result.VulnerabilityType,
                        result.PatternId,
                        result.Success,
                        result.Confidence
                    );
                }

                // Analyze the result for learning opportunities
                await AnalyzeResultForLearningAsync(result);

                _logger.Debug("Learned from attack result: {ResultId}, Success: {Success}", 
                    result.Id, result.Success);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error learning from attack result: {ResultId}", result.Id);
            }
        }

        /// <summary>
        /// Get optimized attack patterns for a specific technology and vulnerability type
        /// </summary>
        public async Task<List<AttackPattern>> GetOptimizedPatternsAsync(
            string technology, 
            VulnerabilityType vulnerabilityType, 
            int maxPatterns = 10)
        {
            try
            {
                var patterns = await _database.GetOptimizedPatternsAsync(technology, vulnerabilityType);
                
                // Sort by success rate and usage count, then take the top patterns
                var optimizedPatterns = patterns
                    .OrderByDescending(p => p.SuccessRate)
                    .ThenByDescending(p => p.UsageCount)
                    .Take(maxPatterns)
                    .ToList();

                _logger.Debug("Retrieved {Count} optimized patterns for {Technology} {VulnType}", 
                    optimizedPatterns.Count, technology, vulnerabilityType);

                return optimizedPatterns;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error getting optimized patterns for {Technology}", technology);
                return new List<AttackPattern>();
            }
        }

        /// <summary>
        /// Analyze a response to determine if an attack was successful
        /// </summary>
        public async Task<AttackAnalysisResult> AnalyzeResponseAsync(
            string payload, 
            string responseBody, 
            int statusCode, 
            VulnerabilityType vulnerabilityType,
            string targetTechnology = "")
        {
            try
            {
                var result = new AttackAnalysisResult
                {
                    Payload = payload,
                    VulnerabilityType = vulnerabilityType,
                    TargetTechnology = targetTechnology,
                    ResponseCode = statusCode
                };

                // Get patterns for this vulnerability type
                var patterns = await _database.GetOptimizedPatternsAsync(targetTechnology, vulnerabilityType);
                
                // Analyze against success indicators
                foreach (var pattern in patterns)
                {
                    foreach (var indicator in pattern.SuccessIndicators)
                    {
                        if (MatchesIndicator(responseBody, statusCode, indicator))
                        {
                            result.Success = true;
                            result.Confidence = Math.Max(result.Confidence, indicator.Confidence);
                            result.Evidence = indicator.Description;
                            result.MatchedIndicator = indicator.Name;
                        }
                    }

                    // Check failure indicators
                    foreach (var indicator in pattern.FailureIndicators)
                    {
                        if (MatchesIndicator(responseBody, statusCode, indicator))
                        {
                            result.Success = false;
                            result.Confidence = Math.Max(result.Confidence, indicator.Confidence);
                            result.Evidence = indicator.Description;
                            result.MatchedIndicator = indicator.Name;
                            break; // Failure indicators override success
                        }
                    }
                }

                // If no specific indicators matched, use heuristics
                if (result.Confidence == 0.0)
                {
                    result = ApplyHeuristicAnalysis(result, responseBody, statusCode, vulnerabilityType);
                }

                _logger.Debug("Analyzed response: Success={Success}, Confidence={Confidence}", 
                    result.Success, result.Confidence);

                return result;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error analyzing response for payload: {Payload}", payload);
                return new AttackAnalysisResult
                {
                    Payload = payload,
                    Success = false,
                    Confidence = 0.0,
                    ErrorMessage = ex.Message
                };
            }
        }

        /// <summary>
        /// Check if a response matches a specific indicator
        /// </summary>
        private bool MatchesIndicator(string responseBody, int statusCode, SuccessIndicator indicator)
        {
            try
            {
                switch (indicator.Type)
                {
                    case IndicatorType.ResponseCode:
                        return statusCode.ToString().Contains(indicator.Pattern);
                    
                    case IndicatorType.ResponseBody:
                        return responseBody.Contains(indicator.Pattern, StringComparison.OrdinalIgnoreCase) ||
                               Regex.IsMatch(responseBody, indicator.Pattern, RegexOptions.IgnoreCase);
                    
                    case IndicatorType.ErrorMessage:
                        return responseBody.Contains(indicator.Pattern, StringComparison.OrdinalIgnoreCase);
                    
                    case IndicatorType.DatabaseError:
                        return ContainsDatabaseError(responseBody, indicator.Pattern);
                    
                    case IndicatorType.FrameworkError:
                        return ContainsFrameworkError(responseBody, indicator.Pattern);
                    
                    default:
                        return false;
                }
            }
            catch (Exception ex)
            {
                _logger.Warning(ex, "Error matching indicator: {IndicatorName}", indicator.Name);
                return false;
            }
        }

        /// <summary>
        /// Check if a response matches a failure indicator
        /// </summary>
        private bool MatchesIndicator(string responseBody, int statusCode, FailureIndicator indicator)
        {
            try
            {
                switch (indicator.Type)
                {
                    case IndicatorType.ResponseCode:
                        return statusCode.ToString().Contains(indicator.Pattern);
                    
                    case IndicatorType.ResponseBody:
                        return responseBody.Contains(indicator.Pattern, StringComparison.OrdinalIgnoreCase) ||
                               Regex.IsMatch(responseBody, indicator.Pattern, RegexOptions.IgnoreCase);
                    
                    case IndicatorType.ErrorMessage:
                        return responseBody.Contains(indicator.Pattern, StringComparison.OrdinalIgnoreCase);
                    
                    default:
                        return false;
                }
            }
            catch (Exception ex)
            {
                _logger.Warning(ex, "Error matching failure indicator: {IndicatorName}", indicator.Name);
                return false;
            }
        }

        /// <summary>
        /// Apply heuristic analysis when no specific indicators match
        /// </summary>
        private AttackAnalysisResult ApplyHeuristicAnalysis(
            AttackAnalysisResult result, 
            string responseBody, 
            int statusCode, 
            VulnerabilityType vulnerabilityType)
        {
            // SQL Injection heuristics
            if (vulnerabilityType == VulnerabilityType.SqlInjection)
            {
                var sqlErrorPatterns = new[]
                {
                    "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "SQLite", "Microsoft Access Driver",
                    "ODBC SQL Server Driver", "SQLServer JDBC Driver", "MySQLSyntaxErrorException"
                };

                foreach (var pattern in sqlErrorPatterns)
                {
                    if (responseBody.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        result.Success = true;
                        result.Confidence = 0.8;
                        result.Evidence = $"SQL error detected: {pattern}";
                        return result;
                    }
                }
            }

            // XSS heuristics
            if (vulnerabilityType == VulnerabilityType.ReflectedXss || 
                vulnerabilityType == VulnerabilityType.StoredXss)
            {
                if (responseBody.Contains(result.Payload, StringComparison.OrdinalIgnoreCase))
                {
                    result.Success = true;
                    result.Confidence = 0.7;
                    result.Evidence = "Payload reflected in response";
                    return result;
                }
            }

            // Authentication bypass heuristics
            if (vulnerabilityType == VulnerabilityType.AuthenticationBypass)
            {
                if (statusCode == 200 && responseBody.Contains("dashboard", StringComparison.OrdinalIgnoreCase))
                {
                    result.Success = true;
                    result.Confidence = 0.6;
                    result.Evidence = "Successful authentication bypass - dashboard access";
                    return result;
                }
            }

            // Default: assume failure
            result.Success = false;
            result.Confidence = 0.3;
            result.Evidence = "No specific indicators matched";

            return result;
        }

        /// <summary>
        /// Check for database-specific error patterns
        /// </summary>
        private bool ContainsDatabaseError(string responseBody, string pattern)
        {
            var databaseErrors = new Dictionary<string, string[]>
            {
                { "MySQL", new[] { "mysql_fetch", "MySQLSyntaxErrorException", "Access denied for user" } },
                { "PostgreSQL", new[] { "PostgreSQL", "pg_query", "FATAL:" } },
                { "SQL Server", new[] { "Microsoft OLE DB Provider", "ODBC SQL Server Driver", "SQLServer JDBC Driver" } },
                { "Oracle", new[] { "ORA-", "Oracle error", "OracleException" } },
                { "SQLite", new[] { "SQLite error", "SQLiteException" } }
            };

            if (databaseErrors.ContainsKey(pattern))
            {
                return databaseErrors[pattern].Any(error => 
                    responseBody.Contains(error, StringComparison.OrdinalIgnoreCase));
            }

            return responseBody.Contains(pattern, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Check for framework-specific error patterns
        /// </summary>
        private bool ContainsFrameworkError(string responseBody, string pattern)
        {
            var frameworkErrors = new Dictionary<string, string[]>
            {
                { "ASP.NET", new[] { "System.Web.HttpException", "ASP.NET", "Server Error in Application" } },
                { "PHP", new[] { "PHP Fatal error", "PHP Parse error", "PHP Warning" } },
                { "Java", new[] { "java.lang.", "ServletException", "NullPointerException" } },
                { "Python", new[] { "Traceback", "Python", "Django" } },
                { "Node.js", new[] { "Error:", "TypeError", "ReferenceError" } }
            };

            if (frameworkErrors.ContainsKey(pattern))
            {
                return frameworkErrors[pattern].Any(error => 
                    responseBody.Contains(error, StringComparison.OrdinalIgnoreCase));
            }

            return responseBody.Contains(pattern, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Analyze result for additional learning opportunities
        /// </summary>
        private async Task AnalyzeResultForLearningAsync(AttackResult result)
        {
            // This could be expanded to:
            // - Identify new attack patterns
            // - Update technology mappings
            // - Adjust confidence scores
            // - Detect false positives
            
            await Task.CompletedTask; // Placeholder for future learning logic
        }

        /// <summary>
        /// Get learning metrics and statistics
        /// </summary>
        public async Task<Dictionary<string, double>> GetLearningMetricsAsync()
        {
            try
            {
                return await _database.GetLearningMetricsAsync();
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error getting learning metrics");
                return new Dictionary<string, double>();
            }
        }

        /// <summary>
        /// Gets RL statistics if RL is enabled
        /// </summary>
        public QLearningStatistics? GetRLStatistics()
        {
            return _rlEngine?.GetStatistics();
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _rlEngine?.Dispose();
                _database?.Dispose();
                _disposed = true;
            }
        }
    }

    /// <summary>
    /// Result of analyzing an attack response
    /// </summary>
    public class AttackAnalysisResult
    {
        public string Payload { get; set; } = string.Empty;
        public VulnerabilityType VulnerabilityType { get; set; }
        public string TargetTechnology { get; set; } = string.Empty;
        public int ResponseCode { get; set; }
        public bool Success { get; set; }
        public double Confidence { get; set; }
        public string Evidence { get; set; } = string.Empty;
        public string MatchedIndicator { get; set; } = string.Empty;
        public string ErrorMessage { get; set; } = string.Empty;
    }
}

