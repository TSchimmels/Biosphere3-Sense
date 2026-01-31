using AttackAgent.Models;
using AttackAgent.Services;
using Serilog;
using System.Text.Json;

namespace AttackAgent.Reporting
{
    /// <summary>
    /// Enhanced report generator with optimization and improved presentation
    /// </summary>
    public class EnhancedReportGenerator
    {
        private readonly VulnerabilityDeduplicationService _deduplicationService;
        private readonly ConfidenceScoringService _confidenceService;
        private readonly ILogger _logger;

        public EnhancedReportGenerator()
        {
            _deduplicationService = new VulnerabilityDeduplicationService();
            _confidenceService = new ConfidenceScoringService();
            _logger = Log.ForContext<EnhancedReportGenerator>();
        }

        /// <summary>
        /// Generates optimized reports with deduplication and improved presentation
        /// </summary>
        public async Task<OptimizedVulnerabilityReport> GenerateOptimizedReportAsync(
            VulnerabilityReport originalReport, ApplicationProfile profile)
        {
            _logger.Information("📊 Generating optimized vulnerability report...");

            // Step 1: Deduplicate vulnerabilities
            var deduplicatedVulns = _deduplicationService.DeduplicateVulnerabilities(originalReport.Vulnerabilities);
            _logger.Information("✅ Deduplication: {Original} → {Deduplicated} vulnerabilities", 
                originalReport.Vulnerabilities.Count, deduplicatedVulns.Count);

            // Step 2: Filter false positives
            var filteredVulns = _deduplicationService.FilterFalsePositives(deduplicatedVulns, 0.6);
            _logger.Information("✅ False positive filtering: {Deduplicated} → {Filtered} vulnerabilities", 
                deduplicatedVulns.Count, filteredVulns.Count);

            // Step 3: Enhance confidence scores
            var enhancedVulns = await EnhanceVulnerabilityConfidenceAsync(filteredVulns);
            _logger.Information("✅ Confidence enhancement completed for {Count} vulnerabilities", enhancedVulns.Count);

            // Step 4: Group vulnerabilities by endpoint
            var groupedVulns = _deduplicationService.GroupVulnerabilitiesByEndpoint(enhancedVulns);

            // Step 5: Generate distribution summary
            var distributionSummary = _deduplicationService.GenerateDistributionSummary(enhancedVulns);

            // Step 6: Create optimized report
            var optimizedReport = new OptimizedVulnerabilityReport
            {
                TargetUrl = originalReport.TargetUrl,
                ScanStartTime = originalReport.ScanStartTime,
                ScanEndTime = originalReport.ScanEndTime,
                ScanDuration = originalReport.ScanEndTime - originalReport.ScanStartTime,
                
                // Optimized vulnerability data
                Vulnerabilities = enhancedVulns,
                GroupedVulnerabilities = groupedVulns,
                DistributionSummary = distributionSummary,
                
                // Enhanced summary
                Summary = CalculateOptimizedSummary(enhancedVulns),
                OverallRiskLevel = CalculateOptimizedRiskLevel(enhancedVulns),
                
                // Optimization metrics
                OptimizationMetrics = new OptimizationMetrics
                {
                    OriginalVulnerabilityCount = originalReport.Vulnerabilities.Count,
                    DeduplicatedCount = deduplicatedVulns.Count,
                    FilteredCount = filteredVulns.Count,
                    FinalCount = enhancedVulns.Count,
                    DeduplicationRate = (double)(originalReport.Vulnerabilities.Count - deduplicatedVulns.Count) / originalReport.Vulnerabilities.Count,
                    FalsePositiveRate = (double)(deduplicatedVulns.Count - filteredVulns.Count) / deduplicatedVulns.Count,
                    OverallReductionRate = (double)(originalReport.Vulnerabilities.Count - enhancedVulns.Count) / originalReport.Vulnerabilities.Count
                },

                // Application context
                ApplicationProfile = profile,
                Recommendations = GenerateRecommendations(enhancedVulns, profile)
            };

            _logger.Information("✅ Optimized report generated successfully");
            _logger.Information("📊 Final metrics: {FinalCount} vulnerabilities, {ReductionRate:P1} reduction", 
                enhancedVulns.Count, optimizedReport.OptimizationMetrics.OverallReductionRate);

            return optimizedReport;
        }

        /// <summary>
        /// Enhances confidence scores for vulnerabilities
        /// </summary>
        private async Task<List<Vulnerability>> EnhanceVulnerabilityConfidenceAsync(List<Vulnerability> vulnerabilities)
        {
            var enhancedVulns = new List<Vulnerability>();

            foreach (var vuln in vulnerabilities)
            {
                var enhancedVuln = vuln;
                
                // Recalculate confidence based on vulnerability type
                switch (vuln.Type)
                {
                    case VulnerabilityType.SqlInjection:
                        enhancedVuln.Confidence = _confidenceService.CalculateSqlInjectionConfidence(
                            vuln.Payload ?? "", vuln.Response ?? "", 200, "Unknown");
                        break;
                    case VulnerabilityType.ReflectedXss:
                    case VulnerabilityType.StoredXss:
                        enhancedVuln.Confidence = _confidenceService.CalculateXssConfidence(
                            vuln.Payload ?? "", vuln.Response ?? "", 200);
                        break;
                    case VulnerabilityType.AuthenticationBypass:
                        enhancedVuln.Confidence = _confidenceService.CalculateAuthBypassConfidence(
                            vuln.Payload ?? "", vuln.Response ?? "", 200, vuln.Endpoint);
                        break;
                    case VulnerabilityType.InformationDisclosure:
                    case VulnerabilityType.ErrorInformationDisclosure:
                        enhancedVuln.Confidence = _confidenceService.CalculateInformationDisclosureConfidence(
                            vuln.Response ?? "", 200, vuln.Endpoint);
                        break;
                    case VulnerabilityType.PathTraversal:
                        enhancedVuln.Confidence = _confidenceService.CalculatePathTraversalConfidence(
                            vuln.Payload ?? "", vuln.Response ?? "", 200);
                        break;
                }

                // Apply overall confidence enhancement
                enhancedVuln.Confidence = _confidenceService.CalculateOverallConfidence(enhancedVuln);

                // Update verification status based on enhanced confidence
                enhancedVuln.Verified = enhancedVuln.Confidence >= 0.8;

                enhancedVulns.Add(enhancedVuln);
            }

            return enhancedVulns;
        }

        /// <summary>
        /// Calculates optimized vulnerability summary
        /// </summary>
        private VulnerabilitySummary CalculateOptimizedSummary(List<Vulnerability> vulnerabilities)
        {
            var summary = new VulnerabilitySummary();

            foreach (var vuln in vulnerabilities)
            {
                switch (vuln.Severity)
                {
                    case SeverityLevel.Critical:
                        summary.CriticalCount++;
                        break;
                    case SeverityLevel.High:
                        summary.HighCount++;
                        break;
                    case SeverityLevel.Medium:
                        summary.MediumCount++;
                        break;
                    case SeverityLevel.Low:
                        summary.LowCount++;
                        break;
                    case SeverityLevel.Info:
                        summary.InfoCount++;
                        break;
                }

                if (summary.VulnerabilityTypes.ContainsKey(vuln.Type))
                    summary.VulnerabilityTypes[vuln.Type]++;
                else
                    summary.VulnerabilityTypes[vuln.Type] = 1;

                if (vuln.FalsePositive)
                    summary.FalsePositiveCount++;

                if (vuln.Verified)
                    summary.VerifiedCount++;
            }

            summary.EndpointsAffected = vulnerabilities.Select(v => v.Endpoint).Distinct().Count();

            return summary;
        }

        /// <summary>
        /// Calculates optimized risk level
        /// </summary>
        private RiskLevel CalculateOptimizedRiskLevel(List<Vulnerability> vulnerabilities)
        {
            var criticalCount = vulnerabilities.Count(v => v.Severity == SeverityLevel.Critical);
            var highCount = vulnerabilities.Count(v => v.Severity == SeverityLevel.High);
            var mediumCount = vulnerabilities.Count(v => v.Severity == SeverityLevel.Medium);

            if (criticalCount > 0)
                return RiskLevel.Critical;
            else if (highCount >= 2) // Lowered threshold for optimized reports
                return RiskLevel.High;
            else if (highCount > 0 || mediumCount >= 3) // Lowered threshold
                return RiskLevel.Medium;
            else
                return RiskLevel.Low;
        }

        /// <summary>
        /// Generates actionable recommendations based on vulnerabilities and application profile
        /// </summary>
        private List<SecurityRecommendation> GenerateRecommendations(List<Vulnerability> vulnerabilities, ApplicationProfile profile)
        {
            var recommendations = new List<SecurityRecommendation>();

            // SQL Injection recommendations
            if (vulnerabilities.Any(v => v.Type == VulnerabilityType.SqlInjection))
            {
                recommendations.Add(new SecurityRecommendation
                {
                    Priority = Priority.High,
                    Category = "SQL Injection",
                    Title = "Implement Parameterized Queries",
                    Description = "Replace raw SQL queries with parameterized queries or prepared statements to prevent SQL injection attacks.",
                    ImplementationSteps = new List<string>
                    {
                        "Replace string concatenation with parameterized queries",
                        "Use Entity Framework LINQ queries instead of raw SQL",
                        "Validate and sanitize all user inputs",
                        "Implement input validation at the application layer"
                    },
                    AffectedEndpoints = vulnerabilities.Where(v => v.Type == VulnerabilityType.SqlInjection)
                        .Select(v => v.Endpoint).Distinct().ToList()
                });
            }

            // XSS recommendations
            if (vulnerabilities.Any(v => v.Type == VulnerabilityType.ReflectedXss || v.Type == VulnerabilityType.StoredXss))
            {
                recommendations.Add(new SecurityRecommendation
                {
                    Priority = Priority.High,
                    Category = "Cross-Site Scripting (XSS)",
                    Title = "Implement Output Encoding and Input Validation",
                    Description = "Prevent XSS attacks by properly encoding output and validating input.",
                    ImplementationSteps = new List<string>
                    {
                        "Encode all user-controlled data before output",
                        "Implement Content Security Policy (CSP) headers",
                        "Use HTML encoding for web output",
                        "Validate and sanitize user inputs"
                    },
                    AffectedEndpoints = vulnerabilities.Where(v => v.Type == VulnerabilityType.ReflectedXss || v.Type == VulnerabilityType.StoredXss)
                        .Select(v => v.Endpoint).Distinct().ToList()
                });
            }

            // Authentication recommendations
            if (vulnerabilities.Any(v => v.Type == VulnerabilityType.AuthenticationBypass || v.Type == VulnerabilityType.WeakAuthentication))
            {
                recommendations.Add(new SecurityRecommendation
                {
                    Priority = Priority.Critical,
                    Category = "Authentication Security",
                    Title = "Strengthen Authentication Mechanisms",
                    Description = "Implement strong authentication and authorization controls.",
                    ImplementationSteps = new List<string>
                    {
                        "Replace MD5 with bcrypt or Argon2 for password hashing",
                        "Implement multi-factor authentication",
                        "Add rate limiting to authentication endpoints",
                        "Use secure session management",
                        "Implement proper authorization checks"
                    },
                    AffectedEndpoints = vulnerabilities.Where(v => v.Type == VulnerabilityType.AuthenticationBypass || v.Type == VulnerabilityType.WeakAuthentication)
                        .Select(v => v.Endpoint).Distinct().ToList()
                });
            }

            // Security headers recommendations
            if (vulnerabilities.Any(v => v.Type == VulnerabilityType.MissingSecurityHeaders))
            {
                recommendations.Add(new SecurityRecommendation
                {
                    Priority = Priority.Medium,
                    Category = "Security Headers",
                    Title = "Implement Security Headers",
                    Description = "Add security headers to protect against various client-side attacks.",
                    ImplementationSteps = new List<string>
                    {
                        "Add X-Content-Type-Options: nosniff",
                        "Add X-Frame-Options: DENY",
                        "Add X-XSS-Protection: 1; mode=block",
                        "Add Strict-Transport-Security header",
                        "Implement Content-Security-Policy"
                    },
                    AffectedEndpoints = new List<string> { "All endpoints" }
                });
            }

            // HTTPS recommendations
            if (!profile.SecurityFeatures.HasHttps)
            {
                recommendations.Add(new SecurityRecommendation
                {
                    Priority = Priority.High,
                    Category = "Transport Security",
                    Title = "Enable HTTPS",
                    Description = "Enable HTTPS to protect data in transit.",
                    ImplementationSteps = new List<string>
                    {
                        "Obtain SSL/TLS certificates",
                        "Configure HTTPS redirection",
                        "Implement HSTS (HTTP Strict Transport Security)",
                        "Update all internal links to use HTTPS"
                    },
                    AffectedEndpoints = new List<string> { "All endpoints" }
                });
            }

            return recommendations;
        }

        /// <summary>
        /// Generates optimized JSON report
        /// </summary>
        public async Task<string> GenerateOptimizedJsonReportAsync(OptimizedVulnerabilityReport report, string outputDir)
        {
            try
            {
                var jsonPath = Path.Combine(outputDir, $"optimized-security-report-{DateTime.Now:yyyyMMdd-HHmmss}.json");
                
                // Create a compact version for large reports
                var compactReport = new
                {
                    report.TargetUrl,
                    report.ScanStartTime,
                    report.ScanEndTime,
                    report.ScanDuration,
                    report.OverallRiskLevel,
                    OptimizationMetrics = report.OptimizationMetrics,
                    Summary = report.Summary,
                    DistributionSummary = report.DistributionSummary,
                    TopVulnerabilities = report.Vulnerabilities
                        .OrderByDescending(v => v.Severity)
                        .ThenByDescending(v => v.Confidence)
                        .Take(20) // Limit to top 20 vulnerabilities
                        .Select(v => new
                        {
                            v.Type,
                            v.Severity,
                            v.Title,
                            v.Endpoint,
                            v.Method,
                            v.Confidence,
                            v.Verified,
                            Evidence = v.Evidence?.Length > 200 ? v.Evidence.Substring(0, 200) + "..." : v.Evidence
                        }),
                    Recommendations = report.Recommendations.Select(r => new
                    {
                        r.Priority,
                        r.Category,
                        r.Title,
                        r.Description,
                        ImplementationSteps = r.ImplementationSteps.Take(5) // Limit to first 5 steps
                    })
                };

                var json = JsonSerializer.Serialize(compactReport, new JsonSerializerOptions 
                { 
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                });
                
                await File.WriteAllTextAsync(jsonPath, json);
                _logger.Information("📄 Optimized JSON report generated: {JsonPath}", jsonPath);
                
                return jsonPath;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error generating optimized JSON report");
                throw;
            }
        }

        /// <summary>
        /// Generates executive summary report
        /// </summary>
        public async Task<string> GenerateExecutiveSummaryAsync(OptimizedVulnerabilityReport report, string outputDir)
        {
            try
            {
                var summaryPath = Path.Combine(outputDir, $"executive-summary-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
                
                using var writer = new StreamWriter(summaryPath);
                
                await writer.WriteLineAsync("EXECUTIVE SECURITY SUMMARY");
                await writer.WriteLineAsync("==========================");
                await writer.WriteLineAsync();
                await writer.WriteLineAsync($"Target Application: {report.TargetUrl}");
                await writer.WriteLineAsync($"Assessment Date: {report.ScanStartTime:yyyy-MM-dd HH:mm:ss}");
                await writer.WriteLineAsync($"Scan Duration: {report.ScanDuration}");
                await writer.WriteLineAsync($"Overall Risk Level: {report.OverallRiskLevel}");
                await writer.WriteLineAsync();
                
                await writer.WriteLineAsync("VULNERABILITY SUMMARY");
                await writer.WriteLineAsync("=====================");
                await writer.WriteLineAsync($"Total Vulnerabilities: {report.Summary.CriticalCount + report.Summary.HighCount + report.Summary.MediumCount + report.Summary.LowCount}");
                await writer.WriteLineAsync($"Critical: {report.Summary.CriticalCount}");
                await writer.WriteLineAsync($"High: {report.Summary.HighCount}");
                await writer.WriteLineAsync($"Medium: {report.Summary.MediumCount}");
                await writer.WriteLineAsync($"Low: {report.Summary.LowCount}");
                await writer.WriteLineAsync();
                
                await writer.WriteLineAsync("OPTIMIZATION METRICS");
                await writer.WriteLineAsync("===================");
                await writer.WriteLineAsync($"Original Findings: {report.OptimizationMetrics.OriginalVulnerabilityCount}");
                await writer.WriteLineAsync($"After Deduplication: {report.OptimizationMetrics.DeduplicatedCount}");
                await writer.WriteLineAsync($"After False Positive Filtering: {report.OptimizationMetrics.FilteredCount}");
                await writer.WriteLineAsync($"Final Report: {report.OptimizationMetrics.FinalCount}");
                await writer.WriteLineAsync($"Overall Reduction: {report.OptimizationMetrics.OverallReductionRate:P1}");
                await writer.WriteLineAsync();
                
                await writer.WriteLineAsync("TOP PRIORITY RECOMMENDATIONS");
                await writer.WriteLineAsync("===========================");
                var topRecommendations = report.Recommendations
                    .OrderByDescending(r => r.Priority)
                    .Take(5);
                
                foreach (var rec in topRecommendations)
                {
                    await writer.WriteLineAsync($"• {rec.Title} ({rec.Priority})");
                    await writer.WriteLineAsync($"  {rec.Description}");
                    await writer.WriteLineAsync();
                }
                
                _logger.Information("📄 Executive summary generated: {SummaryPath}", summaryPath);
                return summaryPath;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error generating executive summary");
                throw;
            }
        }
    }

    /// <summary>
    /// Optimized vulnerability report with enhanced data structure
    /// </summary>
    public class OptimizedVulnerabilityReport
    {
        public string TargetUrl { get; set; } = string.Empty;
        public DateTime ScanStartTime { get; set; }
        public DateTime ScanEndTime { get; set; }
        public TimeSpan ScanDuration { get; set; }
        public RiskLevel OverallRiskLevel { get; set; }
        
        public List<Vulnerability> Vulnerabilities { get; set; } = new();
        public Dictionary<string, List<Vulnerability>> GroupedVulnerabilities { get; set; } = new();
        public VulnerabilityDistributionSummary DistributionSummary { get; set; } = new();
        
        public VulnerabilitySummary Summary { get; set; } = new();
        public OptimizationMetrics OptimizationMetrics { get; set; } = new();
        
        public ApplicationProfile ApplicationProfile { get; set; } = new();
        public List<SecurityRecommendation> Recommendations { get; set; } = new();
    }

    /// <summary>
    /// Optimization metrics for reporting
    /// </summary>
    public class OptimizationMetrics
    {
        public int OriginalVulnerabilityCount { get; set; }
        public int DeduplicatedCount { get; set; }
        public int FilteredCount { get; set; }
        public int FinalCount { get; set; }
        public double DeduplicationRate { get; set; }
        public double FalsePositiveRate { get; set; }
        public double OverallReductionRate { get; set; }
    }

    /// <summary>
    /// Security recommendation with implementation details
    /// </summary>
    public class SecurityRecommendation
    {
        public Priority Priority { get; set; }
        public string Category { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public List<string> ImplementationSteps { get; set; } = new();
        public List<string> AffectedEndpoints { get; set; } = new();
    }

    /// <summary>
    /// Priority levels for recommendations
    /// </summary>
    public enum Priority
    {
        Low,
        Medium,
        High,
        Critical
    }
}
