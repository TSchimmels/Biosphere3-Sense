using AttackAgent.Models;
using iTextSharp.text;
using iTextSharp.text.pdf;
using Serilog;
using System.Text;

namespace AttackAgent
{
    /// <summary>
    /// Simple PDF report generator for security testing results
    /// Creates basic but functional security reports
    /// </summary>
    public class SimplePdfReportGenerator
    {
        private readonly ILogger _logger;

        public SimplePdfReportGenerator()
        {
            _logger = Log.ForContext<SimplePdfReportGenerator>();
        }

        /// <summary>
        /// Generates a simple PDF security report
        /// </summary>
        public async Task<string> GeneratePdfReportAsync(VulnerabilityReport report, string outputDirectory, ApplicationProfile profile = null)
        {
            try
            {
                _logger.Information("📄 Generating PDF security report...");

                var fileName = $"security-report-{DateTime.Now:yyyyMMdd-HHmmss}.pdf";
                var filePath = Path.Combine(outputDirectory, fileName);

                using var fileStream = new FileStream(filePath, FileMode.Create);
                var document = new Document(PageSize.A4, 50, 50, 50, 50);
                var writer = PdfWriter.GetInstance(document, fileStream);

                document.Open();

                // Add title
                var titleFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 20);
                var title = new Paragraph("AI Attack Agent - Security Report", titleFont)
                {
                    Alignment = Element.ALIGN_CENTER,
                    SpacingAfter = 20
                };
                document.Add(title);

                // Add basic information
                var infoFont = FontFactory.GetFont(FontFactory.HELVETICA, 12);
                var info = new StringBuilder();
                info.AppendLine($"Target: {report.TargetUrl}");
                info.AppendLine($"Scan Date: {report.ScanStartTime:yyyy-MM-dd HH:mm:ss UTC}");
                info.AppendLine($"Duration: {report.ScanEndTime - report.ScanStartTime}");
                info.AppendLine($"Overall Risk Level: {report.OverallRiskLevel}");
                info.AppendLine();

                var infoParagraph = new Paragraph(info.ToString(), infoFont)
                {
                    SpacingAfter = 20
                };
                document.Add(infoParagraph);

                // Define fonts
                var summaryFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 14);

                // Add comprehensive discovery information if profile is available
                if (profile != null)
                {
                    AddDiscoveryInformation(document, profile, infoFont, summaryFont);
                }

                // Add EXECUTIVE SUMMARY SECTION (NEW - at the top for easy reading)
                var execSummaryFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 16);
                var execSummaryHeading = new Paragraph("EXECUTIVE SUMMARY", execSummaryFont)
                {
                    Alignment = Element.ALIGN_CENTER,
                    SpacingAfter = 15
                };
                document.Add(execSummaryHeading);

                // Group vulnerabilities by type for summary
                var vulnByType = report.Vulnerabilities
                    .GroupBy(v => v.Type)
                    .OrderByDescending(g => g.Count())
                    .ToList();

                var execSummary = new StringBuilder();
                execSummary.AppendLine($"Total Unique Vulnerabilities: {report.TotalVulnerabilities}");
                execSummary.AppendLine($"Overall Risk Level: {report.OverallRiskLevel}");
                execSummary.AppendLine();
                execSummary.AppendLine("VULNERABILITY TYPES FOUND:");
                execSummary.AppendLine("=========================");
                
                foreach (var typeGroup in vulnByType)
                {
                    var typeName = typeGroup.Key.ToString();
                    var count = typeGroup.Count();
                    var severity = typeGroup.First().Severity.ToString();
                    execSummary.AppendLine($"• {typeName}: {count} ({severity} severity)");
                }
                
                execSummary.AppendLine();
                execSummary.AppendLine("SEVERITY BREAKDOWN:");
                execSummary.AppendLine("===================");
                execSummary.AppendLine($"Critical: {report.Summary.CriticalCount}");
                execSummary.AppendLine($"High: {report.Summary.HighCount}");
                execSummary.AppendLine($"Medium: {report.Summary.MediumCount}");
                execSummary.AppendLine($"Low: {report.Summary.LowCount}");
                execSummary.AppendLine($"Info: {report.Summary.InfoCount}");

                var execSummaryParagraph = new Paragraph(execSummary.ToString(), infoFont)
                {
                    SpacingAfter = 20
                };
                document.Add(execSummaryParagraph);

                // Add vulnerability summary
                var summaryHeading = new Paragraph("Detailed Vulnerability Summary", summaryFont)
                {
                    SpacingAfter = 10
                };
                document.Add(summaryHeading);

                var summary = new StringBuilder();
                summary.AppendLine($"Total Vulnerabilities: {report.TotalVulnerabilities}");
                summary.AppendLine($"Critical: {report.Summary.CriticalCount}");
                summary.AppendLine($"High: {report.Summary.HighCount}");
                summary.AppendLine($"Medium: {report.Summary.MediumCount}");
                summary.AppendLine($"Low: {report.Summary.LowCount}");
                summary.AppendLine($"Info: {report.Summary.InfoCount}");

                var summaryParagraph = new Paragraph(summary.ToString(), infoFont)
                {
                    SpacingAfter = 20
                };
                document.Add(summaryParagraph);

                // Add vulnerability details - Group by type for better organization
                var detailsHeading = new Paragraph("Detailed Vulnerability Findings", summaryFont)
                {
                    SpacingAfter = 10
                };
                document.Add(detailsHeading);

                // Group vulnerabilities by type
                var vulnerabilitiesByType = report.Vulnerabilities
                    .GroupBy(v => v.Type)
                    .OrderByDescending(g => g.Count())
                    .ToList();

                foreach (var typeGroup in vulnerabilitiesByType)
                {
                    var typeName = typeGroup.Key.ToString();
                    var typeHeading = new Paragraph($"{typeName} Vulnerabilities ({typeGroup.Count()} found)", summaryFont)
                    {
                        SpacingBefore = 10,
                        SpacingAfter = 5
                    };
                    document.Add(typeHeading);

                    // Group by endpoint within this type
                    var byEndpoint = typeGroup
                        .GroupBy(v => $"{v.Method} {v.Endpoint}")
                        .OrderByDescending(g => g.Count())
                        .ToList();

                    foreach (var endpointGroup in byEndpoint)
                    {
                        var endpointVuln = endpointGroup.First(); // Use first as representative
                        var vulnDetails = new StringBuilder();
                        vulnDetails.AppendLine($"Endpoint: {endpointVuln.Method} {endpointVuln.Endpoint}");
                        vulnDetails.AppendLine($"Severity: {endpointVuln.Severity}");
                        vulnDetails.AppendLine($"Title: {endpointVuln.Title}");
                        
                        // If multiple payloads, mention it
                        if (endpointGroup.Count() > 1)
                        {
                            vulnDetails.AppendLine($"Note: This vulnerability was confirmed with {endpointGroup.Count()} different payloads.");
                        }
                        else if (!string.IsNullOrEmpty(endpointVuln.Payload))
                        {
                            vulnDetails.AppendLine($"Payload: {endpointVuln.Payload}");
                        }
                        
                        vulnDetails.AppendLine($"Description: {endpointVuln.Description}");
                        
                        // Only show evidence if it's not too long
                        if (!string.IsNullOrEmpty(endpointVuln.Evidence) && endpointVuln.Evidence.Length < 200)
                        {
                            vulnDetails.AppendLine($"Evidence: {endpointVuln.Evidence}");
                        }
                        
                        vulnDetails.AppendLine($"Remediation: {endpointVuln.Remediation}");
                        vulnDetails.AppendLine();

                        var vulnParagraph = new Paragraph(vulnDetails.ToString(), infoFont)
                        {
                            SpacingAfter = 10
                        };
                        document.Add(vulnParagraph);
                    }
                }

                // Add recommendations
                var recommendationsHeading = new Paragraph("Security Recommendations", summaryFont)
                {
                    SpacingAfter = 10
                };
                document.Add(recommendationsHeading);

                var recommendations = GenerateRecommendations(report);
                foreach (var recommendation in recommendations)
                {
                    var recParagraph = new Paragraph($"• {recommendation}", infoFont)
                    {
                        SpacingAfter = 5
                    };
                    document.Add(recParagraph);
                }

                // Add footer
                var footerFont = FontFactory.GetFont(FontFactory.HELVETICA, 8);
                var footer = new Paragraph($"Generated by AI Attack Agent on {DateTime.Now:yyyy-MM-dd HH:mm:ss UTC}", footerFont)
                {
                    Alignment = Element.ALIGN_CENTER,
                    SpacingBefore = 20
                };
                document.Add(footer);

                document.Close();

                _logger.Information("📄 PDF report generated successfully: {FilePath}", filePath);
                return filePath;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error generating PDF report");
                throw;
            }
        }

        /// <summary>
        /// Generates security recommendations based on findings
        /// </summary>
        private List<string> GenerateRecommendations(VulnerabilityReport report)
        {
            var recommendations = new List<string>();

            if (report.Summary.CriticalCount > 0)
            {
                recommendations.Add("Address all critical vulnerabilities immediately to prevent potential security breaches.");
            }

            if (report.Summary.HighCount > 0)
            {
                recommendations.Add("Prioritize high-severity vulnerabilities for remediation within 30 days.");
            }

            if (report.Vulnerabilities.Any(v => v.Type == VulnerabilityType.SqlInjection))
            {
                recommendations.Add("Implement parameterized queries and input validation to prevent SQL injection attacks.");
            }

            if (report.Vulnerabilities.Any(v => v.Type == VulnerabilityType.InformationDisclosure))
            {
                recommendations.Add("Remove sensitive information from source code and configuration files.");
                recommendations.Add("Use environment variables or secure key management services for credentials.");
            }

            if (report.Vulnerabilities.Any(v => v.Type == VulnerabilityType.WeakEncryption))
            {
                recommendations.Add("Enable HTTPS and implement proper SSL/TLS configuration.");
            }

            if (report.Vulnerabilities.Any(v => v.Type == VulnerabilityType.MissingSecurityHeaders))
            {
                recommendations.Add("Implement security headers (X-Content-Type-Options, X-Frame-Options, CSP, etc.).");
            }

            if (report.Vulnerabilities.Any(v => v.Type == VulnerabilityType.InsufficientRateLimiting))
            {
                recommendations.Add("Implement rate limiting to prevent DoS attacks and brute force attempts.");
            }

            recommendations.Add("Conduct regular security assessments and penetration testing.");
            recommendations.Add("Implement a secure development lifecycle (SDL) with security code reviews.");
            recommendations.Add("Keep all dependencies and frameworks updated to the latest secure versions.");

            return recommendations;
        }

        /// <summary>
        /// Adds comprehensive discovery information to the PDF
        /// </summary>
        private void AddDiscoveryInformation(Document document, ApplicationProfile profile, Font infoFont, Font summaryFont)
        {
            // Application Discovery Section
            var discoveryHeading = new Paragraph("Application Discovery Results", summaryFont)
            {
                SpacingAfter = 10
            };
            document.Add(discoveryHeading);

            var discovery = new StringBuilder();
            discovery.AppendLine($"Application Name: {profile.ApplicationName}");
            discovery.AppendLine($"Total Endpoints Discovered: {profile.TotalEndpoints}");
            discovery.AppendLine($"Framework: {profile.TechnologyStack.Framework}");
            discovery.AppendLine($"Programming Language: {profile.TechnologyStack.ProgrammingLanguage}");
            discovery.AppendLine($"Database: {profile.TechnologyStack.Database ?? "Unknown"}");
            discovery.AppendLine($"Web Server: {profile.TechnologyStack.WebServer ?? "Unknown"}");
            discovery.AppendLine($"ORM: {profile.TechnologyStack.Orm ?? "Unknown"}");
            discovery.AppendLine($"Confidence: {profile.TechnologyStack.Confidence:P2}");
            
            if (profile.TechnologyStack.DetectedLibraries.Any())
            {
                discovery.AppendLine($"Detected Libraries: {string.Join(", ", profile.TechnologyStack.DetectedLibraries)}");
            }
            
            discovery.AppendLine();

            var discoveryParagraph = new Paragraph(discovery.ToString(), infoFont)
            {
                SpacingAfter = 15
            };
            document.Add(discoveryParagraph);

            // Security Features Section
            var securityHeading = new Paragraph("Security Features Analysis", summaryFont)
            {
                SpacingAfter = 10
            };
            document.Add(securityHeading);

            var security = new StringBuilder();
            security.AppendLine($"HTTPS Enabled: {(profile.SecurityFeatures.HasHttps ? "Yes" : "No")}");
            security.AppendLine($"Security Headers: {(profile.SecurityFeatures.HasSecurityHeaders ? "Yes" : "No")}");
            security.AppendLine($"Rate Limiting: {(profile.SecurityFeatures.HasRateLimiting ? "Yes" : "No")}");
            security.AppendLine($"CORS Configuration: {(profile.SecurityFeatures.HasCors ? "Yes" : "No")}");
            security.AppendLine($"Camera Access: {(profile.SecurityFeatures.HasCameraAccess ? "Yes" : "No")}");
            security.AppendLine($"File Upload: {(profile.SecurityFeatures.HasFileUpload ? "Yes" : "No")}");
            
            if (!string.IsNullOrEmpty(profile.SecurityFeatures.CorsConfiguration))
            {
                security.AppendLine($"CORS Config: {profile.SecurityFeatures.CorsConfiguration}");
            }
            
            security.AppendLine();

            var securityParagraph = new Paragraph(security.ToString(), infoFont)
            {
                SpacingAfter = 15
            };
            document.Add(securityParagraph);

            // Authentication System Section
            if (profile.AuthenticationSystem.HasAuthentication)
            {
                var authHeading = new Paragraph("Authentication System Details", summaryFont)
                {
                    SpacingAfter = 10
                };
                document.Add(authHeading);

                var auth = new StringBuilder();
                auth.AppendLine($"Authentication Type: {profile.AuthenticationSystem.Type}");
                auth.AppendLine($"Token Type: {profile.AuthenticationSystem.TokenType ?? "Unknown"}");
                auth.AppendLine($"Authentication Endpoints: {profile.AuthenticationSystem.AuthenticationEndpoints.Count}");
                
                foreach (var authEndpoint in profile.AuthenticationSystem.AuthenticationEndpoints)
                {
                    auth.AppendLine($"  - {authEndpoint}");
                }
                
                auth.AppendLine();

                var authParagraph = new Paragraph(auth.ToString(), infoFont)
                {
                    SpacingAfter = 15
                };
                document.Add(authParagraph);
            }

            // Discovered Endpoints Section
            var endpointsHeading = new Paragraph("All Discovered Endpoints", summaryFont)
            {
                SpacingAfter = 10
            };
            document.Add(endpointsHeading);

            var endpoints = new StringBuilder();
            foreach (var endpoint in profile.DiscoveredEndpoints)
            {
                endpoints.AppendLine($"{endpoint.Method} {endpoint.Path} ({endpoint.StatusCode}) - {endpoint.ResponseTime.TotalMilliseconds:F2}ms");
            }
            endpoints.AppendLine();

            var endpointsParagraph = new Paragraph(endpoints.ToString(), infoFont)
            {
                SpacingAfter = 20
            };
            document.Add(endpointsParagraph);
        }
    }
}
