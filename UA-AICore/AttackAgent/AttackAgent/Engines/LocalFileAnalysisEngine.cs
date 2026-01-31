using System.Text.RegularExpressions;
using System.Text.Json;
using Serilog;

namespace AttackAgent.Engines
{
    /// <summary>
    /// Local file analysis engine for direct file system access
    /// Analyzes local configuration files for exposed credentials and sensitive data
    /// </summary>
    public class LocalFileAnalysisEngine
    {
        /// <summary>
        /// Comprehensive local file analysis
        /// </summary>
        public async Task<LocalFileAnalysisReport> AnalyzeLocalFilesAsync(string[] filePaths)
        {
            Log.Information("📄 Starting local file analysis...");
            
            var report = new LocalFileAnalysisReport
            {
                StartTime = DateTime.UtcNow,
                AnalyzedFiles = new List<AnalyzedFile>()
            };

            foreach (var filePath in filePaths)
            {
                try
                {
                    Log.Information("🔍 Analyzing file: {FilePath}", filePath);
                    
                    if (!File.Exists(filePath))
                    {
                        Log.Warning("⚠️ File not found: {FilePath}", filePath);
                        continue;
                    }

                    var fileInfo = new FileInfo(filePath);
                    var content = await File.ReadAllTextAsync(filePath);
                    
                    var analyzedFile = new AnalyzedFile
                    {
                        FilePath = filePath,
                        FileName = fileInfo.Name,
                        FileSize = fileInfo.Length,
                        LastModified = fileInfo.LastWriteTime,
                        Content = content,
                        FileType = DetermineFileType(fileInfo.Name),
                        SensitiveData = ExtractSensitiveData(content, fileInfo.Name),
                        Credentials = ExtractCredentials(content, fileInfo.Name),
                        RiskLevel = CalculateRiskLevel(content, fileInfo.Name)
                    };

                    report.AnalyzedFiles.Add(analyzedFile);
                    
                    Log.Information("✅ Analyzed {FileName}: {RiskLevel} risk, {CredentialCount} credentials found", 
                        fileInfo.Name, analyzedFile.RiskLevel, analyzedFile.Credentials.Count);
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "❌ Failed to analyze file: {FilePath}", filePath);
                }
            }

            report.EndTime = DateTime.UtcNow;
            report.Duration = report.EndTime - report.StartTime;
            report.TotalFiles = filePaths.Length;
            report.SuccessfullyAnalyzed = report.AnalyzedFiles.Count;
            report.HighRiskFiles = report.AnalyzedFiles.Count(f => f.RiskLevel == "High");
            report.CredentialsFound = report.AnalyzedFiles.Sum(f => f.Credentials.Count);

            Log.Information("✅ Local file analysis completed. Analyzed {Count}/{Total} files, found {Credentials} credentials", 
                report.SuccessfullyAnalyzed, report.TotalFiles, report.CredentialsFound);

            return report;
        }

        /// <summary>
        /// Determine file type based on extension and content
        /// </summary>
        private string DetermineFileType(string fileName)
        {
            var extension = Path.GetExtension(fileName).ToLowerInvariant();
            
            return extension switch
            {
                ".json" => "JSON Configuration",
                ".xml" => "XML Configuration", 
                ".yaml" or ".yml" => "YAML Configuration",
                ".env" => "Environment Variables",
                ".config" => "Configuration File",
                ".properties" => "Properties File",
                ".ini" => "INI Configuration",
                ".conf" => "Configuration File",
                ".txt" => "Text File",
                ".log" => "Log File",
                ".sql" => "SQL File",
                ".cs" => "C# Source Code",
                ".js" => "JavaScript",
                ".py" => "Python Source Code",
                ".php" => "PHP Source Code",
                ".java" => "Java Source Code",
                _ => "Unknown"
            };
        }

        /// <summary>
        /// Extract sensitive data from file content
        /// </summary>
        private List<SensitiveDataItem> ExtractSensitiveData(string content, string fileName)
        {
            var sensitiveData = new List<SensitiveDataItem>();
            var fileType = DetermineFileType(fileName);

            // API Keys and Tokens
            var apiKeyPatterns = new[]
            {
                @"(?:api[_-]?key|apikey|api_key)\s*[:=]\s*['""]?([a-zA-Z0-9_\-\.]{20,})['""]?",
                @"(?:token|access_token|bearer_token)\s*[:=]\s*['""]?([a-zA-Z0-9_\-\.]{20,})['""]?",
                @"(?:secret|secret_key|client_secret)\s*[:=]\s*['""]?([a-zA-Z0-9_\-\.]{20,})['""]?",
                @"sk-[a-zA-Z0-9]{20,}", // OpenAI API keys
                @"pk_[a-zA-Z0-9]{20,}", // Stripe public keys
                @"sk_live_[a-zA-Z0-9]{20,}", // Stripe live keys
                @"AIza[0-9A-Za-z\\-_]{35}", // Google API keys
                @"ya29\.[0-9A-Za-z\\-_]+", // Google OAuth tokens
                @"1//[0-9A-Za-z\\-_]+", // Google OAuth refresh tokens
            };

            foreach (var pattern in apiKeyPatterns)
            {
                var matches = Regex.Matches(content, pattern, RegexOptions.IgnoreCase);
                foreach (Match match in matches)
                {
                    var value = match.Groups.Count > 1 ? match.Groups[1].Value : match.Value;
                    sensitiveData.Add(new SensitiveDataItem
                    {
                        Type = "API Key/Token",
                        Value = value,
                        Pattern = pattern,
                        LineNumber = GetLineNumber(content, match.Index),
                        Severity = "High"
                    });
                }
            }

            // Database Connection Strings
            var dbPatterns = new[]
            {
                @"(?:connectionstring|connection_string|database_url|db_url)\s*[:=]\s*['""]?([^'""\s]+)['""]?",
                @"(?:server|host)\s*[:=]\s*['""]?([^'""\s]+)['""]?\s*;.*(?:user|uid|username)\s*[:=]\s*['""]?([^'""\s]+)['""]?\s*;.*(?:password|pwd)\s*[:=]\s*['""]?([^'""\s]+)['""]?",
                @"(?:password|pwd)\s*[:=]\s*['""]?([^'""\s]{8,})['""]?",
                @"(?:user|uid|username)\s*[:=]\s*['""]?([^'""\s]+)['""]?\s*;.*(?:password|pwd)\s*[:=]\s*['""]?([^'""\s]{8,})['""]?"
            };

            foreach (var pattern in dbPatterns)
            {
                var matches = Regex.Matches(content, pattern, RegexOptions.IgnoreCase);
                foreach (Match match in matches)
                {
                    for (int i = 1; i < match.Groups.Count; i++)
                    {
                        if (!string.IsNullOrEmpty(match.Groups[i].Value))
                        {
                            sensitiveData.Add(new SensitiveDataItem
                            {
                                Type = "Database Credential",
                                Value = match.Groups[i].Value,
                                Pattern = pattern,
                                LineNumber = GetLineNumber(content, match.Index),
                                Severity = "Critical"
                            });
                        }
                    }
                }
            }

            // Email addresses
            var emailMatches = Regex.Matches(content, @"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b");
            foreach (Match match in emailMatches)
            {
                sensitiveData.Add(new SensitiveDataItem
                {
                    Type = "Email Address",
                    Value = match.Value,
                    Pattern = "Email Pattern",
                    LineNumber = GetLineNumber(content, match.Index),
                    Severity = "Medium"
                });
            }

            // URLs with credentials
            var urlMatches = Regex.Matches(content, @"https?://[^:\s]+:[^@\s]+@[^\s]+");
            foreach (Match match in urlMatches)
            {
                sensitiveData.Add(new SensitiveDataItem
                {
                    Type = "URL with Credentials",
                    Value = match.Value,
                    Pattern = "URL with Auth",
                    LineNumber = GetLineNumber(content, match.Index),
                    Severity = "High"
                });
            }

            return sensitiveData;
        }

        /// <summary>
        /// Extract specific credentials from file content
        /// </summary>
        private List<CredentialItem> ExtractCredentials(string content, string fileName)
        {
            var credentials = new List<CredentialItem>();

            // OpenAI API Keys
            var openaiMatches = Regex.Matches(content, @"sk-proj-[a-zA-Z0-9\-_]{20,}", RegexOptions.IgnoreCase);
            foreach (Match match in openaiMatches)
            {
                credentials.Add(new CredentialItem
                {
                    Type = "OpenAI API Key",
                    Value = match.Value,
                    Provider = "OpenAI",
                    Severity = "Critical",
                    LineNumber = GetLineNumber(content, match.Index)
                });
            }

            // Database passwords in connection strings
            var dbPasswordMatches = Regex.Matches(content, @"(?:password|pwd)\s*[:=]\s*['""]?([^'""\s]{8,})['""]?", RegexOptions.IgnoreCase);
            foreach (Match match in dbPasswordMatches)
            {
                credentials.Add(new CredentialItem
                {
                    Type = "Database Password",
                    Value = match.Groups[1].Value,
                    Provider = "Database",
                    Severity = "Critical",
                    LineNumber = GetLineNumber(content, match.Index)
                });
            }

            // AWS credentials
            var awsMatches = Regex.Matches(content, @"AKIA[0-9A-Z]{16}", RegexOptions.IgnoreCase);
            foreach (Match match in awsMatches)
            {
                credentials.Add(new CredentialItem
                {
                    Type = "AWS Access Key",
                    Value = match.Value,
                    Provider = "AWS",
                    Severity = "Critical",
                    LineNumber = GetLineNumber(content, match.Index)
                });
            }

            // Generic API keys
            var genericApiMatches = Regex.Matches(content, @"(?:api[_-]?key|apikey|api_key)\s*[:=]\s*['""]?([a-zA-Z0-9_\-\.]{20,})['""]?", RegexOptions.IgnoreCase);
            foreach (Match match in genericApiMatches)
            {
                credentials.Add(new CredentialItem
                {
                    Type = "API Key",
                    Value = match.Groups[1].Value,
                    Provider = "Unknown",
                    Severity = "High",
                    LineNumber = GetLineNumber(content, match.Index)
                });
            }

            return credentials;
        }

        /// <summary>
        /// Calculate risk level based on content analysis
        /// </summary>
        private string CalculateRiskLevel(string content, string fileName)
        {
            var sensitiveData = ExtractSensitiveData(content, fileName);
            var credentials = ExtractCredentials(content, fileName);

            if (credentials.Any(c => c.Severity == "Critical"))
                return "Critical";
            
            if (credentials.Any(c => c.Severity == "High") || sensitiveData.Any(s => s.Severity == "Critical"))
                return "High";
            
            if (credentials.Any() || sensitiveData.Any(s => s.Severity == "High"))
                return "Medium";
            
            if (sensitiveData.Any())
                return "Low";
            
            return "None";
        }

        /// <summary>
        /// Get line number for a character position
        /// </summary>
        private int GetLineNumber(string content, int position)
        {
            return content.Substring(0, position).Split('\n').Length;
        }
    }

    /// <summary>
    /// Local file analysis report
    /// </summary>
    public class LocalFileAnalysisReport
    {
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public int TotalFiles { get; set; }
        public int SuccessfullyAnalyzed { get; set; }
        public int HighRiskFiles { get; set; }
        public int CredentialsFound { get; set; }
        public List<AnalyzedFile> AnalyzedFiles { get; set; } = new();
    }

    /// <summary>
    /// Analyzed file information
    /// </summary>
    public class AnalyzedFile
    {
        public string FilePath { get; set; } = string.Empty;
        public string FileName { get; set; } = string.Empty;
        public long FileSize { get; set; }
        public DateTime LastModified { get; set; }
        public string Content { get; set; } = string.Empty;
        public string FileType { get; set; } = string.Empty;
        public List<SensitiveDataItem> SensitiveData { get; set; } = new();
        public List<CredentialItem> Credentials { get; set; } = new();
        public string RiskLevel { get; set; } = "None";
    }

    /// <summary>
    /// Sensitive data item
    /// </summary>
    public class SensitiveDataItem
    {
        public string Type { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string Pattern { get; set; } = string.Empty;
        public int LineNumber { get; set; }
        public string Severity { get; set; } = "Medium";
    }

    /// <summary>
    /// Credential item
    /// </summary>
    public class CredentialItem
    {
        public string Type { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string Provider { get; set; } = string.Empty;
        public string Severity { get; set; } = "Medium";
        public int LineNumber { get; set; }
    }
}




































