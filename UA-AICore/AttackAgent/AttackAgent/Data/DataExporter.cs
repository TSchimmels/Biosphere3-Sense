using AttackAgent.Models;
using Serilog;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace AttackAgent.Data
{
    /// <summary>
    /// Exports attack patterns, vulnerabilities, and endpoint data for AI training and analysis
    /// Formats data for machine learning training datasets
    /// </summary>
    public class DataExporter : IDisposable
    {
        private readonly AttackPatternDatabase _database;
        private readonly ILogger _logger;
        private bool _disposed = false;

        public DataExporter(string databasePath = "attack_patterns.db")
        {
            _database = new AttackPatternDatabase(databasePath);
            _logger = Log.ForContext<DataExporter>();
        }

        /// <summary>
        /// Exports all data to a specified directory
        /// </summary>
        public async Task<ExportSummary> ExportAllDataAsync(
            string outputDirectory,
            ApplicationProfile? profile = null,
            List<Vulnerability>? vulnerabilities = null,
            ExportFormat format = ExportFormat.Json)
        {
            _logger.Information("📤 Starting data export to {Directory}...", outputDirectory);
            
            Directory.CreateDirectory(outputDirectory);
            
            var summary = new ExportSummary
            {
                ExportDirectory = outputDirectory,
                ExportTime = DateTime.UtcNow,
                Format = format
            };

            try
            {
                // 1. Export successful attack patterns
                _logger.Information("📤 Exporting attack patterns...");
                var patternsFile = await ExportAttackPatternsAsync(outputDirectory, format);
                summary.ExportedFiles.Add(patternsFile);
                _logger.Information("✅ Exported attack patterns to {File}", patternsFile);

                // 2. Export attack results
                _logger.Information("📤 Exporting attack results...");
                var resultsFile = await ExportAttackResultsAsync(outputDirectory, format);
                summary.ExportedFiles.Add(resultsFile);
                _logger.Information("✅ Exported attack results to {File}", resultsFile);

                // 3. Export vulnerabilities
                if (vulnerabilities != null && vulnerabilities.Any())
                {
                    _logger.Information("📤 Exporting vulnerabilities...");
                    var vulnsFile = await ExportVulnerabilitiesAsync(outputDirectory, vulnerabilities, format);
                    summary.ExportedFiles.Add(vulnsFile);
                    summary.VulnerabilitiesExported = vulnerabilities.Count;
                    _logger.Information("✅ Exported {Count} vulnerabilities to {File}", vulnerabilities.Count, vulnsFile);
                }

                // 4. Export endpoint discovery data
                if (profile != null)
                {
                    _logger.Information("📤 Exporting endpoint discovery data...");
                    var endpointsFile = await ExportEndpointDataAsync(outputDirectory, profile, format);
                    summary.ExportedFiles.Add(endpointsFile);
                    summary.EndpointsExported = profile.DiscoveredEndpoints.Count;
                    _logger.Information("✅ Exported {Count} endpoints to {File}", profile.DiscoveredEndpoints.Count, endpointsFile);
                }

                // 5. Export training dataset (formatted for ML)
                _logger.Information("📤 Exporting training dataset...");
                var trainingFile = await ExportTrainingDatasetAsync(outputDirectory, profile, vulnerabilities, format);
                summary.ExportedFiles.Add(trainingFile);
                _logger.Information("✅ Exported training dataset to {File}", trainingFile);

                summary.Success = true;
                _logger.Information("✅ Data export completed successfully. Exported {Count} files", summary.ExportedFiles.Count);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error during data export");
                summary.Success = false;
                summary.ErrorMessage = ex.Message;
            }

            return summary;
        }

        /// <summary>
        /// Exports attack patterns to file
        /// </summary>
        private async Task<string> ExportAttackPatternsAsync(string outputDirectory, ExportFormat format)
        {
            try
            {
                // Get all patterns from database
                var patterns = await GetAllPatternsFromDatabaseAsync();
                
                var filename = format == ExportFormat.Json 
                    ? "attack-patterns.json" 
                    : "attack-patterns.csv";
                var filePath = Path.Combine(outputDirectory, filename);

                if (format == ExportFormat.Json)
                {
                    var json = JsonSerializer.Serialize(patterns, new JsonSerializerOptions 
                    { 
                        WriteIndented = true 
                    });
                    await File.WriteAllTextAsync(filePath, json);
                }
                else
                {
                    var csv = ConvertPatternsToCsv(patterns);
                    await File.WriteAllTextAsync(filePath, csv);
                }

                return filePath;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error exporting attack patterns");
                throw;
            }
        }

        /// <summary>
        /// Exports attack results to file
        /// </summary>
        private async Task<string> ExportAttackResultsAsync(string outputDirectory, ExportFormat format)
        {
            try
            {
                // Get all results from database
                var results = await GetAllResultsFromDatabaseAsync();
                
                var filename = format == ExportFormat.Json 
                    ? "attack-results.json" 
                    : "attack-results.csv";
                var filePath = Path.Combine(outputDirectory, filename);

                if (format == ExportFormat.Json)
                {
                    var json = JsonSerializer.Serialize(results, new JsonSerializerOptions 
                    { 
                        WriteIndented = true 
                    });
                    await File.WriteAllTextAsync(filePath, json);
                }
                else
                {
                    var csv = ConvertResultsToCsv(results);
                    await File.WriteAllTextAsync(filePath, csv);
                }

                return filePath;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error exporting attack results");
                throw;
            }
        }

        /// <summary>
        /// Exports vulnerabilities to file
        /// </summary>
        private async Task<string> ExportVulnerabilitiesAsync(
            string outputDirectory, 
            List<Vulnerability> vulnerabilities, 
            ExportFormat format)
        {
            try
            {
                var filename = format == ExportFormat.Json 
                    ? "vulnerabilities.json" 
                    : "vulnerabilities.csv";
                var filePath = Path.Combine(outputDirectory, filename);

                if (format == ExportFormat.Json)
                {
                    var json = JsonSerializer.Serialize(vulnerabilities, new JsonSerializerOptions 
                    { 
                        WriteIndented = true 
                    });
                    await File.WriteAllTextAsync(filePath, json);
                }
                else
                {
                    var csv = ConvertVulnerabilitiesToCsv(vulnerabilities);
                    await File.WriteAllTextAsync(filePath, csv);
                }

                return filePath;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error exporting vulnerabilities");
                throw;
            }
        }

        /// <summary>
        /// Exports endpoint discovery data to file
        /// </summary>
        private async Task<string> ExportEndpointDataAsync(
            string outputDirectory, 
            ApplicationProfile profile, 
            ExportFormat format)
        {
            try
            {
                var endpointData = new
                {
                    BaseUrl = profile.BaseUrl,
                    DiscoveryTimestamp = profile.DiscoveryTimestamp,
                    TotalEndpoints = profile.DiscoveredEndpoints.Count,
                    Endpoints = profile.DiscoveredEndpoints.Select(e => new
                    {
                        Path = e.Path,
                        Method = e.Method,
                        StatusCode = e.StatusCode,
                        Parameters = e.Parameters.Select(p => new
                        {
                            Name = p.Name,
                            Type = p.Type,
                            Required = p.Required
                        }),
                        Source = e.Source,
                        Technology = profile.TechnologyStack?.Framework
                    })
                };

                var filename = format == ExportFormat.Json 
                    ? "endpoints.json" 
                    : "endpoints.csv";
                var filePath = Path.Combine(outputDirectory, filename);

                if (format == ExportFormat.Json)
                {
                    var json = JsonSerializer.Serialize(endpointData, new JsonSerializerOptions 
                    { 
                        WriteIndented = true 
                    });
                    await File.WriteAllTextAsync(filePath, json);
                }
                else
                {
                    var csv = ConvertEndpointsToCsv(profile.DiscoveredEndpoints);
                    await File.WriteAllTextAsync(filePath, csv);
                }

                return filePath;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error exporting endpoint data");
                throw;
            }
        }

        /// <summary>
        /// Exports training dataset formatted for ML training
        /// </summary>
        private async Task<string> ExportTrainingDatasetAsync(
            string outputDirectory,
            ApplicationProfile? profile,
            List<Vulnerability>? vulnerabilities,
            ExportFormat format)
        {
            try
            {
                var trainingData = new List<TrainingExample>();

                // Create training examples from successful attack patterns
                var patterns = await GetAllPatternsFromDatabaseAsync();
                foreach (var pattern in patterns.Where(p => p.SuccessRate > 0.3))
                {
                    foreach (var payload in pattern.Payloads ?? new List<AttackPayload>())
                    {
                        trainingData.Add(new TrainingExample
                        {
                            Input = new TrainingInput
                            {
                                Technology = pattern.TargetTechnologies?.FirstOrDefault() ?? "Unknown",
                                Endpoint = "example",
                                Parameter = "test",
                                VulnerabilityType = pattern.VulnerabilityType.ToString()
                            },
                            Output = new TrainingOutput
                            {
                                Payload = payload.Payload,
                                Success = true,
                                Confidence = pattern.SuccessRate
                            }
                        });
                    }
                }

                // Add training examples from vulnerabilities
                if (vulnerabilities != null)
                {
                    foreach (var vuln in vulnerabilities.Where(v => v.Verified && !v.FalsePositive))
                    {
                        trainingData.Add(new TrainingExample
                        {
                            Input = new TrainingInput
                            {
                                Technology = profile?.TechnologyStack?.Framework ?? "Unknown",
                                Endpoint = vuln.Endpoint,
                                Parameter = vuln.Parameter ?? "unknown",
                                VulnerabilityType = vuln.Type.ToString()
                            },
                            Output = new TrainingOutput
                            {
                                Payload = vuln.Payload ?? "",
                                Success = true,
                                Confidence = vuln.Confidence
                            }
                        });
                    }
                }

                var filename = format == ExportFormat.Json 
                    ? "training-dataset.json" 
                    : "training-dataset.csv";
                var filePath = Path.Combine(outputDirectory, filename);

                if (format == ExportFormat.Json)
                {
                    var json = JsonSerializer.Serialize(trainingData, new JsonSerializerOptions 
                    { 
                        WriteIndented = true 
                    });
                    await File.WriteAllTextAsync(filePath, json);
                }
                else
                {
                    var csv = ConvertTrainingDataToCsv(trainingData);
                    await File.WriteAllTextAsync(filePath, csv);
                }

                return filePath;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error exporting training dataset");
                throw;
            }
        }

        /// <summary>
        /// Gets all patterns from database
        /// </summary>
        private async Task<List<AttackPattern>> GetAllPatternsFromDatabaseAsync()
        {
            try
            {
                // Get patterns for all vulnerability types
                var allPatterns = new List<AttackPattern>();
                var vulnTypes = Enum.GetValues<VulnerabilityType>();
                
                foreach (var vulnType in vulnTypes)
                {
                    var patterns = await _database.GetOptimizedPatternsAsync("", vulnType);
                    allPatterns.AddRange(patterns);
                }

                return allPatterns.DistinctBy(p => p.Id).ToList();
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error getting patterns from database");
                return new List<AttackPattern>();
            }
        }

        /// <summary>
        /// Gets all results from database
        /// </summary>
        private async Task<List<AttackResult>> GetAllResultsFromDatabaseAsync()
        {
            try
            {
                // Use reflection or create a helper method to access connection string
                // For now, we'll query through the database's existing methods
                // Get results by querying all patterns and their results
                var allResults = new List<AttackResult>();
                
                // Get patterns for all vulnerability types to access their results
                var vulnTypes = Enum.GetValues<VulnerabilityType>();
                var patterns = await GetAllPatternsFromDatabaseAsync();
                
                // For each pattern, we'd need to get its results
                // Since we don't have a direct method, we'll use SQLite directly
                using var connection = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=attack_patterns.db");
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = "SELECT * FROM AttackResults ORDER BY Timestamp DESC LIMIT 10000";

                var results = new List<AttackResult>();
                using var reader = await command.ExecuteReaderAsync();
                
                while (await reader.ReadAsync())
                {
                    results.Add(new AttackResult
                    {
                        Id = reader.GetString(reader.GetOrdinal("Id")),
                        PatternId = reader.GetString(reader.GetOrdinal("PatternId")),
                        TargetUrl = reader.GetString(reader.GetOrdinal("TargetUrl")),
                        TargetTechnology = reader.IsDBNull(reader.GetOrdinal("TargetTechnology")) ? null : reader.GetString(reader.GetOrdinal("TargetTechnology")),
                        Payload = reader.GetString(reader.GetOrdinal("Payload")),
                        Success = reader.GetInt32(reader.GetOrdinal("Success")) == 1,
                        ResponseCode = reader.IsDBNull(reader.GetOrdinal("ResponseCode")) ? null : reader.GetInt32(reader.GetOrdinal("ResponseCode")),
                        ResponseBody = reader.IsDBNull(reader.GetOrdinal("ResponseBody")) ? null : reader.GetString(reader.GetOrdinal("ResponseBody")),
                        Confidence = reader.IsDBNull(reader.GetOrdinal("Confidence")) ? 0.0 : reader.GetDouble(reader.GetOrdinal("Confidence")),
                        Timestamp = DateTime.Parse(reader.GetString(reader.GetOrdinal("Timestamp")))
                    });
                }

                return results;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error getting results from database");
                return new List<AttackResult>();
            }
        }

        /// <summary>
        /// Converts patterns to CSV format
        /// </summary>
        private string ConvertPatternsToCsv(List<AttackPattern> patterns)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Id,Name,VulnerabilityType,SuccessRate,UsageCount,TargetTechnologies,PayloadCount");
            
            foreach (var pattern in patterns)
            {
                var techs = string.Join(";", pattern.TargetTechnologies ?? new List<string>());
                var payloadCount = pattern.Payloads?.Count ?? 0;
                sb.AppendLine($"{pattern.Id},{EscapeCsv(pattern.Name)},{(int)pattern.VulnerabilityType},{pattern.SuccessRate},{pattern.UsageCount},{EscapeCsv(techs)},{payloadCount}");
            }
            
            return sb.ToString();
        }

        /// <summary>
        /// Converts results to CSV format
        /// </summary>
        private string ConvertResultsToCsv(List<AttackResult> results)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Id,PatternId,TargetUrl,TargetTechnology,Payload,Success,ResponseCode,Confidence,Timestamp");
            
            foreach (var result in results)
            {
                sb.AppendLine($"{result.Id},{result.PatternId},{EscapeCsv(result.TargetUrl)},{EscapeCsv(result.TargetTechnology ?? "")},{EscapeCsv(result.Payload)},{(result.Success ? 1 : 0)},{result.ResponseCode ?? 0},{result.Confidence},{result.Timestamp:yyyy-MM-dd HH:mm:ss}");
            }
            
            return sb.ToString();
        }

        /// <summary>
        /// Converts vulnerabilities to CSV format
        /// </summary>
        private string ConvertVulnerabilitiesToCsv(List<Vulnerability> vulnerabilities)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Id,Type,Severity,Title,Endpoint,Method,Parameter,Confidence,Verified,FalsePositive,DiscoveredAt");
            
            foreach (var vuln in vulnerabilities)
            {
                sb.AppendLine($"{vuln.Id},{(int)vuln.Type},{(int)vuln.Severity},{EscapeCsv(vuln.Title)},{EscapeCsv(vuln.Endpoint)},{vuln.Method},{EscapeCsv(vuln.Parameter ?? "")},{vuln.Confidence},{(vuln.Verified ? 1 : 0)},{(vuln.FalsePositive ? 1 : 0)},{vuln.DiscoveredAt:yyyy-MM-dd HH:mm:ss}");
            }
            
            return sb.ToString();
        }

        /// <summary>
        /// Converts endpoints to CSV format
        /// </summary>
        private string ConvertEndpointsToCsv(List<EndpointInfo> endpoints)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Path,Method,StatusCode,ParameterCount,Source");
            
            foreach (var endpoint in endpoints)
            {
                var paramCount = endpoint.Parameters?.Count ?? 0;
                sb.AppendLine($"{EscapeCsv(endpoint.Path)},{endpoint.Method},{endpoint.StatusCode},{paramCount},{EscapeCsv(endpoint.Source ?? "")}");
            }
            
            return sb.ToString();
        }

        /// <summary>
        /// Converts training data to CSV format
        /// </summary>
        private string ConvertTrainingDataToCsv(List<TrainingExample> trainingData)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Technology,Endpoint,Parameter,VulnerabilityType,Payload,Success,Confidence");
            
            foreach (var example in trainingData)
            {
                sb.AppendLine($"{EscapeCsv(example.Input.Technology)},{EscapeCsv(example.Input.Endpoint)},{EscapeCsv(example.Input.Parameter)},{EscapeCsv(example.Input.VulnerabilityType)},{EscapeCsv(example.Output.Payload)},{(example.Output.Success ? 1 : 0)},{example.Output.Confidence}");
            }
            
            return sb.ToString();
        }

        /// <summary>
        /// Escapes CSV values
        /// </summary>
        private string EscapeCsv(string value)
        {
            if (string.IsNullOrEmpty(value))
                return "";
            
            if (value.Contains(",") || value.Contains("\"") || value.Contains("\n"))
            {
                return $"\"{value.Replace("\"", "\"\"")}\"";
            }
            
            return value;
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

    /// <summary>
    /// Export format options
    /// </summary>
    public enum ExportFormat
    {
        Json,
        Csv
    }

    /// <summary>
    /// Summary of export operation
    /// </summary>
    public class ExportSummary
    {
        public string ExportDirectory { get; set; } = string.Empty;
        public DateTime ExportTime { get; set; }
        public ExportFormat Format { get; set; }
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
        public List<string> ExportedFiles { get; set; } = new();
        public int VulnerabilitiesExported { get; set; }
        public int EndpointsExported { get; set; }
    }

    /// <summary>
    /// Training example for ML
    /// </summary>
    public class TrainingExample
    {
        public TrainingInput Input { get; set; } = new();
        public TrainingOutput Output { get; set; } = new();
    }

    /// <summary>
    /// Training input features
    /// </summary>
    public class TrainingInput
    {
        public string Technology { get; set; } = string.Empty;
        public string Endpoint { get; set; } = string.Empty;
        public string Parameter { get; set; } = string.Empty;
        public string VulnerabilityType { get; set; } = string.Empty;
    }

    /// <summary>
    /// Training output (payload and success)
    /// </summary>
    public class TrainingOutput
    {
        public string Payload { get; set; } = string.Empty;
        public bool Success { get; set; }
        public double Confidence { get; set; }
    }
}
