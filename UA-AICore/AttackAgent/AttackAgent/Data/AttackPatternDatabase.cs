using Microsoft.Data.Sqlite;
using Serilog;
using AttackAgent.Models;
using System.Text.Json;

namespace AttackAgent.Data
{
    /// <summary>
    /// SQLite database for storing and managing attack patterns, results, and learning data
    /// </summary>
    public class AttackPatternDatabase : IDisposable
    {
        private readonly string _connectionString;
        private readonly ILogger _logger;
        private bool _disposed = false;

        public AttackPatternDatabase(string databasePath = "attack_patterns.db")
        {
            _connectionString = $"Data Source={databasePath}";
            _logger = Log.ForContext<AttackPatternDatabase>();
            
            InitializeDatabase();
        }

        /// <summary>
        /// Initialize the database and create tables if they don't exist
        /// </summary>
        private void InitializeDatabase()
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                connection.Open();

                // Create AttackPatterns table
                var createPatternsTable = @"
                    CREATE TABLE IF NOT EXISTS AttackPatterns (
                        Id TEXT PRIMARY KEY,
                        Name TEXT NOT NULL,
                        Description TEXT,
                        VulnerabilityType INTEGER NOT NULL,
                        AttackMode INTEGER NOT NULL,
                        TargetTechnologies TEXT, -- JSON array
                        Payloads TEXT, -- JSON array
                        SuccessIndicators TEXT, -- JSON array
                        FailureIndicators TEXT, -- JSON array
                        RiskLevel INTEGER NOT NULL,
                        SuccessRate REAL DEFAULT 0.0,
                        UsageCount INTEGER DEFAULT 0,
                        LastUsed TEXT,
                        CreatedAt TEXT NOT NULL,
                        Tags TEXT, -- JSON array
                        RequiresAuthentication INTEGER DEFAULT 0,
                        ParameterTypes TEXT -- JSON array
                    )";

                // Create AttackResults table
                var createResultsTable = @"
                    CREATE TABLE IF NOT EXISTS AttackResults (
                        Id TEXT PRIMARY KEY,
                        PatternId TEXT NOT NULL,
                        TargetUrl TEXT NOT NULL,
                        TargetTechnology TEXT,
                        Payload TEXT NOT NULL,
                        Success INTEGER NOT NULL, -- 0 = failed, 1 = success
                        ResponseCode INTEGER,
                        ResponseTime INTEGER, -- milliseconds
                        ResponseBody TEXT,
                        ErrorMessage TEXT,
                        Confidence REAL,
                        FalsePositive INTEGER DEFAULT 0,
                        Timestamp TEXT NOT NULL,
                        FOREIGN KEY (PatternId) REFERENCES AttackPatterns (Id)
                    )";

                // Create TechnologyMappings table
                var createTechMappingsTable = @"
                    CREATE TABLE IF NOT EXISTS TechnologyMappings (
                        Id TEXT PRIMARY KEY,
                        Technology TEXT NOT NULL,
                        Framework TEXT,
                        Database TEXT,
                        WebServer TEXT,
                        EffectivePatterns TEXT, -- JSON array of pattern IDs
                        IneffectivePatterns TEXT, -- JSON array of pattern IDs
                        LastUpdated TEXT NOT NULL
                    )";

                // Create LearningMetrics table
                var createMetricsTable = @"
                    CREATE TABLE IF NOT EXISTS LearningMetrics (
                        Id TEXT PRIMARY KEY,
                        MetricName TEXT NOT NULL,
                        MetricValue REAL NOT NULL,
                        Technology TEXT,
                        PatternId TEXT,
                        Timestamp TEXT NOT NULL
                    )";

                var command = connection.CreateCommand();
                command.CommandText = createPatternsTable;
                command.ExecuteNonQuery();

                command.CommandText = createResultsTable;
                command.ExecuteNonQuery();

                command.CommandText = createTechMappingsTable;
                command.ExecuteNonQuery();

                command.CommandText = createMetricsTable;
                command.ExecuteNonQuery();

                _logger.Information("Attack pattern database initialized successfully");
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error initializing attack pattern database");
                throw;
            }
        }

        /// <summary>
        /// Store an attack pattern in the database
        /// </summary>
        public async Task StoreAttackPatternAsync(AttackPattern pattern)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    INSERT OR REPLACE INTO AttackPatterns 
                    (Id, Name, Description, VulnerabilityType, AttackMode, TargetTechnologies, 
                     Payloads, SuccessIndicators, FailureIndicators, RiskLevel, SuccessRate, 
                     UsageCount, LastUsed, CreatedAt, Tags, RequiresAuthentication, ParameterTypes)
                    VALUES 
                    (@Id, @Name, @Description, @VulnerabilityType, @AttackMode, @TargetTechnologies,
                     @Payloads, @SuccessIndicators, @FailureIndicators, @RiskLevel, @SuccessRate,
                     @UsageCount, @LastUsed, @CreatedAt, @Tags, @RequiresAuthentication, @ParameterTypes)";

                command.Parameters.AddWithValue("@Id", pattern.Id);
                command.Parameters.AddWithValue("@Name", pattern.Name);
                command.Parameters.AddWithValue("@Description", pattern.Description ?? "");
                command.Parameters.AddWithValue("@VulnerabilityType", (int)pattern.VulnerabilityType);
                command.Parameters.AddWithValue("@AttackMode", (int)pattern.AttackMode);
                command.Parameters.AddWithValue("@TargetTechnologies", JsonSerializer.Serialize(pattern.TargetTechnologies ?? new List<string>()));
                command.Parameters.AddWithValue("@Payloads", JsonSerializer.Serialize(pattern.Payloads ?? new List<AttackPayload>()));
                command.Parameters.AddWithValue("@SuccessIndicators", JsonSerializer.Serialize(pattern.SuccessIndicators ?? new List<SuccessIndicator>()));
                command.Parameters.AddWithValue("@FailureIndicators", JsonSerializer.Serialize(pattern.FailureIndicators ?? new List<FailureIndicator>()));
                command.Parameters.AddWithValue("@RiskLevel", (int)pattern.RiskLevel);
                command.Parameters.AddWithValue("@SuccessRate", pattern.SuccessRate);
                command.Parameters.AddWithValue("@UsageCount", pattern.UsageCount);
                command.Parameters.AddWithValue("@LastUsed", pattern.LastUsed?.ToString("yyyy-MM-dd HH:mm:ss") ?? "");
                command.Parameters.AddWithValue("@CreatedAt", pattern.CreatedAt.ToString("yyyy-MM-dd HH:mm:ss"));
                command.Parameters.AddWithValue("@Tags", JsonSerializer.Serialize(pattern.Tags ?? new List<string>()));
                command.Parameters.AddWithValue("@RequiresAuthentication", pattern.RequiresAuthentication ? 1 : 0);
                command.Parameters.AddWithValue("@ParameterTypes", JsonSerializer.Serialize(pattern.ParameterTypes ?? new List<string>()));

                await command.ExecuteNonQueryAsync();
                _logger.Debug("Stored attack pattern: {PatternName}", pattern.Name);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error storing attack pattern: {PatternName}", pattern.Name);
                throw;
            }
        }

        /// <summary>
        /// Store an attack result in the database
        /// </summary>
        public async Task StoreAttackResultAsync(AttackResult result)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    INSERT INTO AttackResults 
                    (Id, PatternId, TargetUrl, TargetTechnology, Payload, Success, ResponseCode, 
                     ResponseTime, ResponseBody, ErrorMessage, Confidence, FalsePositive, Timestamp)
                    VALUES 
                    (@Id, @PatternId, @TargetUrl, @TargetTechnology, @Payload, @Success, @ResponseCode,
                     @ResponseTime, @ResponseBody, @ErrorMessage, @Confidence, @FalsePositive, @Timestamp)";

                command.Parameters.AddWithValue("@Id", result.Id);
                command.Parameters.AddWithValue("@PatternId", result.PatternId);
                command.Parameters.AddWithValue("@TargetUrl", result.TargetUrl);
                command.Parameters.AddWithValue("@TargetTechnology", result.TargetTechnology ?? "");
                command.Parameters.AddWithValue("@Payload", result.Payload);
                command.Parameters.AddWithValue("@Success", result.Success ? 1 : 0);
                command.Parameters.AddWithValue("@ResponseCode", result.ResponseCode ?? 0);
                command.Parameters.AddWithValue("@ResponseTime", result.ResponseTime ?? 0);
                command.Parameters.AddWithValue("@ResponseBody", result.ResponseBody ?? "");
                command.Parameters.AddWithValue("@ErrorMessage", result.ErrorMessage ?? "");
                command.Parameters.AddWithValue("@Confidence", result.Confidence);
                command.Parameters.AddWithValue("@FalsePositive", result.FalsePositive ? 1 : 0);
                command.Parameters.AddWithValue("@Timestamp", result.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"));

                await command.ExecuteNonQueryAsync();
                _logger.Debug("Stored attack result for pattern: {PatternId}", result.PatternId);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error storing attack result: {ResultId}", result.Id);
                throw;
            }
        }

        /// <summary>
        /// Get attack patterns optimized for a specific technology stack
        /// </summary>
        public async Task<List<AttackPattern>> GetOptimizedPatternsAsync(string technology, VulnerabilityType vulnerabilityType)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT * FROM AttackPatterns 
                    WHERE VulnerabilityType = @VulnerabilityType
                    AND (TargetTechnologies LIKE @Technology OR TargetTechnologies = '[]')
                    ORDER BY SuccessRate DESC, UsageCount DESC
                    LIMIT 20";

                command.Parameters.AddWithValue("@VulnerabilityType", (int)vulnerabilityType);
                command.Parameters.AddWithValue("@Technology", $"%{technology}%");

                var patterns = new List<AttackPattern>();
                using var reader = await command.ExecuteReaderAsync();

                while (await reader.ReadAsync())
                {
                    patterns.Add(MapReaderToAttackPattern(reader));
                }

                _logger.Debug("Retrieved {Count} optimized patterns for {Technology}", patterns.Count, technology);
                return patterns;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error retrieving optimized patterns for {Technology}", technology);
                return new List<AttackPattern>();
            }
        }

        /// <summary>
        /// Update pattern success rate based on recent results
        /// </summary>
        public async Task UpdatePatternSuccessRateAsync(string patternId)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                // Calculate success rate from recent results
                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT 
                        COUNT(*) as TotalAttempts,
                        SUM(Success) as SuccessfulAttempts
                    FROM AttackResults 
                    WHERE PatternId = @PatternId 
                    AND Timestamp > datetime('now', '-30 days')";

                command.Parameters.AddWithValue("@PatternId", patternId);

                using var reader = await command.ExecuteReaderAsync();
                if (await reader.ReadAsync())
                {
                    var totalAttempts = reader.GetInt32(0);
                    var successfulAttempts = reader.GetInt32(1);
                    
                    var successRate = totalAttempts > 0 ? (double)successfulAttempts / totalAttempts : 0.0;

                    // Update the pattern's success rate
                    reader.Close();
                    var updateCommand = connection.CreateCommand();
                    updateCommand.CommandText = @"
                        UPDATE AttackPatterns 
                        SET SuccessRate = @SuccessRate, 
                            UsageCount = @UsageCount,
                            LastUsed = datetime('now')
                        WHERE Id = @PatternId";

                    updateCommand.Parameters.AddWithValue("@SuccessRate", successRate);
                    updateCommand.Parameters.AddWithValue("@UsageCount", totalAttempts);
                    updateCommand.Parameters.AddWithValue("@PatternId", patternId);

                    await updateCommand.ExecuteNonQueryAsync();
                    _logger.Debug("Updated success rate for pattern {PatternId}: {SuccessRate:P2}", patternId, successRate);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error updating success rate for pattern {PatternId}", patternId);
            }
        }

        /// <summary>
        /// Get learning metrics for analysis
        /// </summary>
        public async Task<Dictionary<string, double>> GetLearningMetricsAsync()
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT 
                        VulnerabilityType,
                        AVG(SuccessRate) as AvgSuccessRate,
                        COUNT(*) as PatternCount
                    FROM AttackPatterns 
                    GROUP BY VulnerabilityType";

                var metrics = new Dictionary<string, double>();
                using var reader = await command.ExecuteReaderAsync();

                while (await reader.ReadAsync())
                {
                    var vulnType = ((VulnerabilityType)reader.GetInt32(0)).ToString();
                    var avgSuccessRate = reader.GetDouble(1);
                    var patternCount = reader.GetInt32(2);
                    
                    metrics[$"{vulnType}_AvgSuccessRate"] = avgSuccessRate;
                    metrics[$"{vulnType}_PatternCount"] = patternCount;
                }

                return metrics;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error retrieving learning metrics");
                return new Dictionary<string, double>();
            }
        }

        /// <summary>
        /// Map database reader to AttackPattern object
        /// </summary>
        private AttackPattern MapReaderToAttackPattern(SqliteDataReader reader)
        {
            return new AttackPattern
            {
                Id = reader.GetString(0),
                Name = reader.GetString(1),
                Description = reader.GetString(2),
                VulnerabilityType = (VulnerabilityType)reader.GetInt32(3),
                AttackMode = (AttackMode)reader.GetInt32(4),
                TargetTechnologies = JsonSerializer.Deserialize<List<string>>(reader.GetString(5)) ?? new List<string>(),
                Payloads = JsonSerializer.Deserialize<List<AttackPayload>>(reader.GetString(6)) ?? new List<AttackPayload>(),
                SuccessIndicators = JsonSerializer.Deserialize<List<SuccessIndicator>>(reader.GetString(7)) ?? new List<SuccessIndicator>(),
                FailureIndicators = JsonSerializer.Deserialize<List<FailureIndicator>>(reader.GetString(8)) ?? new List<FailureIndicator>(),
                RiskLevel = (RiskLevel)reader.GetInt32(9),
                SuccessRate = reader.GetDouble(10),
                UsageCount = reader.GetInt32(11),
                LastUsed = reader.IsDBNull(12) || string.IsNullOrEmpty(reader.GetString(12)) ? null : DateTime.Parse(reader.GetString(12)),
                CreatedAt = reader.IsDBNull(13) || string.IsNullOrEmpty(reader.GetString(13)) ? DateTime.UtcNow : DateTime.Parse(reader.GetString(13)),
                Tags = JsonSerializer.Deserialize<List<string>>(reader.GetString(14)) ?? new List<string>(),
                RequiresAuthentication = reader.GetInt32(15) == 1,
                ParameterTypes = JsonSerializer.Deserialize<List<string>>(reader.GetString(16)) ?? new List<string>()
            };
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _disposed = true;
            }
        }
    }
}
