using AttackAgent.Data;
using AttackAgent.Models;
using Serilog;
using System.Collections.Concurrent;
using Microsoft.Data.Sqlite;

namespace AttackAgent.Core
{
    /// <summary>
    /// Reinforcement Learning Engine using Q-Learning for attack strategy optimization
    /// Learns which attack patterns work best for specific technologies and vulnerability types
    /// </summary>
    public class ReinforcementLearningEngine : IDisposable
    {
        private readonly AttackPatternDatabase _database;
        private readonly ILogger _logger;
        
        // Q-Table: Key = "State_Action", Value = Q-Value
        // State = Technology_VulnerabilityType
        // Action = PatternId
        private readonly ConcurrentDictionary<string, double> _qTable = new();
        
        private readonly double _learningRate = 0.1; // Alpha: how much to update Q-values
        private readonly double _discountFactor = 0.9; // Gamma: importance of future rewards
        private readonly double _defaultEpsilon = 0.15; // Exploration rate (15% explore, 85% exploit)
        
        private bool _disposed = false;

        public ReinforcementLearningEngine(string databasePath = "attack_patterns.db")
        {
            _database = new AttackPatternDatabase(databasePath);
            _logger = Log.ForContext<ReinforcementLearningEngine>();
            
            // Load Q-table from database on initialization
            LoadQTableAsync().Wait();
            
            _logger.Information("Reinforcement Learning Engine initialized with {Count} Q-values", _qTable.Count);
        }

        /// <summary>
        /// Selects the best action (pattern) for a given state using epsilon-greedy strategy
        /// </summary>
        /// <param name="technology">Target technology</param>
        /// <param name="vulnerabilityType">Type of vulnerability to test</param>
        /// <param name="epsilon">Exploration rate (0.0 = always exploit, 1.0 = always explore)</param>
        /// <returns>Pattern ID to use, or empty string if no patterns available</returns>
        public async Task<string> SelectBestActionAsync(
            string technology,
            VulnerabilityType vulnerabilityType,
            double? epsilon = null)
        {
            var state = CreateState(technology, vulnerabilityType);
            var explorationRate = epsilon ?? _defaultEpsilon;
            
            try
            {
                // Get available actions (patterns) for this state
                var patterns = await _database.GetOptimizedPatternsAsync(technology, vulnerabilityType);
                
                if (!patterns.Any())
                {
                    _logger.Debug("RL: No patterns available for {State}", state);
                    return string.Empty;
                }
                
                // Epsilon-greedy: explore or exploit
                var random = new Random();
                if (random.NextDouble() < explorationRate)
                {
                    // Explore: random action to discover new patterns
                    var randomPattern = patterns[random.Next(patterns.Count)];
                    _logger.Debug("RL: Exploring with pattern {PatternId} for {State}", randomPattern.Id, state);
                    return randomPattern.Id;
                }
                else
                {
                    // Exploit: best known action based on Q-values
                    var bestPattern = patterns
                        .Select(p => new
                        {
                            Pattern = p,
                            QValue = GetQValue(state, p.Id)
                        })
                        .OrderByDescending(p => p.QValue)
                        .ThenByDescending(p => p.Pattern.SuccessRate) // Tie-breaker
                        .First();
                    
                    _logger.Debug("RL: Exploiting pattern {PatternId} for {State} (Q={Q:F3})", 
                        bestPattern.Pattern.Id, state, bestPattern.QValue);
                    return bestPattern.Pattern.Id;
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error selecting best action for {State}", state);
                return string.Empty;
            }
        }

        /// <summary>
        /// Updates Q-value based on reward received from action
        /// Q-Learning formula: Q(s,a) = Q(s,a) + α[r + γ*max(Q(s',a')) - Q(s,a)]
        /// </summary>
        /// <param name="technology">Target technology</param>
        /// <param name="vulnerabilityType">Vulnerability type</param>
        /// <param name="patternId">Pattern ID that was used</param>
        /// <param name="success">Whether the attack was successful</param>
        /// <param name="confidence">Confidence level (0.0 to 1.0)</param>
        public async Task UpdateQValueAsync(
            string technology,
            VulnerabilityType vulnerabilityType,
            string patternId,
            bool success,
            double confidence = 1.0)
        {
            var state = CreateState(technology, vulnerabilityType);
            var action = patternId;
            
            try
            {
                // Calculate reward: success = positive, failure = negative
                // Higher confidence = higher reward magnitude
                double reward = success 
                    ? 1.0 * confidence  // Positive reward for success
                    : -0.2 * (1.0 - confidence); // Negative reward for failure (less negative if low confidence)
                
                // Get current Q-value
                double currentQ = GetQValue(state, action);
                
                // Get max Q-value for next state (simplified: use pattern's success rate as proxy)
                // In a full RL implementation, we'd look at actual next states
                // For now, we use the pattern's historical success rate
                double maxNextQ = 0.0;
                try
                {
                    var pattern = await GetPatternFromDatabaseAsync(patternId);
                    if (pattern != null)
                    {
                        maxNextQ = pattern.SuccessRate;
                    }
                }
                catch
                {
                    // If we can't get pattern, use 0.0
                }
                
                // Q-Learning update: Q(s,a) = Q(s,a) + α[r + γ*max(Q(s',a')) - Q(s,a)]
                double newQ = currentQ + _learningRate * (reward + _discountFactor * maxNextQ - currentQ);
                
                // Update Q-table
                var key = CreateQKey(state, action);
                _qTable.AddOrUpdate(key, newQ, (k, v) => newQ);
                
                // Persist to database
                await SaveQValueAsync(state, action, newQ);
                
                _logger.Debug("RL: Updated Q({State}, {Action}) = {OldQ:F3} -> {NewQ:F3} (reward={Reward:F3}, success={Success})",
                    state, action, currentQ, newQ, reward, success);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error updating Q-value for {State}, {Action}", state, action);
            }
        }

        /// <summary>
        /// Gets Q-value for a state-action pair
        /// </summary>
        public double GetQValue(string technology, VulnerabilityType vulnerabilityType, string patternId)
        {
            var state = CreateState(technology, vulnerabilityType);
            return GetQValue(state, patternId);
        }

        /// <summary>
        /// Gets Q-value for a state-action pair (internal)
        /// </summary>
        private double GetQValue(string state, string action)
        {
            var key = CreateQKey(state, action);
            return _qTable.GetValueOrDefault(key, 0.0); // Default Q-value is 0.0
        }

        /// <summary>
        /// Creates state string from technology and vulnerability type
        /// </summary>
        private string CreateState(string technology, VulnerabilityType vulnerabilityType)
        {
            // Normalize technology name
            var normalizedTech = technology?.ToLowerInvariant() ?? "unknown";
            return $"{normalizedTech}_{vulnerabilityType}";
        }

        /// <summary>
        /// Creates Q-table key from state and action
        /// </summary>
        private string CreateQKey(string state, string action)
        {
            return $"{state}::{action}";
        }

        /// <summary>
        /// Loads Q-table from database
        /// </summary>
        private async Task LoadQTableAsync()
        {
            try
            {
                // Load Q-values from LearningMetrics table
                using var connection = new SqliteConnection("Data Source=attack_patterns.db");
                await connection.OpenAsync();
                
                var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT MetricName, MetricValue, PatternId 
                    FROM LearningMetrics 
                    WHERE MetricName LIKE 'QValue_%'";
                
                var qValues = new Dictionary<string, double>();
                using var reader = await command.ExecuteReaderAsync();
                
                while (await reader.ReadAsync())
                {
                    var metricName = reader.GetString(reader.GetOrdinal("MetricName"));
                    var qValue = reader.GetDouble(reader.GetOrdinal("MetricValue"));
                    var patternId = reader.GetString(reader.GetOrdinal("PatternId"));
                    
                    // Extract state from metric name (format: "QValue_Technology_VulnerabilityType")
                    var state = metricName.Replace("QValue_", "");
                    var key = CreateQKey(state, patternId);
                    
                    _qTable[key] = qValue;
                }
                
                _logger.Information("Loaded {Count} Q-values from database", _qTable.Count);
            }
            catch (Exception ex)
            {
                _logger.Warning(ex, "Error loading Q-table from database, starting with empty Q-table");
            }
        }

        /// <summary>
        /// Saves Q-value to database
        /// </summary>
        private async Task SaveQValueAsync(string state, string action, double qValue)
        {
            try
            {
                using var connection = new SqliteConnection("Data Source=attack_patterns.db");
                await connection.OpenAsync();
                
                var command = connection.CreateCommand();
                command.CommandText = @"
                    INSERT OR REPLACE INTO LearningMetrics 
                    (Id, MetricName, MetricValue, PatternId, Timestamp)
                    VALUES 
                    (@Id, @MetricName, @MetricValue, @PatternId, @Timestamp)";
                
                var metricId = Guid.NewGuid().ToString();
                var metricName = $"QValue_{state}";
                
                command.Parameters.AddWithValue("@Id", metricId);
                command.Parameters.AddWithValue("@MetricName", metricName);
                command.Parameters.AddWithValue("@MetricValue", qValue);
                command.Parameters.AddWithValue("@PatternId", action);
                command.Parameters.AddWithValue("@Timestamp", DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"));
                
                await command.ExecuteNonQueryAsync();
            }
            catch (Exception ex)
            {
                _logger.Warning(ex, "Error saving Q-value to database: {Error}", ex.Message);
            }
        }

        /// <summary>
        /// Gets pattern from database by ID
        /// </summary>
        private async Task<AttackPattern?> GetPatternFromDatabaseAsync(string patternId)
        {
            try
            {
                // Try to get pattern from all vulnerability types
                var vulnTypes = Enum.GetValues<VulnerabilityType>();
                foreach (var vulnType in vulnTypes)
                {
                    var patterns = await _database.GetOptimizedPatternsAsync("", vulnType);
                    var pattern = patterns.FirstOrDefault(p => p.Id == patternId);
                    if (pattern != null)
                        return pattern;
                }
                return null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Gets statistics about Q-values
        /// </summary>
        public QLearningStatistics GetStatistics()
        {
            return new QLearningStatistics
            {
                TotalQValues = _qTable.Count,
                AverageQValue = _qTable.Values.Any() ? _qTable.Values.Average() : 0.0,
                MaxQValue = _qTable.Values.Any() ? _qTable.Values.Max() : 0.0,
                MinQValue = _qTable.Values.Any() ? _qTable.Values.Min() : 0.0,
                PositiveQValues = _qTable.Values.Count(v => v > 0),
                NegativeQValues = _qTable.Values.Count(v => v < 0)
            };
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
    /// Statistics about Q-learning performance
    /// </summary>
    public class QLearningStatistics
    {
        public int TotalQValues { get; set; }
        public double AverageQValue { get; set; }
        public double MaxQValue { get; set; }
        public double MinQValue { get; set; }
        public int PositiveQValues { get; set; }
        public int NegativeQValues { get; set; }
    }
}


















