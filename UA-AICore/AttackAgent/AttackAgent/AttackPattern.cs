using System.Text.Json.Serialization;

namespace AttackAgent.Models
{
    /// <summary>
    /// Represents an attack pattern that can be used to test for vulnerabilities
    /// </summary>
    public class AttackPattern
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = Guid.NewGuid().ToString();

        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("description")]
        public string Description { get; set; } = string.Empty;

        [JsonPropertyName("vulnerabilityType")]
        public VulnerabilityType VulnerabilityType { get; set; }

        [JsonPropertyName("attackMode")]
        public AttackMode AttackMode { get; set; }

        [JsonPropertyName("targetTechnologies")]
        public List<string> TargetTechnologies { get; set; } = new();

        [JsonPropertyName("payloads")]
        public List<AttackPayload> Payloads { get; set; } = new();

        [JsonPropertyName("successIndicators")]
        public List<SuccessIndicator> SuccessIndicators { get; set; } = new();

        [JsonPropertyName("failureIndicators")]
        public List<FailureIndicator> FailureIndicators { get; set; } = new();

        [JsonPropertyName("riskLevel")]
        public RiskLevel RiskLevel { get; set; }

        [JsonPropertyName("successRate")]
        public double SuccessRate { get; set; } // 0.0 to 1.0

        [JsonPropertyName("usageCount")]
        public int UsageCount { get; set; }

        [JsonPropertyName("lastUsed")]
        public DateTime? LastUsed { get; set; }

        [JsonPropertyName("createdAt")]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        [JsonPropertyName("tags")]
        public List<string> Tags { get; set; } = new();

        [JsonPropertyName("requiresAuthentication")]
        public bool RequiresAuthentication { get; set; }

        [JsonPropertyName("parameterTypes")]
        public List<string> ParameterTypes { get; set; } = new();
    }

    /// <summary>
    /// Represents a specific attack payload
    /// </summary>
    public class AttackPayload
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = Guid.NewGuid().ToString();

        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("payload")]
        public string Payload { get; set; } = string.Empty;

        [JsonPropertyName("description")]
        public string Description { get; set; } = string.Empty;

        [JsonPropertyName("targetParameter")]
        public string? TargetParameter { get; set; }

        [JsonPropertyName("parameterType")]
        public string ParameterType { get; set; } = "query";

        [JsonPropertyName("method")]
        public string Method { get; set; } = "GET";

        [JsonPropertyName("headers")]
        public Dictionary<string, string> Headers { get; set; } = new();

        [JsonPropertyName("targetTechnologies")]
        public List<string> TargetTechnologies { get; set; } = new();

        [JsonPropertyName("riskLevel")]
        public RiskLevel RiskLevel { get; set; }

        [JsonPropertyName("requiresAuthentication")]
        public bool RequiresAuthentication { get; set; }

        [JsonPropertyName("successRate")]
        public double SuccessRate { get; set; } // 0.0 to 1.0

        [JsonPropertyName("usageCount")]
        public int UsageCount { get; set; }

        [JsonPropertyName("lastUsed")]
        public DateTime? LastUsed { get; set; }

        [JsonPropertyName("tags")]
        public List<string> Tags { get; set; } = new();

        [JsonPropertyName("severity")]
        public SeverityLevel Severity { get; set; }
    }

    /// <summary>
    /// Indicates how to recognize a successful attack
    /// </summary>
    public class SuccessIndicator
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = Guid.NewGuid().ToString();

        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("type")]
        public IndicatorType Type { get; set; }

        [JsonPropertyName("pattern")]
        public string Pattern { get; set; } = string.Empty;

        [JsonPropertyName("description")]
        public string Description { get; set; } = string.Empty;

        [JsonPropertyName("location")]
        public IndicatorLocation Location { get; set; }

        [JsonPropertyName("confidence")]
        public double Confidence { get; set; } // 0.0 to 1.0

        [JsonPropertyName("severity")]
        public SeverityLevel Severity { get; set; }

        [JsonPropertyName("createdAt")]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        [JsonPropertyName("tags")]
        public List<string> Tags { get; set; } = new();

        [JsonPropertyName("caseSensitive")]
        public bool CaseSensitive { get; set; } = false;

        [JsonPropertyName("regex")]
        public bool IsRegex { get; set; } = false;
    }

    /// <summary>
    /// Indicates how to recognize a failed attack
    /// </summary>
    public class FailureIndicator
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = Guid.NewGuid().ToString();

        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("type")]
        public IndicatorType Type { get; set; }

        [JsonPropertyName("pattern")]
        public string Pattern { get; set; } = string.Empty;

        [JsonPropertyName("description")]
        public string Description { get; set; } = string.Empty;

        [JsonPropertyName("location")]
        public IndicatorLocation Location { get; set; }

        [JsonPropertyName("confidence")]
        public double Confidence { get; set; } // 0.0 to 1.0

        [JsonPropertyName("createdAt")]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        [JsonPropertyName("tags")]
        public List<string> Tags { get; set; } = new();

        [JsonPropertyName("caseSensitive")]
        public bool CaseSensitive { get; set; } = false;

        [JsonPropertyName("regex")]
        public bool IsRegex { get; set; } = false;
    }

    /// <summary>
    /// Types of indicators for success/failure detection
    /// </summary>
    public enum IndicatorType
    {
        ResponseCode,      // HTTP status code
        ResponseBody,      // Content in response body
        ResponseHeader,    // HTTP header
        ResponseTime,      // Response timing
        ErrorMessage,      // Error messages
        DatabaseError,     // Database-specific errors
        FrameworkError,    // Framework-specific errors
        Custom             // Custom pattern
    }

    /// <summary>
    /// Where to look for the indicator
    /// </summary>
    public enum IndicatorLocation
    {
        ResponseBody,
        ResponseHeaders,
        StatusCode,
        ResponseTime,
        ErrorMessage,
        All
    }

    /// <summary>
    /// Result of executing an attack pattern
    /// </summary>
    public class AttackResult
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = Guid.NewGuid().ToString();

        [JsonPropertyName("patternId")]
        public string PatternId { get; set; } = string.Empty;

        [JsonPropertyName("targetUrl")]
        public string TargetUrl { get; set; } = string.Empty;

        [JsonPropertyName("targetTechnology")]
        public string? TargetTechnology { get; set; }

        [JsonPropertyName("payload")]
        public string Payload { get; set; } = string.Empty;

        [JsonPropertyName("success")]
        public bool Success { get; set; }

        [JsonPropertyName("responseCode")]
        public int? ResponseCode { get; set; }

        [JsonPropertyName("responseTime")]
        public int? ResponseTime { get; set; } // milliseconds

        [JsonPropertyName("responseBody")]
        public string? ResponseBody { get; set; }

        [JsonPropertyName("errorMessage")]
        public string? ErrorMessage { get; set; }

        [JsonPropertyName("confidence")]
        public double Confidence { get; set; } // 0.0 to 1.0

        [JsonPropertyName("falsePositive")]
        public bool FalsePositive { get; set; } = false;

        [JsonPropertyName("timestamp")]
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        [JsonPropertyName("attackMode")]
        public AttackMode AttackMode { get; set; }

        [JsonPropertyName("vulnerabilityType")]
        public VulnerabilityType VulnerabilityType { get; set; }
    }

    /// <summary>
    /// Learning data for improving attack patterns
    /// </summary>
    public class LearningData
    {
        [JsonPropertyName("patternId")]
        public string PatternId { get; set; } = string.Empty;

        [JsonPropertyName("payloadId")]
        public string PayloadId { get; set; } = string.Empty;

        [JsonPropertyName("technology")]
        public string Technology { get; set; } = string.Empty;

        [JsonPropertyName("success")]
        public bool Success { get; set; }

        [JsonPropertyName("confidence")]
        public double Confidence { get; set; }

        [JsonPropertyName("responseTime")]
        public TimeSpan ResponseTime { get; set; }

        [JsonPropertyName("statusCode")]
        public int StatusCode { get; set; }

        [JsonPropertyName("responseLength")]
        public int ResponseLength { get; set; }

        [JsonPropertyName("timestamp")]
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        [JsonPropertyName("verified")]
        public bool Verified { get; set; } = false;

        [JsonPropertyName("falsePositive")]
        public bool FalsePositive { get; set; } = false;
    }
}
