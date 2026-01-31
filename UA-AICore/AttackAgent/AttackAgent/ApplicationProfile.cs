using System.Text.Json.Serialization;

namespace AttackAgent.Models
{
    /// <summary>
    /// Represents a comprehensive profile of the target application
    /// discovered through reconnaissance and analysis
    /// </summary>
    public class ApplicationProfile
    {
        [JsonPropertyName("baseUrl")]
        public string BaseUrl { get; set; } = string.Empty;

        [JsonPropertyName("applicationName")]
        public string ApplicationName { get; set; } = string.Empty;

        [JsonPropertyName("discoveredEndpoints")]
        public List<EndpointInfo> DiscoveredEndpoints { get; set; } = new();

        [JsonPropertyName("technologyStack")]
        public TechnologyStack TechnologyStack { get; set; } = new();

        [JsonPropertyName("securityFeatures")]
        public SecurityFeatures SecurityFeatures { get; set; } = new();

        [JsonPropertyName("authenticationSystem")]
        public AuthenticationSystem AuthenticationSystem { get; set; } = new();

        [JsonPropertyName("discoveryTimestamp")]
        public DateTime DiscoveryTimestamp { get; set; } = DateTime.UtcNow;

        [JsonPropertyName("scanDuration")]
        public TimeSpan ScanDuration { get; set; }

        [JsonPropertyName("totalEndpoints")]
        public int TotalEndpoints => DiscoveredEndpoints.Count;

        [JsonPropertyName("endpoints")]
        public List<EndpointInfo> Endpoints => DiscoveredEndpoints;

        [JsonPropertyName("riskLevel")]
        public RiskLevel RiskLevel { get; set; } = RiskLevel.Unknown;

        [JsonPropertyName("staticFiles")]
        public List<string> StaticFiles { get; set; } = new();

        [JsonPropertyName("configurationVulnerabilities")]
        public List<Vulnerability> ConfigurationVulnerabilities { get; set; } = new();
    }

    /// <summary>
    /// Information about a discovered endpoint
    /// </summary>
    public class EndpointInfo
    {
        [JsonPropertyName("path")]
        public string Path { get; set; } = string.Empty;

        [JsonPropertyName("method")]
        public string Method { get; set; } = string.Empty;

        [JsonPropertyName("parameters")]
        public List<ParameterInfo> Parameters { get; set; } = new();

        [JsonPropertyName("responseHeaders")]
        public Dictionary<string, string> ResponseHeaders { get; set; } = new();

        [JsonPropertyName("statusCode")]
        public int StatusCode { get; set; }

        [JsonPropertyName("responseTime")]
        public TimeSpan ResponseTime { get; set; }

        [JsonPropertyName("requiresAuthentication")]
        public bool RequiresAuthentication { get; set; }

        [JsonPropertyName("potentialVulnerabilities")]
        public List<string> PotentialVulnerabilities { get; set; } = new();

        [JsonPropertyName("isParameterized")]
        public bool IsParameterized { get; set; } = false;

        [JsonPropertyName("parameterName")]
        public string? ParameterName { get; set; }

        [JsonPropertyName("parameterValue")]
        public string? ParameterValue { get; set; }

        [JsonPropertyName("source")]
        public string? Source { get; set; }

        [JsonPropertyName("endpoint")]
        public string Endpoint => Path;
    }

    /// <summary>
    /// Information about endpoint parameters
    /// </summary>
    public class ParameterInfo
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("type")]
        public string Type { get; set; } = string.Empty;

        [JsonPropertyName("location")]
        public ParameterLocation Location { get; set; }

        [JsonPropertyName("required")]
        public bool Required { get; set; }

        [JsonPropertyName("exampleValue")]
        public string? ExampleValue { get; set; }
    }

    /// <summary>
    /// Where the parameter is located in the request
    /// </summary>
    public enum ParameterLocation
    {
        Query,
        Body,
        Header,
        Path,
        Cookie
    }

    /// <summary>
    /// Detected technology stack information
    /// </summary>
    public class TechnologyStack
    {
        [JsonPropertyName("framework")]
        public string Framework { get; set; } = string.Empty;

        [JsonPropertyName("frameworkVersion")]
        public string? FrameworkVersion { get; set; }

        [JsonPropertyName("database")]
        public string? Database { get; set; }

        [JsonPropertyName("databaseVersion")]
        public string? DatabaseVersion { get; set; }

        [JsonPropertyName("webServer")]
        public string? WebServer { get; set; }

        [JsonPropertyName("programmingLanguage")]
        public string ProgrammingLanguage { get; set; } = string.Empty;

        [JsonPropertyName("orm")]
        public string? Orm { get; set; }

        [JsonPropertyName("authenticationFramework")]
        public string? AuthenticationFramework { get; set; }

        [JsonPropertyName("detectedLibraries")]
        public List<string> DetectedLibraries { get; set; } = new();

        [JsonPropertyName("confidence")]
        public double Confidence { get; set; } // 0.0 to 1.0
    }

    /// <summary>
    /// Detected security features and configurations
    /// </summary>
    public class SecurityFeatures
    {
        [JsonPropertyName("hasCors")]
        public bool HasCors { get; set; }

        [JsonPropertyName("corsConfiguration")]
        public string? CorsConfiguration { get; set; }

        [JsonPropertyName("hasRateLimiting")]
        public bool HasRateLimiting { get; set; }

        [JsonPropertyName("hasHttps")]
        public bool HasHttps { get; set; }

        [JsonPropertyName("hasSecurityHeaders")]
        public bool HasSecurityHeaders { get; set; }

        [JsonPropertyName("securityHeaders")]
        public List<string> SecurityHeaders { get; set; } = new();

        [JsonPropertyName("hasInputValidation")]
        public bool HasInputValidation { get; set; }

        [JsonPropertyName("hasCsrfProtection")]
        public bool HasCsrfProtection { get; set; }

        [JsonPropertyName("hasSessionManagement")]
        public bool HasSessionManagement { get; set; }

        [JsonPropertyName("hasFileUpload")]
        public bool HasFileUpload { get; set; }

        [JsonPropertyName("hasCameraAccess")]
        public bool HasCameraAccess { get; set; }
    }

    /// <summary>
    /// Information about the authentication system
    /// </summary>
    public class AuthenticationSystem
    {
        [JsonPropertyName("type")]
        public AuthenticationType Type { get; set; } = AuthenticationType.Unknown;

        [JsonPropertyName("hasAuthentication")]
        public bool HasAuthentication { get; set; }

        [JsonPropertyName("authenticationEndpoints")]
        public List<string> AuthenticationEndpoints { get; set; } = new();

        [JsonPropertyName("tokenType")]
        public string? TokenType { get; set; }

        [JsonPropertyName("sessionManagement")]
        public string? SessionManagement { get; set; }

        [JsonPropertyName("passwordPolicy")]
        public string? PasswordPolicy { get; set; }

        [JsonPropertyName("multiFactorAuth")]
        public bool MultiFactorAuth { get; set; }

        [JsonPropertyName("accountLockout")]
        public bool AccountLockout { get; set; }
    }

    /// <summary>
    /// Types of authentication systems
    /// </summary>
    public enum AuthenticationType
    {
        Unknown,
        None,
        Basic,
        Bearer,
        JWT,
        Session,
        OAuth,
        Custom
    }

    /// <summary>
    /// Overall risk level of the application
    /// </summary>
    public enum RiskLevel
    {
        Unknown,
        Low,
        Medium,
        High,
        Critical
    }
}
