using AttackAgent.Models;
using Serilog;
using System.Text.RegularExpressions;

namespace AttackAgent
{
    /// <summary>
    /// Enhanced technology detection with improved service and integration detection
    /// </summary>
    public class EnhancedTechnologyDetector
    {
        private readonly SecurityHttpClient _httpClient;
        private readonly ILogger _logger;

        public EnhancedTechnologyDetector(string baseUrl = "")
        {
            _httpClient = new SecurityHttpClient(baseUrl);
            _logger = Log.ForContext<EnhancedTechnologyDetector>();
        }

        /// <summary>
        /// Performs enhanced technology stack analysis
        /// </summary>
        public async Task<TechnologyStack> AnalyzeTechnologyStackAsync(ApplicationProfile profile)
        {
            _logger.Information("🔍 Performing enhanced technology stack analysis...");
            
            var techStack = new TechnologyStack();
            
            // Analyze all discovered endpoints for technology indicators
            foreach (var endpoint in profile.DiscoveredEndpoints)
            {
                try
                {
                    var response = await _httpClient.GetAsync(endpoint.Path);
                    if (response.Success)
                    {
                        // Analyze response for various technologies
                        AnalyzeDatabaseTechnologies(techStack, response.Content, endpoint.Path);
                        AnalyzeAIServices(techStack, response.Content, endpoint.Path);
                        AnalyzeORMTechnologies(techStack, response.Content, endpoint.Path);
                        AnalyzeWebFrameworks(techStack, response.Content, endpoint.Path);
                        AnalyzeAuthenticationFrameworks(techStack, response.Content, endpoint.Path);
                        AnalyzeExternalServices(techStack, response.Content, endpoint.Path);
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Error analyzing endpoint {Endpoint} for technology", endpoint.Path);
                }
            }
            
            // Test specific technology endpoints
            await TestTechnologyEndpointsAsync(profile, techStack);
            
            // Analyze configuration files
            await AnalyzeConfigurationFilesAsync(profile, techStack);
            
            _logger.Information("✅ Enhanced technology analysis completed");
            return techStack;
        }

        /// <summary>
        /// Analyzes content for database technology indicators
        /// </summary>
        private void AnalyzeDatabaseTechnologies(TechnologyStack techStack, string content, string endpoint)
        {
            // SQL Server indicators
            if (content.Contains("Microsoft.Data.SqlClient") || content.Contains("SqlConnection") || 
                content.Contains("sql5111.site4now.net") || content.Contains("SQL Server"))
            {
                techStack.Database = "SQL Server";
                techStack.Confidence = Math.Max(techStack.Confidence, 0.95f);
                _logger.Information("🔍 Detected SQL Server database from {Endpoint}", endpoint);
            }
            
            // MySQL indicators
            if (content.Contains("MySqlConnection") || content.Contains("mysql") || 
                content.Contains("MariaDB"))
            {
                techStack.Database = "MySQL";
                techStack.Confidence = Math.Max(techStack.Confidence, 0.90f);
                _logger.Information("🔍 Detected MySQL database from {Endpoint}", endpoint);
            }
            
            // PostgreSQL indicators
            if (content.Contains("Npgsql") || content.Contains("postgresql") || 
                content.Contains("PostgreSQL"))
            {
                techStack.Database = "PostgreSQL";
                techStack.Confidence = Math.Max(techStack.Confidence, 0.90f);
                _logger.Information("🔍 Detected PostgreSQL database from {Endpoint}", endpoint);
            }
        }

        /// <summary>
        /// Analyzes content for AI service indicators
        /// </summary>
        private void AnalyzeAIServices(TechnologyStack techStack, string content, string endpoint)
        {
            // Enhanced OpenAI indicators
            if (content.Contains("OpenAI") || content.Contains("sk-proj-") || content.Contains("ChatGPT") ||
                content.Contains("DALL-E") || content.Contains("GPT-") || content.Contains("gpt-3.5-turbo") ||
                content.Contains("gpt-4") || content.Contains("text-davinci") || content.Contains("whisper") ||
                content.Contains("api.openai.com"))
            {
                if (!techStack.DetectedLibraries.Contains("OpenAI"))
                {
                    techStack.DetectedLibraries.Add("OpenAI");
                }
                _logger.Information("🔍 Detected OpenAI integration from {Endpoint}", endpoint);
            }
            
            // Anthropic Claude indicators
            if (content.Contains("Anthropic") || content.Contains("Claude") || content.Contains("claude-3") ||
                content.Contains("anthropic-api") || content.Contains("claude-opus"))
            {
                if (!techStack.DetectedLibraries.Contains("Anthropic Claude"))
                {
                    techStack.DetectedLibraries.Add("Anthropic Claude");
                }
                _logger.Information("🔍 Detected Anthropic Claude integration from {Endpoint}", endpoint);
            }
            
            // Google AI indicators
            if (content.Contains("Gemini") || content.Contains("Bard") || content.Contains("Palm") ||
                content.Contains("Vertex AI") || content.Contains("Google AI") || content.Contains("gemini-pro"))
            {
                if (!techStack.DetectedLibraries.Contains("Google AI"))
                {
                    techStack.DetectedLibraries.Add("Google AI");
                }
                _logger.Information("🔍 Detected Google AI integration from {Endpoint}", endpoint);
            }
            
            // Microsoft Azure AI indicators
            if (content.Contains("Azure OpenAI") || content.Contains("Azure Cognitive Services") ||
                content.Contains("Bing Chat") || content.Contains("Copilot") || content.Contains("azure-openai"))
            {
                if (!techStack.DetectedLibraries.Contains("Microsoft Azure AI"))
                {
                    techStack.DetectedLibraries.Add("Microsoft Azure AI");
                }
                _logger.Information("🔍 Detected Microsoft Azure AI integration from {Endpoint}", endpoint);
            }
            
            // AWS AI indicators
            if (content.Contains("AWS Bedrock") || content.Contains("Amazon Bedrock") ||
                content.Contains("SageMaker") || content.Contains("Comprehend") || content.Contains("Rekognition"))
            {
                if (!techStack.DetectedLibraries.Contains("AWS AI"))
                {
                    techStack.DetectedLibraries.Add("AWS AI");
                }
                _logger.Information("🔍 Detected AWS AI integration from {Endpoint}", endpoint);
            }
        }

        /// <summary>
        /// Analyzes content for ORM technology indicators
        /// </summary>
        private void AnalyzeORMTechnologies(TechnologyStack techStack, string content, string endpoint)
        {
            // Entity Framework Core specific indicators
            if (content.Contains("Microsoft.EntityFrameworkCore.SqlServer") || 
                content.Contains("UseSqlServer") || content.Contains("AddDbContext") ||
                content.Contains("EntityFramework") || content.Contains("DbContext") || 
                content.Contains("DbSet"))
            {
                techStack.Orm = "Entity Framework Core";
                techStack.Confidence = Math.Max(techStack.Confidence, 0.95f);
                _logger.Information("🔍 Detected Entity Framework Core ORM from {Endpoint}", endpoint);
            }
            
            // Dapper indicators
            if (content.Contains("Dapper") || content.Contains("IDbConnection"))
            {
                techStack.Orm = "Dapper";
                techStack.Confidence = Math.Max(techStack.Confidence, 0.85f);
                _logger.Information("🔍 Detected Dapper ORM from {Endpoint}", endpoint);
            }
            
            // NHibernate indicators
            if (content.Contains("NHibernate") || content.Contains("ISession"))
            {
                techStack.Orm = "NHibernate";
                techStack.Confidence = Math.Max(techStack.Confidence, 0.85f);
                _logger.Information("🔍 Detected NHibernate ORM from {Endpoint}", endpoint);
            }
        }

        /// <summary>
        /// Analyzes content for web framework indicators
        /// </summary>
        private void AnalyzeWebFrameworks(TechnologyStack techStack, string content, string endpoint)
        {
            // ASP.NET Core indicators
            if (content.Contains("ASP.NET Core") || content.Contains("Microsoft.AspNetCore") ||
                content.Contains("Kestrel") || content.Contains("UseRouting") || content.Contains("MapControllers"))
            {
                techStack.Framework = "ASP.NET Core";
                techStack.ProgrammingLanguage = "C#";
                techStack.Confidence = Math.Max(techStack.Confidence, 0.95f);
                _logger.Information("🔍 Detected ASP.NET Core framework from {Endpoint}", endpoint);
            }
            
            // ASP.NET Framework indicators
            if (content.Contains("System.Web") || content.Contains("HttpContext") ||
                content.Contains("IIS") || content.Contains("Web.config"))
            {
                techStack.Framework = "ASP.NET Framework";
                techStack.ProgrammingLanguage = "C#";
                techStack.Confidence = Math.Max(techStack.Confidence, 0.90f);
                _logger.Information("🔍 Detected ASP.NET Framework from {Endpoint}", endpoint);
            }
            
            // Node.js indicators
            if (content.Contains("Express") || content.Contains("Node.js") || content.Contains("npm") ||
                content.Contains("package.json"))
            {
                techStack.Framework = "Express.js";
                techStack.ProgrammingLanguage = "JavaScript";
                techStack.Confidence = Math.Max(techStack.Confidence, 0.90f);
                _logger.Information("🔍 Detected Express.js framework from {Endpoint}", endpoint);
            }
            
            // React indicators
            if (content.Contains("React") || content.Contains("react-dom") || content.Contains("JSX"))
            {
                if (!techStack.DetectedLibraries.Contains("React"))
                {
                    techStack.DetectedLibraries.Add("React");
                }
                _logger.Information("🔍 Detected React library from {Endpoint}", endpoint);
            }
            
            // Angular indicators
            if (content.Contains("Angular") || content.Contains("@angular") || content.Contains("ng-"))
            {
                if (!techStack.DetectedLibraries.Contains("Angular"))
                {
                    techStack.DetectedLibraries.Add("Angular");
                }
                _logger.Information("🔍 Detected Angular library from {Endpoint}", endpoint);
            }
        }

        /// <summary>
        /// Analyzes content for authentication framework indicators
        /// </summary>
        private void AnalyzeAuthenticationFrameworks(TechnologyStack techStack, string content, string endpoint)
        {
            // JWT indicators
            if (content.Contains("JWT") || content.Contains("JsonWebToken") || content.Contains("Bearer") ||
                content.Contains("jwt.io") || content.Contains("eyJ"))
            {
                techStack.AuthenticationFramework = "JWT";
                _logger.Information("🔍 Detected JWT authentication from {Endpoint}", endpoint);
            }
            
            // OAuth indicators
            if (content.Contains("OAuth") || content.Contains("oauth2") || content.Contains("authorization_code"))
            {
                techStack.AuthenticationFramework = "OAuth";
                _logger.Information("🔍 Detected OAuth authentication from {Endpoint}", endpoint);
            }
            
            // Identity Server indicators
            if (content.Contains("IdentityServer") || content.Contains("IdentityServer4"))
            {
                techStack.AuthenticationFramework = "Identity Server";
                _logger.Information("🔍 Detected Identity Server from {Endpoint}", endpoint);
            }
        }

        /// <summary>
        /// Analyzes content for external service indicators
        /// </summary>
        private void AnalyzeExternalServices(TechnologyStack techStack, string content, string endpoint)
        {
            // Payment services
            if (content.Contains("Stripe") || content.Contains("PayPal") || content.Contains("Square"))
            {
                if (!techStack.DetectedLibraries.Contains("Payment Services"))
                {
                    techStack.DetectedLibraries.Add("Payment Services");
                }
                _logger.Information("🔍 Detected payment services from {Endpoint}", endpoint);
            }
            
            // Cloud services
            if (content.Contains("AWS") || content.Contains("Amazon Web Services"))
            {
                if (!techStack.DetectedLibraries.Contains("AWS"))
                {
                    techStack.DetectedLibraries.Add("AWS");
                }
                _logger.Information("🔍 Detected AWS services from {Endpoint}", endpoint);
            }
            
            if (content.Contains("Azure") || content.Contains("Microsoft Azure"))
            {
                if (!techStack.DetectedLibraries.Contains("Microsoft Azure"))
                {
                    techStack.DetectedLibraries.Add("Microsoft Azure");
                }
                _logger.Information("🔍 Detected Microsoft Azure services from {Endpoint}", endpoint);
            }
            
            if (content.Contains("Google Cloud") || content.Contains("GCP"))
            {
                if (!techStack.DetectedLibraries.Contains("Google Cloud"))
                {
                    techStack.DetectedLibraries.Add("Google Cloud");
                }
                _logger.Information("🔍 Detected Google Cloud services from {Endpoint}", endpoint);
            }
        }

        /// <summary>
        /// Tests specific technology endpoints
        /// </summary>
        private async Task TestTechnologyEndpointsAsync(ApplicationProfile profile, TechnologyStack techStack)
        {
            var baseUrl = profile.BaseUrl;
            
            // Test database connection endpoints
            var dbEndpoints = new[] { "/api/db-test", "/api/database", "/api/connection", "/api/health" };
            foreach (var endpoint in dbEndpoints)
            {
                try
                {
                    var response = await _httpClient.GetAsync(baseUrl.TrimEnd('/') + endpoint);
                    if (response.Success && response.Content.Contains("database"))
                    {
                        techStack.Database = "SQL Server";
                        _logger.Information("🔍 Confirmed database technology from {Endpoint}", endpoint);
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Error testing database endpoint {Endpoint}", endpoint);
                }
            }
            
            // Test AI service endpoints
            var aiEndpoints = new[] { "/api/chatbot", "/api/ai", "/api/chat", "/api/recipe" };
            foreach (var endpoint in aiEndpoints)
            {
                try
                {
                    var response = await _httpClient.GetAsync(baseUrl.TrimEnd('/') + endpoint);
                    if (response.Success && (response.Content.Contains("OpenAI") || response.Content.Contains("AI")))
                    {
                        if (!techStack.DetectedLibraries.Contains("OpenAI"))
                        {
                            techStack.DetectedLibraries.Add("OpenAI");
                        }
                        _logger.Information("🔍 Confirmed AI services from {Endpoint}", endpoint);
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Error testing AI endpoint {Endpoint}", endpoint);
                }
            }
        }

        /// <summary>
        /// Analyzes configuration files for technology indicators
        /// </summary>
        private async Task AnalyzeConfigurationFilesAsync(ApplicationProfile profile, TechnologyStack techStack)
        {
            var baseUrl = profile.BaseUrl;
            var configFiles = new[]
            {
                "/appsettings.json", "/web.config", "/package.json", "/composer.json",
                "/requirements.txt", "/Gemfile", "/pom.xml", "/build.gradle"
            };

            foreach (var configFile in configFiles)
            {
                try
                {
                    var response = await _httpClient.GetAsync(baseUrl.TrimEnd('/') + configFile);
                    if (response.Success)
                    {
                        _logger.Information("🔍 Found configuration file: {ConfigFile}", configFile);
                        
                        // Analyze based on file type
                        if (configFile.EndsWith(".json"))
                        {
                            AnalyzeJsonConfiguration(techStack, response.Content);
                        }
                        else if (configFile.EndsWith(".xml"))
                        {
                            AnalyzeXmlConfiguration(techStack, response.Content);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Error analyzing configuration file {ConfigFile}", configFile);
                }
            }
        }

        /// <summary>
        /// Analyzes JSON configuration files
        /// </summary>
        private void AnalyzeJsonConfiguration(TechnologyStack techStack, string content)
        {
            // Look for common configuration patterns
            if (content.Contains("ConnectionStrings") || content.Contains("DefaultConnection"))
            {
                techStack.Confidence = Math.Max(techStack.Confidence, 0.8f);
            }
            
            if (content.Contains("OpenAI") || content.Contains("ApiKey"))
            {
                if (!techStack.DetectedLibraries.Contains("OpenAI"))
                {
                    techStack.DetectedLibraries.Add("OpenAI");
                }
            }
        }

        /// <summary>
        /// Analyzes XML configuration files
        /// </summary>
        private void AnalyzeXmlConfiguration(TechnologyStack techStack, string content)
        {
            // Look for ASP.NET configuration
            if (content.Contains("system.web") || content.Contains("system.webServer"))
            {
                techStack.Framework = "ASP.NET Framework";
                techStack.ProgrammingLanguage = "C#";
            }
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
}

