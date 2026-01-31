using System.Text.RegularExpressions;
using AttackAgent.Models;
using Serilog;

namespace AttackAgent.Engines
{
    /// <summary>
    /// Parses source code to extract endpoints, parameters, and route information
    /// Supports ASP.NET Core, Express.js, Flask, and other frameworks
    /// </summary>
    public class SourceCodeParser
    {
        private readonly ILogger _logger;

        public SourceCodeParser()
        {
            _logger = Log.ForContext<SourceCodeParser>();
        }

        /// <summary>
        /// Parses source code directory and extracts all endpoints
        /// </summary>
        public async Task<List<EndpointInfo>> ParseSourceCodeAsync(string sourceCodePath)
        {
            var endpoints = new List<EndpointInfo>();

            if (string.IsNullOrEmpty(sourceCodePath) || !Directory.Exists(sourceCodePath))
            {
                _logger.Warning("Source code path does not exist: {Path}", sourceCodePath);
                return endpoints;
            }

            _logger.Information("🔍 Parsing source code from: {Path}", sourceCodePath);

            // Try ASP.NET Core first (most common)
            var aspNetEndpoints = await ParseAspNetCoreAsync(sourceCodePath);
            endpoints.AddRange(aspNetEndpoints);

            // Try Express.js if no ASP.NET endpoints found
            if (!endpoints.Any())
            {
                var expressEndpoints = await ParseExpressJsAsync(sourceCodePath);
                endpoints.AddRange(expressEndpoints);
            }

            // Try Flask if still no endpoints
            if (!endpoints.Any())
            {
                var flaskEndpoints = await ParseFlaskAsync(sourceCodePath);
                endpoints.AddRange(flaskEndpoints);
            }

            _logger.Information("✅ Source code parsing completed. Found {Count} endpoints", endpoints.Count);

            return endpoints;
        }

        /// <summary>
        /// Parses ASP.NET Core applications (Program.cs, Startup.cs, Controllers)
        /// </summary>
        private async Task<List<EndpointInfo>> ParseAspNetCoreAsync(string sourceCodePath)
        {
            var endpoints = new List<EndpointInfo>();

            try
            {
                // Find Program.cs (most common in .NET 6+)
                var programCs = FindFile(sourceCodePath, "Program.cs");
                if (!string.IsNullOrEmpty(programCs))
                {
                    _logger.Information("📄 Found Program.cs: {File}", programCs);
                    var programEndpoints = await ParseProgramCsAsync(programCs);
                    endpoints.AddRange(programEndpoints);
                }

                // Find Startup.cs (older .NET versions)
                var startupCs = FindFile(sourceCodePath, "Startup.cs");
                if (!string.IsNullOrEmpty(startupCs))
                {
                    _logger.Information("📄 Found Startup.cs: {File}", startupCs);
                    var startupEndpoints = await ParseStartupCsAsync(startupCs);
                    endpoints.AddRange(startupEndpoints);
                }

                // Find Controllers (MVC pattern)
                var controllers = FindFiles(sourceCodePath, "*Controller.cs");
                foreach (var controller in controllers)
                {
                    _logger.Debug("📄 Found Controller: {File}", controller);
                    var controllerEndpoints = await ParseControllerAsync(controller);
                    endpoints.AddRange(controllerEndpoints);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error parsing ASP.NET Core source code");
            }

            return endpoints;
        }

        /// <summary>
        /// Parses Program.cs for endpoint definitions (app.MapPost, app.MapGet, etc.)
        /// </summary>
        private async Task<List<EndpointInfo>> ParseProgramCsAsync(string filePath)
        {
            var endpoints = new List<EndpointInfo>();
            var code = await File.ReadAllTextAsync(filePath);

            // Pattern: app.MapPost("/api/chatbot/chat", async (HttpContext context) => { ... })
            // Pattern: app.MapGet("/api/hello", () => { ... })
            var routePattern = @"app\.Map(Post|Get|Put|Delete|Patch)\s*\(\s*""([^""]+)""";
            var matches = Regex.Matches(code, routePattern, RegexOptions.Multiline | RegexOptions.IgnoreCase);

            foreach (Match match in matches)
            {
                var method = match.Groups[1].Value.ToUpper();
                var path = match.Groups[2].Value;

                // Extract endpoint code block to find parameters
                var endpointCode = ExtractEndpointCode(code, match.Index);

                // Extract parameters from endpoint code
                var parameters = ExtractParametersFromCode(endpointCode, path);

                var endpoint = new EndpointInfo
                {
                    Path = path,
                    Method = method,
                    StatusCode = 200, // Assume success for discovered endpoints
                    Parameters = parameters,
                    Source = "Program.cs",
                    IsParameterized = path.Contains("{") || path.Contains(":"),
                    ParameterName = ExtractParameterName(path)
                };

                endpoints.Add(endpoint);
                _logger.Debug("🔍 Found endpoint: {Method} {Path} (from Program.cs)", method, path);
            }

            return endpoints;
        }

        /// <summary>
        /// Parses Startup.cs for endpoint definitions
        /// </summary>
        private async Task<List<EndpointInfo>> ParseStartupCsAsync(string filePath)
        {
            var endpoints = new List<EndpointInfo>();
            var code = await File.ReadAllTextAsync(filePath);

            // Similar pattern to Program.cs
            var routePattern = @"app\.Map(Post|Get|Put|Delete|Patch)\s*\(\s*""([^""]+)""";
            var matches = Regex.Matches(code, routePattern, RegexOptions.Multiline | RegexOptions.IgnoreCase);

            foreach (Match match in matches)
            {
                var method = match.Groups[1].Value.ToUpper();
                var path = match.Groups[2].Value;
                var endpointCode = ExtractEndpointCode(code, match.Index);
                var parameters = ExtractParametersFromCode(endpointCode, path);

                var endpoint = new EndpointInfo
                {
                    Path = path,
                    Method = method,
                    StatusCode = 200,
                    Parameters = parameters,
                    Source = "Startup.cs",
                    IsParameterized = path.Contains("{") || path.Contains(":"),
                    ParameterName = ExtractParameterName(path)
                };

                endpoints.Add(endpoint);
            }

            return endpoints;
        }

        /// <summary>
        /// Parses Controller classes for endpoint definitions
        /// </summary>
        private async Task<List<EndpointInfo>> ParseControllerAsync(string filePath)
        {
            var endpoints = new List<EndpointInfo>();
            var code = await File.ReadAllTextAsync(filePath);

            // Extract controller route prefix
            var routePrefix = ExtractRoutePrefix(code);
            var controllerName = Path.GetFileNameWithoutExtension(filePath).Replace("Controller", "");

            // Pattern: [HttpPost("chat"), HttpGet("history")]
            var httpMethodPattern = @"\[Http(Post|Get|Put|Delete|Patch)\s*\(?\s*""?([^""\)]+)""?\s*\)?\]";
            var methodPattern = @"(public|private)\s+(async\s+)?(IActionResult|ActionResult|Task<IActionResult>|Task<ActionResult>)\s+(\w+)\s*\(";

            var httpMatches = Regex.Matches(code, httpMethodPattern, RegexOptions.IgnoreCase);
            var methodMatches = Regex.Matches(code, methodPattern, RegexOptions.IgnoreCase);

            foreach (Match httpMatch in httpMatches)
            {
                var method = httpMatch.Groups[1].Value.ToUpper();
                var route = httpMatch.Groups[2].Value.Trim('/');

                // Build full path
                var fullPath = $"/{routePrefix}/{controllerName}/{route}".Replace("//", "/");
                if (fullPath.EndsWith("/"))
                    fullPath = fullPath.TrimEnd('/');

                // Extract method code to find parameters
                var methodCode = ExtractMethodCode(code, httpMatch.Index);
                var parameters = ExtractParametersFromCode(methodCode, fullPath);

                var endpoint = new EndpointInfo
                {
                    Path = fullPath,
                    Method = method,
                    StatusCode = 200,
                    Parameters = parameters,
                    Source = Path.GetFileName(filePath),
                    IsParameterized = fullPath.Contains("{") || fullPath.Contains(":"),
                    ParameterName = ExtractParameterName(fullPath)
                };

                endpoints.Add(endpoint);
            }

            return endpoints;
        }

        /// <summary>
        /// Extracts parameters from endpoint code by analyzing request body parsing
        /// </summary>
        private List<ParameterInfo> ExtractParametersFromCode(string endpointCode, string endpointPath)
        {
            var parameters = new List<ParameterInfo>();

            // Pattern 1: requestData["message"].GetString()
            // Pattern 2: requestData["dessertName"].GetString()
            var parameterPattern = @"requestData\[""([^""]+)""\]";
            var matches = Regex.Matches(endpointCode, parameterPattern, RegexOptions.IgnoreCase);

            foreach (Match match in matches)
            {
                var paramName = match.Groups[1].Value;
                if (!parameters.Any(p => p.Name == paramName))
                {
                    parameters.Add(new ParameterInfo
                    {
                        Name = paramName,
                        Location = ParameterLocation.Body,
                        Type = "string" // Default, could be enhanced
                    });
                }
            }

            // Pattern 3: From route parameters: {id}, {userId}
            var routeParamPattern = @"\{(\w+)\}";
            var routeMatches = Regex.Matches(endpointPath, routeParamPattern);
            foreach (Match match in routeMatches)
            {
                var paramName = match.Groups[1].Value;
                if (!parameters.Any(p => p.Name == paramName))
                {
                    parameters.Add(new ParameterInfo
                    {
                        Name = paramName,
                        Location = ParameterLocation.Path,
                        Type = "int" // Common for route parameters
                    });
                }
            }

            // Pattern 4: Query parameters: context.Request.Query["param"]
            var queryPattern = @"Request\.Query\[""([^""]+)""\]|Query\[""([^""]+)""\]";
            var queryMatches = Regex.Matches(endpointCode, queryPattern, RegexOptions.IgnoreCase);
            foreach (Match match in queryMatches)
            {
                var paramName = match.Groups[1].Value ?? match.Groups[2].Value;
                if (!parameters.Any(p => p.Name == paramName))
                {
                    parameters.Add(new ParameterInfo
                    {
                        Name = paramName,
                        Location = ParameterLocation.Query,
                        Type = "string"
                    });
                }
            }

            return parameters;
        }

        /// <summary>
        /// Extracts the code block for an endpoint method
        /// </summary>
        private string ExtractEndpointCode(string code, int startIndex)
        {
            var start = startIndex;
            var braceCount = 0;
            var inString = false;
            var stringChar = '\0';

            // Find the opening brace
            for (int i = start; i < code.Length; i++)
            {
                if (code[i] == '"' || code[i] == '\'')
                {
                    if (!inString)
                    {
                        inString = true;
                        stringChar = code[i];
                    }
                    else if (code[i] == stringChar)
                    {
                        inString = false;
                    }
                }
                else if (!inString && code[i] == '{')
                {
                    start = i;
                    break;
                }
            }

            // Find matching closing brace
            for (int i = start; i < code.Length; i++)
            {
                if (code[i] == '"' || code[i] == '\'')
                {
                    if (!inString)
                    {
                        inString = true;
                        stringChar = code[i];
                    }
                    else if (code[i] == stringChar)
                    {
                        inString = false;
                    }
                }
                else if (!inString)
                {
                    if (code[i] == '{')
                        braceCount++;
                    else if (code[i] == '}')
                    {
                        braceCount--;
                        if (braceCount == 0)
                        {
                            return code.Substring(start, i - start + 1);
                        }
                    }
                }
            }

            // Fallback: return next 500 characters
            var endIndex = Math.Min(start + 500, code.Length);
            return code.Substring(start, endIndex - start);
        }

        /// <summary>
        /// Extracts method code block
        /// </summary>
        private string ExtractMethodCode(string code, int attributeIndex)
        {
            // Find the method declaration after the attribute
            var methodStart = code.IndexOf("async", attributeIndex);
            if (methodStart == -1)
                methodStart = code.IndexOf("public", attributeIndex);

            if (methodStart == -1)
                return "";

            return ExtractEndpointCode(code, methodStart);
        }

        /// <summary>
        /// Extracts route prefix from [Route] attribute
        /// </summary>
        private string ExtractRoutePrefix(string code)
        {
            var routePattern = @"\[Route\s*\(?\s*""?([^""\)]+)""?\s*\)?\]";
            var match = Regex.Match(code, routePattern, RegexOptions.IgnoreCase);
            if (match.Success)
            {
                return match.Groups[1].Value.Trim('/');
            }
            return "";
        }

        /// <summary>
        /// Extracts parameter name from route path
        /// </summary>
        private string? ExtractParameterName(string path)
        {
            var match = Regex.Match(path, @"\{(\w+)\}");
            return match.Success ? match.Groups[1].Value : null;
        }

        /// <summary>
        /// Finds a file in the source code directory
        /// </summary>
        private string? FindFile(string directory, string fileName)
        {
            try
            {
                var files = Directory.GetFiles(directory, fileName, SearchOption.AllDirectories);
                return files.FirstOrDefault();
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Finds multiple files matching pattern
        /// </summary>
        private List<string> FindFiles(string directory, string pattern)
        {
            try
            {
                return Directory.GetFiles(directory, pattern, SearchOption.AllDirectories).ToList();
            }
            catch
            {
                return new List<string>();
            }
        }

        /// <summary>
        /// Parses Express.js applications (app.js, routes/*.js)
        /// </summary>
        private Task<List<EndpointInfo>> ParseExpressJsAsync(string sourceCodePath)
        {
            var endpoints = new List<EndpointInfo>();
            // TODO: Implement Express.js parsing
            return Task.FromResult(endpoints);
        }

        /// <summary>
        /// Parses Flask applications (app.py, routes.py)
        /// </summary>
        private Task<List<EndpointInfo>> ParseFlaskAsync(string sourceCodePath)
        {
            var endpoints = new List<EndpointInfo>();
            // TODO: Implement Flask parsing
            return Task.FromResult(endpoints);
        }
    }
}

