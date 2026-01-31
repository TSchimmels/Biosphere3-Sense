using System.Text.RegularExpressions;
using AttackAgent.Models;
using Serilog;

namespace AttackAgent
{
    /// <summary>
    /// Tests for file-related security vulnerabilities including path traversal and file upload
    /// </summary>
    public class FileSecurityScanner
    {
        private readonly SecurityHttpClient _httpClient;
        private readonly ILogger _logger;
        
        private readonly string[] _pathTraversalPayloads = new[]
        {
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "..%255c..%255c..%255cwindows%255csystem32%255cdrivers%255cetc%255chosts",
            "../../../var/log/apache2/access.log",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "../../../proc/version",
            "../../../proc/cpuinfo",
            "../../../proc/meminfo",
            "../../../etc/shadow",
            "../../../etc/hosts",
            "../../../etc/fstab",
            "../../../boot.ini",
            "../../../windows/system.ini",
            "../../../windows/win.ini"
        };
        
        private readonly string[] _sensitiveFilePatterns = new[]
        {
            ".env", ".env.local", ".env.production", ".env.development",
            "appsettings.json", "appsettings.*.json", "web.config", "config.xml",
            "secrets.json", "credentials.json", "keys.json", "passwords.txt",
            "backup.sql", "dump.sql", "database.sql", "db_backup.sql",
            "id_rsa", "id_dsa", "private.key", "cert.pem", "certificate.pem",
            "composer.json", "package.json", "requirements.txt", "Gemfile",
            "Dockerfile", "docker-compose.yml", ".git/config", ".svn/entries",
            "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml"
        };
        
        private readonly string[] _fileUploadTestFiles = new[]
        {
            "test.txt", "test.php", "test.jsp", "test.asp", "test.aspx",
            "test.html", "test.js", "test.css", "test.xml", "test.json",
            "malicious.exe", "malicious.bat", "malicious.sh", "malicious.py",
            "shell.php", "webshell.jsp", "backdoor.asp", "trojan.exe"
        };
        
        private readonly string[] _systemFileIndicators = new[]
        {
            "root:x:", "daemon:x:", "bin:x:", "sys:x:", "adm:x:",
            "127.0.0.1", "localhost", "::1", "fe80::1%lo0",
            "Microsoft Windows", "Linux version", "Darwin Kernel",
            "Apache/", "nginx/", "IIS/", "Microsoft-IIS/",
            "MySQL", "PostgreSQL", "SQLite", "Oracle",
            "BEGIN CERTIFICATE", "-----BEGIN", "-----END"
        };

        public FileSecurityScanner(string baseUrl = "")
        {
            _httpClient = new SecurityHttpClient(baseUrl);
            _logger = Log.ForContext<FileSecurityScanner>();
        }

        /// <summary>
        /// Scans for file-related security vulnerabilities
        /// </summary>
        public async Task<List<Vulnerability>> TestFileSecurityAsync(ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            _logger.Information("🔍 Starting file security scanning...");
            _logger.Information("🔍 Testing {EndpointCount} endpoints for file vulnerabilities...", profile.DiscoveredEndpoints.Count);

            // Test each endpoint for file-related vulnerabilities
            foreach (var endpoint in profile.DiscoveredEndpoints)
            {
                try
                {
                    // Test for path traversal vulnerabilities
                    var pathTraversalVulns = await TestPathTraversalAsync(endpoint, profile.BaseUrl);
                    vulnerabilities.AddRange(pathTraversalVulns);
                    
                    // Test for file upload vulnerabilities
                    var fileUploadVulns = await TestFileUploadAsync(endpoint, profile.BaseUrl);
                    vulnerabilities.AddRange(fileUploadVulns);
                    
                    // Test for sensitive file exposure
                    var sensitiveFileVulns = await TestSensitiveFileExposureAsync(endpoint, profile.BaseUrl);
                    vulnerabilities.AddRange(sensitiveFileVulns);
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, "Error testing file security for endpoint {Endpoint}", endpoint.Path);
                }
            }

            // Test for common sensitive files
            var commonFileVulns = await TestCommonSensitiveFilesAsync(profile.BaseUrl);
            vulnerabilities.AddRange(commonFileVulns);

            _logger.Information("✅ File security scanning completed. Found {Count} file vulnerabilities", vulnerabilities.Count);
            return vulnerabilities;
        }

        /// <summary>
        /// Gets appropriate parameter name for file-related endpoints
        /// </summary>
        private string GetParameterNameForFileEndpoint(string path)
        {
            return path.ToLower() switch
            {
                var p when p.Contains("download") => "filename",
                var p when p.Contains("list") => "path",
                var p when p.Contains("file") => "file",
                var p when p.Contains("path") => "path",
                var p when p.Contains("directory") => "directory",
                var p when p.Contains("dir") => "dir",
                _ => "file"
            };
        }

        /// <summary>
        /// Tests for path traversal vulnerabilities
        /// </summary>
        private async Task<List<Vulnerability>> TestPathTraversalAsync(EndpointInfo endpoint, string baseUrl)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            foreach (var payload in _pathTraversalPayloads)
            {
                try
                {
                    string testUrl;
                    
                    // Handle parameterized endpoints
                    if (endpoint.IsParameterized && !string.IsNullOrEmpty(endpoint.ParameterName))
                    {
                        testUrl = endpoint.Path.Replace($"{{{endpoint.ParameterName}}}", payload);
                    }
                    else
                    {
                        // Enhanced parameter name detection based on endpoint
                        var paramName = GetParameterNameForFileEndpoint(endpoint.Path);
                        testUrl = $"{endpoint.Path}?{paramName}={Uri.EscapeDataString(payload)}";
                    }
                    
                    var fullUrl = $"{baseUrl.TrimEnd('/')}{testUrl}";
                    var response = await _httpClient.GetAsync(fullUrl);
                    
                    if (response.Success)
                    {
                        var content = response.Content;
                        
                        // Check if response contains system file content
                        if (ContainsSystemFileContent(content))
                        {
                            vulnerabilities.Add(CreateFileVulnerability(
                                endpoint,
                                "Path Traversal Vulnerability",
                                SeverityLevel.High,
                                $"Path traversal vulnerability detected. Successfully accessed system file with payload: {payload}",
                                $"Payload: {payload}, Response contains system file content",
                                payload));
                        }
                        
                        // Check for error messages that reveal path information
                        if (ContainsPathInformation(content))
                        {
                            vulnerabilities.Add(CreateFileVulnerability(
                                endpoint,
                                "Path Information Disclosure",
                                SeverityLevel.Medium,
                                $"Path information disclosed in error message for payload: {payload}",
                                $"Payload: {payload}, Error message reveals path information",
                                payload));
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Error testing path traversal payload {Payload} on endpoint {Endpoint}", 
                        payload, endpoint.Path);
                }
            }
            
            return vulnerabilities;
        }

        /// <summary>
        /// Tests for file upload vulnerabilities
        /// </summary>
        private async Task<List<Vulnerability>> TestFileUploadAsync(EndpointInfo endpoint, string baseUrl)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            // Only test endpoints that might handle file uploads
            if (!IsPotentialFileUploadEndpoint(endpoint))
                return vulnerabilities;
            
            foreach (var testFile in _fileUploadTestFiles)
            {
                try
                {
                    var url = $"{baseUrl.TrimEnd('/')}{endpoint.Path}";
                    
                    // Create a test file content
                    var fileContent = CreateTestFileContent(testFile);
                    var fileName = testFile;
                    
                    // Test file upload
                    var response = await TestFileUploadAsync(url, fileName, fileContent, endpoint.Method);
                    
                    if (response.Success)
                    {
                        // Check if the file was uploaded successfully
                        if (IsFileUploadSuccessful(response.Content, fileName))
                        {
                            vulnerabilities.Add(CreateFileVulnerability(
                                endpoint,
                                "File Upload Vulnerability",
                                SeverityLevel.High,
                                $"File upload vulnerability detected. Successfully uploaded file: {fileName}",
                                $"File: {fileName}, Upload successful",
                                fileName));
                        }
                        
                        // Check for lack of file type validation
                        if (IsDangerousFileType(fileName) && (int)response.StatusCode == 200)
                        {
                            vulnerabilities.Add(CreateFileVulnerability(
                                endpoint,
                                "Dangerous File Type Allowed",
                                SeverityLevel.Medium,
                                $"Dangerous file type allowed for upload: {fileName}",
                                $"File: {fileName}, No file type validation detected",
                                fileName));
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Error testing file upload {File} on endpoint {Endpoint}", 
                        testFile, endpoint.Path);
                }
            }
            
            return vulnerabilities;
        }

        /// <summary>
        /// Tests for sensitive file exposure
        /// </summary>
        private async Task<List<Vulnerability>> TestSensitiveFileExposureAsync(EndpointInfo endpoint, string baseUrl)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            foreach (var filePattern in _sensitiveFilePatterns)
            {
                try
                {
                    // Test if the endpoint exposes sensitive files
                    var testUrl = $"{baseUrl.TrimEnd('/')}{endpoint.Path}/{filePattern}";
                    var response = await _httpClient.GetAsync(testUrl);
                    
                    if (response.Success && ContainsSensitiveContent(response.Content, filePattern))
                    {
                        vulnerabilities.Add(CreateFileVulnerability(
                            endpoint,
                            "Sensitive File Exposed",
                            SeverityLevel.Critical,
                            $"Sensitive file exposed: {filePattern}",
                            $"File: {filePattern}, Contains sensitive content",
                            filePattern));
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Error testing sensitive file {File} on endpoint {Endpoint}", 
                        filePattern, endpoint.Path);
                }
            }
            
            return vulnerabilities;
        }

        /// <summary>
        /// Tests for common sensitive files at the application root
        /// </summary>
        private async Task<List<Vulnerability>> TestCommonSensitiveFilesAsync(string baseUrl)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            foreach (var filePattern in _sensitiveFilePatterns)
            {
                try
                {
                    var testUrl = $"{baseUrl.TrimEnd('/')}/{filePattern}";
                    var response = await _httpClient.GetAsync(testUrl);
                    
                    if (response.Success)
                    {
                        vulnerabilities.Add(CreateFileVulnerability(
                            new EndpointInfo { Path = $"/{filePattern}", Method = "GET" },
                            "Sensitive File Exposed",
                            SeverityLevel.High,
                            $"Sensitive file accessible at application root: {filePattern}",
                            $"File: {filePattern}, Directly accessible",
                            filePattern));
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug(ex, "Error testing common sensitive file {File}", filePattern);
                }
            }
            
            return vulnerabilities;
        }

        /// <summary>
        /// Checks if content contains system file indicators
        /// </summary>
        private bool ContainsSystemFileContent(string content)
        {
            return _systemFileIndicators.Any(indicator => 
                content.Contains(indicator, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Checks if content reveals path information
        /// </summary>
        private bool ContainsPathInformation(string content)
        {
            var pathIndicators = new[]
            {
                "No such file or directory", "File not found", "Path not found",
                "Access denied", "Permission denied", "Invalid path",
                "C:\\", "/etc/", "/var/", "/usr/", "/home/", "/root/"
            };
            
            return pathIndicators.Any(indicator => 
                content.Contains(indicator, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Checks if endpoint might handle file uploads
        /// </summary>
        private bool IsPotentialFileUploadEndpoint(EndpointInfo endpoint)
        {
            var uploadKeywords = new[] { "upload", "file", "image", "media", "attach", "import" };
            return uploadKeywords.Any(keyword => 
                endpoint.Path.Contains(keyword, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Creates test file content based on file type
        /// </summary>
        private string CreateTestFileContent(string fileName)
        {
            var extension = Path.GetExtension(fileName).ToLower();
            
            return extension switch
            {
                ".php" => "<?php echo 'Test PHP file'; ?>",
                ".jsp" => "<%@ page language=\"java\" %>Test JSP file",
                ".asp" => "<% Response.Write(\"Test ASP file\") %>",
                ".aspx" => "<%@ Page Language=\"C#\" %>Test ASPX file",
                ".html" => "<html><body>Test HTML file</body></html>",
                ".js" => "console.log('Test JS file');",
                ".css" => "body { color: red; }",
                ".xml" => "<?xml version=\"1.0\"?><test>Test XML file</test>",
                ".json" => "{\"test\": \"Test JSON file\"}",
                ".txt" => "Test text file content",
                _ => "Test file content"
            };
        }

        /// <summary>
        /// Tests file upload functionality
        /// </summary>
        private async Task<HttpResponse> TestFileUploadAsync(string url, string fileName, string content, string method)
        {
            // This is a simplified test - in a real implementation, you'd need to create proper multipart form data
            var requestBody = new Dictionary<string, string>
            {
                { "filename", fileName },
                { "content", content },
                { "file", content }
            };
            
            var jsonBody = System.Text.Json.JsonSerializer.Serialize(requestBody);
            
            return method.ToUpper() switch
            {
                "POST" => await _httpClient.PostAsync(url, jsonBody),
                "PUT" => await _httpClient.PutAsync(url, jsonBody),
                _ => await _httpClient.PostAsync(url, jsonBody)
            };
        }

        /// <summary>
        /// Checks if file upload was successful
        /// </summary>
        private bool IsFileUploadSuccessful(string responseContent, string fileName)
        {
            var successIndicators = new[]
            {
                "upload successful", "file uploaded", "upload complete",
                "success", "ok", "200", "created"
            };
            
            return successIndicators.Any(indicator => 
                responseContent.Contains(indicator, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Checks if file type is dangerous
        /// </summary>
        private bool IsDangerousFileType(string fileName)
        {
            var dangerousExtensions = new[] { ".exe", ".bat", ".sh", ".php", ".jsp", ".asp", ".aspx", ".py" };
            var extension = Path.GetExtension(fileName).ToLower();
            return dangerousExtensions.Contains(extension);
        }

        /// <summary>
        /// Checks if content contains sensitive information
        /// </summary>
        private bool ContainsSensitiveContent(string content, string fileName)
        {
            var sensitivePatterns = new[]
            {
                @"password\s*=\s*[^\s]+",
                @"secret\s*=\s*[^\s]+",
                @"key\s*=\s*[^\s]+",
                @"token\s*=\s*[^\s]+",
                @"api[_-]?key\s*=\s*[^\s]+",
                @"connection[_-]?string\s*=\s*[^\s]+"
            };
            
            return sensitivePatterns.Any(pattern => 
                Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase));
        }

        /// <summary>
        /// Creates a file-related vulnerability
        /// </summary>
        private Vulnerability CreateFileVulnerability(EndpointInfo endpoint, string title, SeverityLevel severity, 
            string description, string evidence, string payload)
        {
            return new Vulnerability
            {
                Type = VulnerabilityType.PathTraversal,
                Severity = severity,
                Title = $"File Security: {title}",
                Description = description,
                Evidence = evidence,
                Endpoint = endpoint.Path,
                Method = endpoint.Method,
                Payload = payload,
                Remediation = GetFileSecurityRemediation(title),
                Confidence = 0.9
            };
        }

        /// <summary>
        /// Gets remediation advice for file security vulnerabilities
        /// </summary>
        private string GetFileSecurityRemediation(string vulnerabilityType)
        {
            return vulnerabilityType switch
            {
                "Path Traversal Vulnerability" => "🔒 RECOMMENDED FIX: Implement proper input validation and file access controls.\n\n" +
                                                "❌ VULNERABLE CODE:\n" +
                                                "// Direct file path usage\n" +
                                                "string filePath = Request.Query[\"file\"];\n" +
                                                "return File(filePath, \"text/plain\");\n" +
                                                "// Unsafe file access\n" +
                                                "var content = File.ReadAllText(userInput);\n" +
                                                "// No path validation\n" +
                                                "string fullPath = Path.Combine(basePath, userPath);\n\n" +
                                                "✅ SECURE CODE:\n" +
                                                "// Validate and sanitize file paths\n" +
                                                "string fileName = Request.Query[\"file\"];\n" +
                                                "if (!IsValidFileName(fileName)) return BadRequest();\n" +
                                                "string safePath = Path.Combine(basePath, fileName);\n" +
                                                "if (!safePath.StartsWith(basePath)) return BadRequest();\n" +
                                                "return File(safePath, \"text/plain\");\n" +
                                                "// Whitelist-based file access\n" +
                                                "var allowedFiles = new[] { \"file1.txt\", \"file2.pdf\" };\n" +
                                                "if (!allowedFiles.Contains(userInput)) return BadRequest();\n\n" +
                                                "📋 ADDITIONAL MEASURES:\n" +
                                                "• Use whitelist-based file access controls\n" +
                                                "• Validate all file paths against allowed directories\n" +
                                                "• Use Path.GetFileName() to extract only filename\n" +
                                                "• Implement proper error handling without path disclosure\n" +
                                                "• Use chroot or similar sandboxing techniques\n" +
                                                "• Regular security audits of file access patterns\n" +
                                                "• Implement file access logging and monitoring",

                "File Upload Vulnerability" => "🔒 RECOMMENDED FIX: Implement comprehensive file upload security controls.\n\n" +
                                            "❌ VULNERABLE CODE:\n" +
                                            "// No file validation\n" +
                                            "var file = Request.Form.Files[0];\n" +
                                            "file.CopyTo(new FileStream(fileName, FileMode.Create));\n" +
                                            "// Unsafe file storage\n" +
                                            "string uploadPath = Path.Combine(\"uploads\", file.FileName);\n\n" +
                                            "✅ SECURE CODE:\n" +
                                            "// Comprehensive file validation\n" +
                                            "var file = Request.Form.Files[0];\n" +
                                            "if (!IsValidFileType(file)) return BadRequest();\n" +
                                            "if (file.Length > maxFileSize) return BadRequest();\n" +
                                            "string safeFileName = Path.GetRandomFileName() + Path.GetExtension(file.FileName);\n" +
                                            "string uploadPath = Path.Combine(\"uploads\", safeFileName);\n" +
                                            "// Scan for malware\n" +
                                            "if (await ScanForMalwareAsync(file)) return BadRequest();\n\n" +
                                            "📋 ADDITIONAL MEASURES:\n" +
                                            "• Implement file type validation (MIME type + extension)\n" +
                                            "• Set strict file size limits\n" +
                                            "• Use random filenames to prevent conflicts\n" +
                                            "• Scan uploaded files for malware\n" +
                                            "• Store files outside web root when possible\n" +
                                            "• Implement virus scanning\n" +
                                            "• Use Content Security Policy (CSP) headers\n" +
                                            "• Regular security audits of upload functionality",

                "Dangerous File Type Allowed" => "🔒 RECOMMENDED FIX: Restrict file uploads to safe file types only.\n\n" +
                                              "❌ VULNERABLE CODE:\n" +
                                              "// No file type restrictions\n" +
                                              "var allowedTypes = new[] { \"*\" };\n" +
                                              "// Weak validation\n" +
                                              "if (file.FileName.EndsWith(\".exe\")) return BadRequest();\n\n" +
                                              "✅ SECURE CODE:\n" +
                                              "// Strict file type whitelist\n" +
                                              "var allowedTypes = new[] { \".jpg\", \".png\", \".pdf\", \".txt\" };\n" +
                                              "var allowedMimeTypes = new[] { \"image/jpeg\", \"image/png\", \"application/pdf\", \"text/plain\" };\n" +
                                              "if (!allowedTypes.Contains(Path.GetExtension(file.FileName).ToLower())) return BadRequest();\n" +
                                              "if (!allowedMimeTypes.Contains(file.ContentType)) return BadRequest();\n" +
                                              "// Additional content validation\n" +
                                              "if (!ValidateFileContent(file)) return BadRequest();\n\n" +
                                              "📋 ADDITIONAL MEASURES:\n" +
                                              "• Use strict file type whitelists\n" +
                                              "• Validate both file extension and MIME type\n" +
                                              "• Implement file content validation\n" +
                                              "• Scan file headers for correct file type\n" +
                                              "• Use antivirus scanning for uploaded files\n" +
                                              "• Implement file quarantine for suspicious files\n" +
                                              "• Regular review of allowed file types",

                "Sensitive File Exposed" => "🔒 RECOMMENDED FIX: Secure sensitive files and implement proper access controls.\n\n" +
                                          "❌ VULNERABLE CODE:\n" +
                                          "// Exposed configuration files\n" +
                                          "[HttpGet(\"config\")]\n" +
                                          "public IActionResult GetConfig() { return File(\"appsettings.json\"); }\n" +
                                          "// No access controls\n" +
                                          "public IActionResult GetLogs() { return File(\"logs/app.log\"); }\n\n" +
                                          "✅ SECURE CODE:\n" +
                                          "// Proper access controls\n" +
                                          "[Authorize(Roles = \"Admin\")]\n" +
                                          "[HttpGet(\"config\")]\n" +
                                          "public IActionResult GetConfig() { return File(\"appsettings.json\"); }\n" +
                                          "// Remove sensitive files from web root\n" +
                                          "// Move .env, config files outside web directory\n" +
                                          "// Use environment variables for sensitive data\n\n" +
                                          "📋 ADDITIONAL MEASURES:\n" +
                                          "• Remove sensitive files from web root\n" +
                                          "• Use environment variables for configuration\n" +
                                          "• Implement proper access controls\n" +
                                          "• Use secure file permissions (600/700)\n" +
                                          "• Regular security scans for exposed files\n" +
                                          "• Implement file access logging\n" +
                                          "• Use secrets management systems\n" +
                                          "• Regular cleanup of temporary files",

                "Path Information Disclosure" => "🔒 RECOMMENDED FIX: Implement proper error handling without path disclosure.\n\n" +
                                               "❌ VULNERABLE CODE:\n" +
                                               "// Revealing error messages\n" +
                                               "try { File.ReadAllText(filePath); }\n" +
                                               "catch (Exception ex) { return BadRequest(ex.Message); }\n" +
                                               "// Stack trace exposure\n" +
                                               "catch (Exception ex) { return StatusCode(500, ex.ToString()); }\n\n" +
                                               "✅ SECURE CODE:\n" +
                                               "// Generic error handling\n" +
                                               "try { File.ReadAllText(filePath); }\n" +
                                               "catch (FileNotFoundException) { return NotFound(\"File not found\"); }\n" +
                                               "catch (UnauthorizedAccessException) { return Forbid(); }\n" +
                                               "catch (Exception) { return StatusCode(500, \"Internal server error\"); }\n" +
                                               "// Log detailed errors server-side only\n" +
                                               "_logger.Error(ex, \"File access error for {FilePath}\", filePath);\n\n" +
                                               "📋 ADDITIONAL MEASURES:\n" +
                                               "• Implement generic error messages\n" +
                                               "• Log detailed errors server-side only\n" +
                                               "• Use custom error pages\n" +
                                               "• Disable detailed error pages in production\n" +
                                               "• Implement proper exception handling\n" +
                                               "• Regular security testing of error handling\n" +
                                               "• Monitor for information disclosure attempts",

                _ => "🔒 RECOMMENDED FIX: Implement comprehensive file security controls.\n\n" +
                     "❌ VULNERABLE CODE:\n" +
                     "// Any direct file access without validation\n" +
                     "var content = File.ReadAllText(userInput);\n" +
                     "return File(filePath, \"application/octet-stream\");\n\n" +
                     "✅ SECURE CODE:\n" +
                     "// Always validate file access\n" +
                     "if (!IsValidFileAccess(userInput)) return BadRequest();\n" +
                     "var safePath = GetSafeFilePath(userInput);\n" +
                     "return File(safePath, GetContentType(safePath));\n\n" +
                     "📋 COMPREHENSIVE MEASURES:\n" +
                     "• Implement input validation for all file operations\n" +
                     "• Use whitelist-based file access controls\n" +
                     "• Validate file paths against allowed directories\n" +
                     "• Implement proper error handling\n" +
                     "• Use secure file permissions\n" +
                     "• Regular security audits\n" +
                     "• Monitor file access patterns\n" +
                     "• Implement file access logging"
            };
        }

        /// <summary>
        /// Disposes of resources
        /// </summary>
        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
}
