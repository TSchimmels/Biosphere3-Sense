using AttackAgent.Models;
using AttackAgent.Services;
using Serilog;
using System.Text;

namespace AttackAgent.Engines
{
    /// <summary>
    /// Enhanced file upload testing engine for comprehensive file upload vulnerability detection
    /// </summary>
    public class EnhancedFileUploadTester : IDisposable
    {
        private readonly SecurityHttpClient _httpClient;
        private readonly ILogger _logger;
        private readonly ResourceTracker? _resourceTracker;
        private bool _disposed = false;

        public EnhancedFileUploadTester(string baseUrl, ResourceTracker? resourceTracker = null)
        {
            _httpClient = new SecurityHttpClient(baseUrl);
            _logger = Log.ForContext<EnhancedFileUploadTester>();
            _resourceTracker = resourceTracker;
        }

        /// <summary>
        /// Tests all discovered endpoints for file upload vulnerabilities
        /// </summary>
        public async Task<List<Vulnerability>> TestForFileUploadVulnerabilitiesAsync(ApplicationProfile profile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            _logger.Information("🔍 Starting enhanced file upload testing...");
            
            // Find file upload endpoints
            var uploadEndpoints = profile.DiscoveredEndpoints
                .Where(e => e.Path.ToLower().Contains("upload") || 
                           e.Path.ToLower().Contains("file") ||
                           e.Method.ToUpper() == "POST")
                .ToList();

            _logger.Information("🔍 Found {Count} potential file upload endpoints", uploadEndpoints.Count);

            foreach (var endpoint in uploadEndpoints)
            {
                var endpointVulns = await TestEndpointForFileUploadAsync(endpoint, profile.BaseUrl);
                vulnerabilities.AddRange(endpointVulns);
            }

            _logger.Information("✅ Enhanced file upload testing completed. Found {Count} vulnerabilities", vulnerabilities.Count);
            return vulnerabilities;
        }

        /// <summary>
        /// Tests a specific endpoint for file upload vulnerabilities
        /// </summary>
        private async Task<List<Vulnerability>> TestEndpointForFileUploadAsync(EndpointInfo endpoint, string baseUrl)
        {
            var vulnerabilities = new List<Vulnerability>();
            var url = baseUrl.TrimEnd('/') + endpoint.Path;

            // Test 1: Unrestricted file upload
            var unrestrictedVuln = await TestUnrestrictedFileUploadAsync(endpoint, url);
            if (unrestrictedVuln != null)
                vulnerabilities.Add(unrestrictedVuln);

            // Test 2: Malicious file upload
            var maliciousVuln = await TestMaliciousFileUploadAsync(endpoint, url);
            if (maliciousVuln != null)
                vulnerabilities.Add(maliciousVuln);

            // Test 3: File type bypass
            var bypassVuln = await TestFileTypeBypassAsync(endpoint, url);
            if (bypassVuln != null)
                vulnerabilities.Add(bypassVuln);

            // Test 4: Path traversal in filename
            var pathTraversalVuln = await TestPathTraversalInFilenameAsync(endpoint, url);
            if (pathTraversalVuln != null)
                vulnerabilities.Add(pathTraversalVuln);

            // Test 5: Large file upload (DoS)
            var dosVuln = await TestLargeFileUploadAsync(endpoint, url);
            if (dosVuln != null)
                vulnerabilities.Add(dosVuln);

            return vulnerabilities;
        }

        /// <summary>
        /// Tests for unrestricted file upload vulnerabilities
        /// </summary>
        private async Task<Vulnerability?> TestUnrestrictedFileUploadAsync(EndpointInfo endpoint, string url)
        {
            try
            {
                _logger.Debug("🔍 Testing unrestricted file upload on {Endpoint}", endpoint.Path);

                // Test with various dangerous file types
                var dangerousFiles = new[]
                {
                    new { Extension = ".php", Content = "<?php echo 'PHP Execution Test'; ?>", MimeType = "application/x-php" },
                    new { Extension = ".jsp", Content = "<% out.println(\"JSP Execution Test\"); %>", MimeType = "application/x-jsp" },
                    new { Extension = ".asp", Content = "<% Response.Write(\"ASP Execution Test\") %>", MimeType = "application/x-asp" },
                    new { Extension = ".exe", Content = "MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00", MimeType = "application/x-executable" },
                    new { Extension = ".bat", Content = "@echo off\necho Batch Execution Test", MimeType = "application/x-bat" },
                    new { Extension = ".sh", Content = "#!/bin/bash\necho 'Shell Execution Test'", MimeType = "application/x-sh" }
                };

                foreach (var file in dangerousFiles)
                {
                    var filename = $"test{file.Extension}";
                    var response = await UploadTestFileAsync(url, filename, file.Content, file.MimeType);
                    
                    if (response.Success && response.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        // Track uploaded file for cleanup
                        _resourceTracker?.TrackUploadedFile(endpoint.Path, filename, null, endpoint.Path.Replace("/upload", "/delete"));
                        
                        return new Vulnerability
                        {
                            Type = VulnerabilityType.FileUpload,
                            Severity = SeverityLevel.High,
                            Title = $"Unrestricted File Upload in {endpoint.Method} {endpoint.Path}",
                            Description = $"The application allows unrestricted file uploads, including dangerous file types like {file.Extension}. This could allow attackers to upload malicious files and execute arbitrary code.",
                            Endpoint = endpoint.Path,
                            Method = endpoint.Method,
                            Payload = $"Uploaded file: test{file.Extension}",
                            Response = response.Content,
                            Evidence = $"Successfully uploaded {file.Extension} file with content type {file.MimeType}",
                            Remediation = "Implement strict file type validation, use allowlists instead of blocklists, scan uploaded files for malware, store files outside web root, and use random filenames.",
                            AttackMode = AttackMode.Aggressive,
                            Confidence = 0.9,
                            Verified = true
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Debug("Error testing unrestricted file upload: {Error}", ex.Message);
            }

            return null;
        }

        /// <summary>
        /// Tests for malicious file upload vulnerabilities
        /// </summary>
        private async Task<Vulnerability?> TestMaliciousFileUploadAsync(EndpointInfo endpoint, string url)
        {
            try
            {
                _logger.Debug("🔍 Testing malicious file upload on {Endpoint}", endpoint.Path);

                // Test with malicious HTML/JavaScript files
                var maliciousFiles = new[]
                {
                    new { Extension = ".html", Content = "<html><body><script>alert('XSS via File Upload')</script></body></html>", MimeType = "text/html" },
                    new { Extension = ".htm", Content = "<html><body><img src=x onerror=alert('XSS')></body></html>", MimeType = "text/html" },
                    new { Extension = ".js", Content = "alert('JavaScript Execution via File Upload');", MimeType = "application/javascript" },
                    new { Extension = ".svg", Content = "<svg onload=alert('SVG XSS')></svg>", MimeType = "image/svg+xml" }
                };

                foreach (var file in maliciousFiles)
                {
                    var filename = $"malicious{file.Extension}";
                    var response = await UploadTestFileAsync(url, filename, file.Content, file.MimeType);
                    
                    if (response.Success && response.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        // Track uploaded file for cleanup
                        _resourceTracker?.TrackUploadedFile(endpoint.Path, filename, null, endpoint.Path.Replace("/upload", "/delete"));
                        
                        return new Vulnerability
                        {
                            Type = VulnerabilityType.FileUpload,
                            Severity = SeverityLevel.Critical,
                            Title = $"Malicious File Upload in {endpoint.Method} {endpoint.Path}",
                            Description = $"The application allows upload of malicious files like {file.Extension} that could execute scripts or contain XSS payloads. This poses a critical security risk.",
                            Endpoint = endpoint.Path,
                            Method = endpoint.Method,
                            Payload = $"Uploaded malicious file: malicious{file.Extension}",
                            Response = response.Content,
                            Evidence = $"Successfully uploaded malicious {file.Extension} file containing script content",
                            Remediation = "Implement strict content validation, scan file contents for malicious patterns, use Content Security Policy, and store uploaded files with restricted permissions.",
                            AttackMode = AttackMode.Aggressive,
                            Confidence = 0.95,
                            Verified = true
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Debug("Error testing malicious file upload: {Error}", ex.Message);
            }

            return null;
        }

        /// <summary>
        /// Tests for file type bypass vulnerabilities
        /// </summary>
        private async Task<Vulnerability?> TestFileTypeBypassAsync(EndpointInfo endpoint, string url)
        {
            try
            {
                _logger.Debug("🔍 Testing file type bypass on {Endpoint}", endpoint.Path);

                // Test various bypass techniques
                var bypassFiles = new[]
                {
                    new { Filename = "test.php.jpg", Content = "<?php echo 'PHP Execution'; ?>", MimeType = "image/jpeg" },
                    new { Filename = "test.php%00.jpg", Content = "<?php echo 'Null Byte Bypass'; ?>", MimeType = "image/jpeg" },
                    new { Filename = "test.php;.jpg", Content = "<?php echo 'Semicolon Bypass'; ?>", MimeType = "image/jpeg" },
                    new { Filename = "test.php\x00.jpg", Content = "<?php echo 'Null Byte Bypass'; ?>", MimeType = "image/jpeg" },
                    new { Filename = "test.php ", Content = "<?php echo 'Space Bypass'; ?>", MimeType = "image/jpeg" },
                    new { Filename = "test.php.", Content = "<?php echo 'Dot Bypass'; ?>", MimeType = "image/jpeg" }
                };

                foreach (var file in bypassFiles)
                {
                    var response = await UploadTestFileAsync(url, file.Filename, file.Content, file.MimeType);
                    
                    if (response.Success && response.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        // Track uploaded file for cleanup
                        _resourceTracker?.TrackUploadedFile(endpoint.Path, file.Filename, null, endpoint.Path.Replace("/upload", "/delete"));
                        
                        return new Vulnerability
                        {
                            Type = VulnerabilityType.FileUpload,
                            Severity = SeverityLevel.High,
                            Title = $"File Type Bypass in {endpoint.Method} {endpoint.Path}",
                            Description = $"The application's file type validation can be bypassed using techniques like double extensions or null bytes. File '{file.Filename}' was successfully uploaded.",
                            Endpoint = endpoint.Path,
                            Method = endpoint.Method,
                            Payload = $"Uploaded file with bypass: {file.Filename}",
                            Response = response.Content,
                            Evidence = $"Successfully bypassed file type validation with filename: {file.Filename}",
                            Remediation = "Implement server-side file type validation based on file content (magic bytes), not just filename or MIME type. Use strict allowlists and validate file headers.",
                            AttackMode = AttackMode.Aggressive,
                            Confidence = 0.85,
                            Verified = true
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Debug("Error testing file type bypass: {Error}", ex.Message);
            }

            return null;
        }

        /// <summary>
        /// Tests for path traversal in filename vulnerabilities
        /// </summary>
        private async Task<Vulnerability?> TestPathTraversalInFilenameAsync(EndpointInfo endpoint, string url)
        {
            try
            {
                _logger.Debug("🔍 Testing path traversal in filename on {Endpoint}", endpoint.Path);

                // Test path traversal in filenames
                var traversalFiles = new[]
                {
                    new { Filename = "../../../etc/passwd", Content = "test", MimeType = "text/plain" },
                    new { Filename = "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", Content = "test", MimeType = "text/plain" },
                    new { Filename = "....//....//....//etc/passwd", Content = "test", MimeType = "text/plain" },
                    new { Filename = "..%2F..%2F..%2Fetc%2Fpasswd", Content = "test", MimeType = "text/plain" },
                    new { Filename = "..%252F..%252F..%252Fetc%252Fpasswd", Content = "test", MimeType = "text/plain" }
                };

                foreach (var file in traversalFiles)
                {
                    var response = await UploadTestFileAsync(url, file.Filename, file.Content, file.MimeType);
                    
                    if (response.Success && response.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        // Track uploaded file for cleanup
                        _resourceTracker?.TrackUploadedFile(endpoint.Path, file.Filename, null, endpoint.Path.Replace("/upload", "/delete"));
                        
                        return new Vulnerability
                        {
                            Type = VulnerabilityType.PathTraversal,
                            Severity = SeverityLevel.Critical,
                            Title = $"Path Traversal in Filename for {endpoint.Method} {endpoint.Path}",
                            Description = $"The application is vulnerable to path traversal attacks through malicious filenames. Filename '{file.Filename}' could potentially access files outside the intended directory.",
                            Endpoint = endpoint.Path,
                            Method = endpoint.Method,
                            Payload = $"Path traversal filename: {file.Filename}",
                            Response = response.Content,
                            Evidence = $"Path traversal sequence detected in filename: {file.Filename}",
                            Remediation = "Sanitize filenames by removing path traversal sequences, use random filenames, and store files in a restricted directory outside the web root.",
                            AttackMode = AttackMode.Aggressive,
                            Confidence = 0.9,
                            Verified = true
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Debug("Error testing path traversal in filename: {Error}", ex.Message);
            }

            return null;
        }

        /// <summary>
        /// Tests for large file upload DoS vulnerabilities
        /// </summary>
        private async Task<Vulnerability?> TestLargeFileUploadAsync(EndpointInfo endpoint, string url)
        {
            try
            {
                _logger.Debug("🔍 Testing large file upload DoS on {Endpoint}", endpoint.Path);

                // Test with large files (10MB)
                var largeContent = new string('A', 10 * 1024 * 1024); // 10MB of 'A' characters
                var filename = "large_file.txt";
                var response = await UploadTestFileAsync(url, filename, largeContent, "text/plain");
                
                if (response.Success && response.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    // Track uploaded file for cleanup
                    _resourceTracker?.TrackUploadedFile(endpoint.Path, filename, null, endpoint.Path.Replace("/upload", "/delete"));
                    
                    return new Vulnerability
                    {
                        Type = VulnerabilityType.DenialOfService,
                        Severity = SeverityLevel.Medium,
                        Title = $"Large File Upload DoS in {endpoint.Method} {endpoint.Path}",
                        Description = "The application allows upload of very large files without proper size restrictions, which could lead to denial of service attacks by consuming server resources.",
                        Endpoint = endpoint.Path,
                        Method = endpoint.Method,
                        Payload = "Uploaded 10MB file",
                        Response = response.Content,
                        Evidence = "Successfully uploaded 10MB file without size restrictions",
                        Remediation = "Implement file size limits, use streaming uploads for large files, and implement proper resource management.",
                        AttackMode = AttackMode.Aggressive,
                        Confidence = 0.7,
                        Verified = true
                    };
                }
            }
            catch (Exception ex)
            {
                _logger.Debug("Error testing large file upload: {Error}", ex.Message);
            }

            return null;
        }

        /// <summary>
        /// Uploads a test file to the specified URL
        /// </summary>
        private async Task<HttpResponse> UploadTestFileAsync(string url, string filename, string content, string mimeType)
        {
            try
            {
                // Create multipart form data
                var boundary = "----WebKitFormBoundary" + Guid.NewGuid().ToString("N");
                var formData = new StringBuilder();
                
                formData.AppendLine($"--{boundary}");
                formData.AppendLine($"Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"");
                formData.AppendLine($"Content-Type: {mimeType}");
                formData.AppendLine();
                formData.AppendLine(content);
                formData.AppendLine($"--{boundary}--");

                var headers = new Dictionary<string, string>
                {
                    { "Content-Type", $"multipart/form-data; boundary={boundary}" }
                };

                return await _httpClient.PostAsync(url, formData.ToString(), headers);
            }
            catch (Exception ex)
            {
                _logger.Debug("Error uploading test file {Filename}: {Error}", filename, ex.Message);
                return new HttpResponse
                {
                    StatusCode = System.Net.HttpStatusCode.InternalServerError,
                    Content = ex.Message,
                    Success = false
                };
            }
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _httpClient?.Dispose();
                _disposed = true;
            }
        }
    }
}
