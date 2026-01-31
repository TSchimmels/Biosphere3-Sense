using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;

namespace AttackAgent.Services
{
    /// <summary>
    /// Service for validating target URLs against a whitelist
    /// Prevents accidental testing of unauthorized targets
    /// </summary>
    public class WhitelistService
    {
        private readonly string _whitelistPath;
        private readonly ILogger _logger;
        private HashSet<string>? _whitelistEntries;
        private bool _isInitialized = false;

        public WhitelistService(string whitelistPath = "whitelist.txt")
        {
            _whitelistPath = whitelistPath;
            _logger = Log.ForContext<WhitelistService>();
        }

        /// <summary>
        /// Initializes the whitelist by reading from the file
        /// </summary>
        public void Initialize()
        {
            if (_isInitialized)
                return;

            _whitelistEntries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            try
            {
                if (!File.Exists(_whitelistPath))
                {
                    _logger.Warning("⚠️  Whitelist file not found: {WhitelistPath}", _whitelistPath);
                    _logger.Warning("⚠️  Creating empty whitelist.txt - NO TARGETS WILL BE ALLOWED");
                    _logger.Warning("⚠️  Add authorized URLs to whitelist.txt to enable testing");
                    
                    // Create empty whitelist file with instructions
                    CreateSampleWhitelistFile();
                    return;
                }

                var lines = File.ReadAllLines(_whitelistPath);
                var validEntries = 0;

                foreach (var line in lines)
                {
                    var trimmedLine = line.Trim();
                    
                    // Skip empty lines and comments
                    if (string.IsNullOrWhiteSpace(trimmedLine) || trimmedLine.StartsWith("#"))
                        continue;

                    // Normalize the URL entry
                    var normalized = NormalizeUrl(trimmedLine);
                    if (normalized != null)
                    {
                        _whitelistEntries.Add(normalized);
                        validEntries++;
                    }
                    else
                    {
                        _logger.Warning("⚠️  Invalid whitelist entry (skipped): {Entry}", trimmedLine);
                    }
                }

                _isInitialized = true;
                _logger.Information("✅ Whitelist loaded: {Count} authorized target(s)", validEntries);
                
                if (validEntries == 0)
                {
                    _logger.Warning("⚠️  Whitelist is empty - NO TARGETS WILL BE ALLOWED");
                    _logger.Warning("⚠️  Add authorized URLs to {WhitelistPath} to enable testing", _whitelistPath);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "❌ Error reading whitelist file: {WhitelistPath}", _whitelistPath);
                _logger.Error("❌ Whitelist check will BLOCK ALL TARGETS for safety");
                _isInitialized = true; // Mark as initialized to prevent retries
            }
        }

        /// <summary>
        /// Checks if a target URL is whitelisted
        /// Supports:
        /// 1. Localhost/local IP addresses (for local testing)
        /// 2. Base domain pattern matching (aicore-app-server.tra220030.projects.jetstream-cloud.org)
        /// 3. Explicit whitelist entries from whitelist.txt
        /// </summary>
        public bool IsWhitelisted(string targetUrl)
        {
            if (string.IsNullOrWhiteSpace(targetUrl))
            {
                _logger.Error("❌ Target URL is empty - BLOCKING");
                return false;
            }

            // Normalize the target URL for comparison
            var normalizedTarget = NormalizeUrl(targetUrl);
            if (normalizedTarget == null)
            {
                _logger.Error("❌ Invalid target URL format - BLOCKING: {Target}", targetUrl);
                return false;
            }

            // Check 1: Is it localhost or local IP address?
            if (IsLocalhostOrLocalIp(targetUrl))
            {
                _logger.Information("✅ Target is localhost/local IP - ALLOWED: {Target}", targetUrl);
                return true;
            }

            // Check 2: Does it match the base domain pattern?
            if (MatchesBaseDomain(targetUrl))
            {
                _logger.Information("✅ Target matches base domain pattern - ALLOWED: {Target}", targetUrl);
                return true;
            }

            // Check 3: Fall back to explicit whitelist entries
            if (!_isInitialized)
            {
                Initialize();
            }

            if (_whitelistEntries == null || _whitelistEntries.Count == 0)
            {
                _logger.Warning("⚠️  Whitelist is empty, but target may still be allowed via localhost/base domain");
            }
            else
            {
            // Check exact match
            if (_whitelistEntries.Contains(normalizedTarget))
            {
                _logger.Information("✅ Target is whitelisted: {Target}", targetUrl);
                return true;
            }

            // Check if target matches any whitelist entry (supports domain matching)
            foreach (var whitelistEntry in _whitelistEntries)
            {
                if (normalizedTarget.StartsWith(whitelistEntry, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.Information("✅ Target matches whitelist entry: {Target} matches {Entry}", targetUrl, whitelistEntry);
                    return true;
                    }
                }
            }

            _logger.Error("❌ Target is NOT whitelisted: {Target}", targetUrl);
            _logger.Error("❌ Target must be: (1) localhost/local IP, (2) base domain pattern, or (3) in whitelist.txt");
            return false;
        }

        /// <summary>
        /// Checks if the target URL is localhost or a local IP address
        /// </summary>
        private bool IsLocalhostOrLocalIp(string targetUrl)
        {
            try
            {
                if (!Uri.TryCreate(targetUrl, UriKind.Absolute, out var uri))
                {
                    if (!Uri.TryCreate($"http://{targetUrl}", UriKind.Absolute, out uri))
                    {
                        return false;
                    }
                }

                var host = uri.Host.ToLowerInvariant();

                // Check for localhost variations
                if (host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]")
                {
                    return true;
                }

                // Check for local IP ranges
                if (IPAddress.TryParse(host, out var ipAddress))
                {
                    // Private IP ranges:
                    // 10.0.0.0/8 (10.0.0.0 - 10.255.255.255)
                    // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
                    // 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)
                    // 127.0.0.0/8 (127.0.0.0 - 127.255.255.255) - loopback
                    // 169.254.0.0/16 (169.254.0.0 - 169.254.255.255) - link-local

                    var bytes = ipAddress.GetAddressBytes();
                    
                    // IPv4 checks
                    if (bytes.Length == 4)
                    {
                        // 127.x.x.x (loopback)
                        if (bytes[0] == 127)
                            return true;
                        
                        // 10.x.x.x (private)
                        if (bytes[0] == 10)
                            return true;
                        
                        // 192.168.x.x (private)
                        if (bytes[0] == 192 && bytes[1] == 168)
                            return true;
                        
                        // 172.16.x.x - 172.31.x.x (private)
                        if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                            return true;
                        
                        // 169.254.x.x (link-local)
                        if (bytes[0] == 169 && bytes[1] == 254)
                            return true;
                    }
                    // IPv6 checks
                    else if (bytes.Length == 16)
                    {
                        // ::1 (loopback) - check if all bytes are 0 except the last one which is 1
                        bool isIPv6Loopback = true;
                        for (int i = 0; i < 15; i++)
                        {
                            if (bytes[i] != 0)
                            {
                                isIPv6Loopback = false;
                                break;
                            }
                        }
                        if (isIPv6Loopback && bytes[15] == 1)
                            return true;
                        
                        // fe80::/10 (link-local)
                        if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80)
                            return true;
                        
                        // fc00::/7 (unique local)
                        if ((bytes[0] & 0xfe) == 0xfc)
                            return true;
                    }
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Checks if the target URL matches the base domain pattern
        /// Base domain: aicore-app-server.tra220030.projects.jetstream-cloud.org
        /// </summary>
        private bool MatchesBaseDomain(string targetUrl)
        {
            try
            {
                if (!Uri.TryCreate(targetUrl, UriKind.Absolute, out var uri))
                {
                    if (!Uri.TryCreate($"https://{targetUrl}", UriKind.Absolute, out uri))
                    {
                        return false;
                    }
                }

                var host = uri.Host.ToLowerInvariant();
                const string baseDomain = "aicore-app-server.tra220030.projects.jetstream-cloud.org";

                // Check if host matches base domain exactly or is a subdomain/path of it
                if (host == baseDomain || host.EndsWith($".{baseDomain}", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Normalizes a URL for comparison (removes trailing slashes, converts to lowercase)
        /// </summary>
        private string? NormalizeUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url))
                return null;

            try
            {
                // Try to parse as URI
                if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
                {
                    // If not a full URL, try adding http://
                    if (!Uri.TryCreate($"http://{url}", UriKind.Absolute, out uri))
                    {
                        return null;
                    }
                }

                // Normalize: scheme + host + port (if not default)
                var normalized = $"{uri.Scheme}://{uri.Host}";
                
                // Add port if it's not the default port
                if (!((uri.Scheme == "http" && uri.Port == 80) || 
                      (uri.Scheme == "https" && uri.Port == 443)))
                {
                    normalized += $":{uri.Port}";
                }

                // Add path (normalize trailing slash)
                var path = uri.AbsolutePath.TrimEnd('/');
                if (!string.IsNullOrEmpty(path))
                {
                    normalized += path;
                }

                return normalized.ToLowerInvariant();
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Creates a sample whitelist file with instructions
        /// </summary>
        private void CreateSampleWhitelistFile()
        {
            try
            {
                var sampleContent = @"# AttackAgent Whitelist
# Add authorized target URLs here, one per line
# Lines starting with # are comments and will be ignored
# Empty lines are ignored
#
# Examples:
# http://localhost:3000
# https://staging.example.com
# http://localhost:5285
# https://aicore-app-server.tra220030.projects.jetstream-cloud.org/david-websitetest/
#
# IMPORTANT: Only add URLs you own or have explicit permission to test
# Unauthorized testing may violate laws and regulations
#
# Format: One URL per line (with or without trailing slash)
# Supports: http://, https://, localhost, IP addresses, domains
";

                File.WriteAllText(_whitelistPath, sampleContent);
                _logger.Information("📝 Created sample whitelist file: {WhitelistPath}", _whitelistPath);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "❌ Failed to create sample whitelist file");
            }
        }

        /// <summary>
        /// Gets all whitelisted entries (for display purposes)
        /// </summary>
        public List<string> GetWhitelistedEntries()
        {
            if (!_isInitialized)
                Initialize();

            return _whitelistEntries?.ToList() ?? new List<string>();
        }
    }
}

