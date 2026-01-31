using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AttackAgent.Services
{
    /// <summary>
    /// Enhanced whitelist service with file integrity verification
    /// Prevents tampering with whitelist.txt file
    /// </summary>
    public class SecureWhitelistService : WhitelistService
    {
        private readonly string _hashFilePath;
        private readonly ILogger _logger;
        private bool _hashVerified = false;

        public SecureWhitelistService(string whitelistPath = "whitelist.txt") 
            : base(whitelistPath)
        {
            _hashFilePath = $"{whitelistPath}.hash";
            _logger = Log.ForContext<SecureWhitelistService>();
        }

        /// <summary>
        /// Initializes whitelist with integrity verification
        /// </summary>
        public new void Initialize()
        {
            // First, verify file integrity
            if (!VerifyFileIntegrity())
            {
                _logger.Error("🚨 SECURITY ALERT: Whitelist file integrity check FAILED");
                _logger.Error("🚨 Whitelist file may have been tampered with");
                _logger.Error("🚨 BLOCKING ALL TARGETS for security");
                _hashVerified = false;
                return;
            }

            _hashVerified = true;
            _logger.Information("✅ Whitelist file integrity verified");

            // Call base initialization
            base.Initialize();

            // After loading, update hash if needed
            UpdateFileHashIfNeeded();
        }

        /// <summary>
        /// Checks if target is whitelisted with additional security checks
        /// </summary>
        public new bool IsWhitelisted(string targetUrl)
        {
            // Security check: Verify file integrity before each check
            if (!_hashVerified)
            {
                _logger.Error("🚨 SECURITY: File integrity not verified - BLOCKING");
                LogSecurityEvent("SECURITY_BLOCK", targetUrl, "File integrity not verified");
                return false;
            }

            // Re-verify integrity periodically (every 10th check)
            if (new Random().Next(0, 10) == 0)
            {
                if (!VerifyFileIntegrity())
                {
                    _logger.Error("🚨 SECURITY: File integrity check failed during runtime - BLOCKING");
                    LogSecurityEvent("SECURITY_BLOCK", targetUrl, "Runtime integrity check failed");
                    _hashVerified = false;
                    return false;
                }
            }

            // Call base implementation
            var result = base.IsWhitelisted(targetUrl);
            
            if (result)
            {
                LogSecurityEvent("WHITELIST_ALLOW", targetUrl, "Authorized");
            }
            else
            {
                LogSecurityEvent("WHITELIST_BLOCK", targetUrl, "Not in whitelist");
            }

            return result;
        }

        /// <summary>
        /// Verifies whitelist file integrity using SHA256 hash
        /// </summary>
        private bool VerifyFileIntegrity()
        {
            try
            {
                var whitelistPath = "whitelist.txt"; // Get from base class if possible

                if (!File.Exists(whitelistPath))
                {
                    // If file doesn't exist, that's OK (will be created)
                    // But we can't verify integrity of non-existent file
                    return true; // Allow creation
                }

                // Calculate current hash
                var currentHash = CalculateFileHash(whitelistPath);
                if (string.IsNullOrEmpty(currentHash))
                {
                    _logger.Error("🚨 SECURITY: Failed to calculate file hash");
                    return false;
                }

                // Check if hash file exists
                if (!File.Exists(_hashFilePath))
                {
                    // First run - create hash file
                    _logger.Information("📝 Creating whitelist integrity hash file");
                    File.WriteAllText(_hashFilePath, currentHash);
                    return true;
                }

                // Read stored hash
                var storedHash = File.ReadAllText(_hashFilePath).Trim();
                
                // Compare hashes
                if (currentHash.Equals(storedHash, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.Debug("✅ Whitelist file integrity verified");
                    return true;
                }
                else
                {
                    _logger.Error("🚨 SECURITY: Whitelist file hash mismatch!");
                    _logger.Error("🚨 Expected: {StoredHash}", storedHash);
                    _logger.Error("🚨 Actual: {CurrentHash}", currentHash);
                    _logger.Error("🚨 File may have been tampered with");
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "🚨 SECURITY: File integrity verification failed");
                return false; // Fail secure
            }
        }

        /// <summary>
        /// Updates hash file if whitelist was modified legitimately
        /// </summary>
        private void UpdateFileHashIfNeeded()
        {
            try
            {
                var whitelistPath = "whitelist.txt";
                if (File.Exists(whitelistPath))
                {
                    var currentHash = CalculateFileHash(whitelistPath);
                    var storedHash = File.Exists(_hashFilePath) 
                        ? File.ReadAllText(_hashFilePath).Trim() 
                        : string.Empty;

                    if (!currentHash.Equals(storedHash, StringComparison.OrdinalIgnoreCase))
                    {
                        // Hash mismatch - update it (assumes legitimate change)
                        File.WriteAllText(_hashFilePath, currentHash);
                        _logger.Information("📝 Updated whitelist integrity hash");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Warning(ex, "⚠️  Could not update hash file");
            }
        }

        /// <summary>
        /// Calculates SHA256 hash of a file
        /// </summary>
        private string CalculateFileHash(string filePath)
        {
            try
            {
                using var sha256 = SHA256.Create();
                using var stream = File.OpenRead(filePath);
                var hash = sha256.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error calculating file hash: {FilePath}", filePath);
                return string.Empty;
            }
        }

        /// <summary>
        /// Logs security events for audit trail
        /// </summary>
        private void LogSecurityEvent(string eventType, string target, string reason)
        {
            try
            {
                var logEntry = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC] {eventType} | Target: {target} | Reason: {reason}";
                var logFile = "whitelist_audit.log";
                File.AppendAllText(logFile, logEntry + Environment.NewLine);
                _logger.Debug("🔒 Security event logged: {EventType}", eventType);
            }
            catch
            {
                // Don't fail if logging fails
            }
        }
    }
}
