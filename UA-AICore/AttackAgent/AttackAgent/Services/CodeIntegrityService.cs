using Serilog;
using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace AttackAgent.Services
{
    /// <summary>
    /// Verifies code integrity to detect tampering
    /// </summary>
    public class CodeIntegrityService
    {
        private readonly ILogger _logger;

        public CodeIntegrityService()
        {
            _logger = Log.ForContext<CodeIntegrityService>();
        }

        /// <summary>
        /// Verifies that critical code hasn't been modified
        /// </summary>
        public bool VerifyCodeIntegrity()
        {
            try
            {
                // Check 1: Verify WhitelistService exists and has correct methods
                var whitelistType = typeof(WhitelistService);
                if (whitelistType == null)
                {
                    _logger.Error("🚨 SECURITY: WhitelistService type not found");
                    return false;
                }

                // Check 2: Verify critical methods exist
                var isWhitelistedMethod = whitelistType.GetMethod("IsWhitelisted", 
                    BindingFlags.Public | BindingFlags.Instance);
                if (isWhitelistedMethod == null)
                {
                    _logger.Error("🚨 SECURITY: IsWhitelisted method not found");
                    return false;
                }

                // Check 3: Verify method signature hasn't been changed
                var parameters = isWhitelistedMethod.GetParameters();
                if (parameters.Length != 1 || parameters[0].ParameterType != typeof(string))
                {
                    _logger.Error("🚨 SECURITY: IsWhitelisted method signature modified");
                    return false;
                }

                // Check 4: Verify return type
                if (isWhitelistedMethod.ReturnType != typeof(bool))
                {
                    _logger.Error("🚨 SECURITY: IsWhitelisted return type modified");
                    return false;
                }

                // Check 5: Verify assembly location (basic check)
                var assembly = Assembly.GetExecutingAssembly();
                var assemblyPath = assembly.Location;
                
                if (string.IsNullOrEmpty(assemblyPath))
                {
                    _logger.Warning("⚠️  Assembly location not available (may be in-memory)");
                    // This is OK for some deployment scenarios
                }
                else if (!File.Exists(assemblyPath))
                {
                    _logger.Error("🚨 SECURITY: Assembly file not found at expected location");
                    return false;
                }

                _logger.Debug("✅ Code integrity check passed");
                return true;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "🚨 SECURITY: Code integrity check failed with exception");
                return false;
            }
        }

        /// <summary>
        /// Calculates SHA256 hash of a file
        /// </summary>
        public string CalculateFileHash(string filePath)
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
    }
}
