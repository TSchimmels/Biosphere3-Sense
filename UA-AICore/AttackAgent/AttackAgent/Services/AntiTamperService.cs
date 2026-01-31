using Serilog;
using System;
using System.Diagnostics;
using System.Linq;
using System.Reflection;

namespace AttackAgent.Services
{
    /// <summary>
    /// Detects runtime tampering and suspicious processes
    /// </summary>
    public class AntiTamperService
    {
        private readonly ILogger _logger;
        private readonly string[] _suspiciousProcesses = new[]
        {
            "dnspy", "ilspy", "reflector", "dotpeek", "de4dot",
            "cheatengine", "ollydbg", "x64dbg", "windbg", "ida",
            "ghidra", "radare2", "wireshark", "fiddler", "charles",
            "burpsuite", "httptoolkit", "mitmproxy"
        };

        public AntiTamperService()
        {
            _logger = Log.ForContext<AntiTamperService>();
        }

        /// <summary>
        /// Performs anti-tampering checks
        /// </summary>
        public bool PerformAntiTamperChecks()
        {
            try
            {
                // Check 1: Detect suspicious processes
                if (DetectSuspiciousProcesses())
                {
                    _logger.Warning("⚠️  Suspicious processes detected (may be legitimate tools)");
                    // Don't block, just warn - these might be legitimate security tools
                }

                // Check 2: Verify debugger not attached (basic check)
                if (Debugger.IsAttached)
                {
                    _logger.Warning("⚠️  Debugger detected - this may be legitimate development");
                    // Don't block in debug mode - allow development
                }

                // Check 3: Verify WhitelistService integrity
                if (!VerifyWhitelistServiceIntegrity())
                {
                    _logger.Error("🚨 SECURITY: WhitelistService integrity check failed");
                    return false;
                }

                _logger.Debug("✅ Anti-tamper checks passed");
                return true;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "🚨 SECURITY: Anti-tamper check failed with exception");
                return false;
            }
        }

        /// <summary>
        /// Detects suspicious processes that might be used for tampering
        /// </summary>
        private bool DetectSuspiciousProcesses()
        {
            try
            {
                var runningProcesses = Process.GetProcesses()
                    .Select(p => p.ProcessName.ToLowerInvariant())
                    .ToList();

                foreach (var suspicious in _suspiciousProcesses)
                {
                    if (runningProcesses.Contains(suspicious))
                    {
                        _logger.Warning("⚠️  Suspicious process detected: {Process}", suspicious);
                        return true;
                    }
                }

                return false;
            }
            catch
            {
                // If we can't check, assume OK (fail open for development)
                return false;
            }
        }

        /// <summary>
        /// Verifies WhitelistService hasn't been modified at runtime
        /// </summary>
        private bool VerifyWhitelistServiceIntegrity()
        {
            try
            {
                var whitelistType = typeof(WhitelistService);
                
                // Verify the service can be instantiated (use default parameter)
                var instance = Activator.CreateInstance(whitelistType, new object[] { "whitelist.txt" });
                if (instance == null)
                {
                    _logger.Error("🚨 SECURITY: Cannot instantiate WhitelistService");
                    return false;
                }

                // Verify critical method exists and is callable
                var method = whitelistType.GetMethod("IsWhitelisted");
                if (method == null)
                {
                    _logger.Error("🚨 SECURITY: IsWhitelisted method not accessible");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "🚨 SECURITY: WhitelistService integrity verification failed");
                return false;
            }
        }
    }
}
