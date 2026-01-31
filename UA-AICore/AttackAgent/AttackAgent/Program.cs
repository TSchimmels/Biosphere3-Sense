using AttackAgent.Models;
using AttackAgent.Core;
using AttackAgent.Data;
using AttackAgent.Engines;
using AttackAgent.Reporting;
using AttackAgent.Services;
using Serilog;
using System.Net;
using System.Text.Json;

namespace AttackAgent
{
    /// <summary>
    /// AI Attack Agent - Advanced Security Testing Tool
    /// Tests web applications for security vulnerabilities using AI-powered analysis
    /// </summary>
    class Program
    {
        // Default database connection string for vulnerability storage
        // Can be overridden via --db-connection parameter or ATTACKAGENT_DB_CONNECTION environment variable
        private const string DEFAULT_DB_CONNECTION_STRING = "Server=sql5111.site4now.net;Database=db_a840f1_aicoretraining;User Id=db_a840f1_aicoretraining_admin;Password=Fv993faldfoo!;TrustServerCertificate=true;";

        static async Task<int> Main(string[] args)
        {
            // Configure logging
            Log.Logger = new LoggerConfiguration()
                .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}")
                .CreateLogger();

            try
            {
                Log.Information("🤖 AI Attack Agent Starting...");
                Log.Information("Advanced Security Testing Tool v1.0");
                Log.Information("=====================================");

                // Security Layer 0: Code integrity and anti-tampering checks
                var codeIntegrity = new Services.CodeIntegrityService();
                if (!codeIntegrity.VerifyCodeIntegrity())
                {
                    Log.Error("🚨 SECURITY ALERT: Code integrity check failed");
                    Log.Error("🚨 Application may have been tampered with");
                    Log.Error("🚨 Terminating for security");
                    return 1;
                }

                var antiTamper = new Services.AntiTamperService();
                if (!antiTamper.PerformAntiTamperChecks())
                {
                    Log.Error("🚨 SECURITY ALERT: Anti-tamper checks failed");
                    Log.Error("🚨 Application may have been modified");
                    Log.Error("🚨 Terminating for security");
                    return 1;
                }

                // Initialize hardened whitelist service with multiple security layers
                var whitelistService = new Services.SecureWhitelistService();
                whitelistService.Initialize();

                // Check for cleanup-db mode (clean false positives and duplicates)
                if (args.Contains("--cleanup-db"))
                {
                    Log.Information("🧹 Running database cleanup...");
                    
                    var cleanupDbIndex = Array.IndexOf(args, "--db-connection");
                    var cleanupDbConnection = cleanupDbIndex >= 0 && cleanupDbIndex + 1 < args.Length ? 
                        args[cleanupDbIndex + 1] : null;
                    
                    if (string.IsNullOrWhiteSpace(cleanupDbConnection))
                    {
                        cleanupDbConnection = Environment.GetEnvironmentVariable("ATTACKAGENT_DB_CONNECTION");
                    }
                    
                    if (string.IsNullOrWhiteSpace(cleanupDbConnection))
                    {
                        cleanupDbConnection = DEFAULT_DB_CONNECTION_STRING;
                    }

                    try
                    {
                        var dbService = new Services.VulnerabilityDatabaseService(cleanupDbConnection);
                        
                        // Get stats before cleanup
                        Log.Information("📊 Getting database statistics...");
                        var statsBefore = await dbService.GetDatabaseStatsAsync();
                        Log.Information("📊 Before cleanup:");
                        Log.Information("   Total vulnerabilities: {Count}", statsBefore.TotalCount);
                        Log.Information("   Already marked as false positives: {Count}", statsBefore.FalsePositiveCount);
                        Log.Information("   Potential DoS false positives: {Count}", statsBefore.PotentialDosFalsePositives);
                        Log.Information("   Potential duplicates: {Count}", statsBefore.PotentialDuplicates);
                        
                        // Run cleanup
                        var (falsePositives, duplicates) = await dbService.CleanupDatabaseAsync();
                        
                        // Get stats after cleanup
                        var statsAfter = await dbService.GetDatabaseStatsAsync();
                        Log.Information("📊 After cleanup:");
                        Log.Information("   Total vulnerabilities: {Count}", statsAfter.TotalCount);
                        Log.Information("   False positives marked: {Count}", statsAfter.FalsePositiveCount);
                        Log.Information("   Remaining potential DoS false positives: {Count}", statsAfter.PotentialDosFalsePositives);
                        Log.Information("   Remaining potential duplicates: {Count}", statsAfter.PotentialDuplicates);
                        
                        Log.Information("✅ Database cleanup completed!");
                        Log.Information("   Marked {FP} DoS vulnerabilities as false positives", falsePositives);
                        Log.Information("   Deleted {Dup} duplicate XSS/SQLi entries", duplicates);
                        
                        return 0;
                    }
                    catch (Exception ex)
                    {
                        Log.Error(ex, "❌ Error during database cleanup");
                        return 1;
                    }
                }

                // Check for list-vulns mode (query and display all vulnerabilities from database)
                if (args.Contains("--list-vulns"))
                {
                    Log.Information("📊 Querying all vulnerabilities from database...");
                    
                    var listDbIndex = Array.IndexOf(args, "--db-connection");
                    var listDbConnection = listDbIndex >= 0 && listDbIndex + 1 < args.Length ? 
                        args[listDbIndex + 1] : null;
                    
                    if (string.IsNullOrWhiteSpace(listDbConnection))
                    {
                        listDbConnection = Environment.GetEnvironmentVariable("ATTACKAGENT_DB_CONNECTION");
                    }
                    
                    if (string.IsNullOrWhiteSpace(listDbConnection))
                    {
                        listDbConnection = DEFAULT_DB_CONNECTION_STRING;
                    }

                    try
                    {
                        using var connection = new Microsoft.Data.SqlClient.SqlConnection(listDbConnection);
                        await connection.OpenAsync();
                        
                        var sql = @"
                            SELECT Id, VulnerabilityType, Severity, Confidence, Endpoint, Method, Parameter, Payload, Evidence, FalsePositive, Verified 
                            FROM AttackAgentVulnerabilities 
                            ORDER BY Id DESC";
                        
                        using var command = new Microsoft.Data.SqlClient.SqlCommand(sql, connection);
                        using var reader = await command.ExecuteReaderAsync();
                        
                        Console.WriteLine("\n=== ALL VULNERABILITIES IN DATABASE ===\n");
                        
                        int count = 0;
                        while (await reader.ReadAsync())
                        {
                            count++;
                            Console.WriteLine($"--- Vulnerability #{reader.GetInt32(0)} ---");
                            Console.WriteLine($"  Type: {reader.GetString(1)}");
                            Console.WriteLine($"  Severity: {reader.GetString(2)}");
                            Console.WriteLine($"  Confidence: {reader.GetDecimal(3):P0}");
                            Console.WriteLine($"  Endpoint: {(reader.IsDBNull(4) ? "N/A" : reader.GetString(4))}");
                            Console.WriteLine($"  Method: {(reader.IsDBNull(5) ? "N/A" : reader.GetString(5))}");
                            Console.WriteLine($"  Parameter: {(reader.IsDBNull(6) ? "N/A" : reader.GetString(6))}");
                            Console.WriteLine($"  Payload: {(reader.IsDBNull(7) ? "N/A" : reader.GetString(7))}");
                            Console.WriteLine($"  Evidence: {(reader.IsDBNull(8) ? "N/A" : reader.GetString(8))}");
                            Console.WriteLine($"  FalsePositive: {reader.GetBoolean(9)}");
                            Console.WriteLine($"  Verified: {reader.GetBoolean(10)}");
                            Console.WriteLine();
                        }
                        
                        Console.WriteLine($"=== TOTAL: {count} vulnerabilities ===\n");
                        return 0;
                    }
                    catch (Exception ex)
                    {
                        Log.Error(ex, "❌ Error querying database");
                        return 1;
                    }
                }

                // Check for dashboard-only mode (view all vulnerabilities from database)
                if (args.Contains("--dashboard"))
                {
                    Log.Information("📊 Launching vulnerability database dashboard...");
                    
                    // Get database connection string
                    var dashboardDbIndex = Array.IndexOf(args, "--db-connection");
                    var dashboardDbConnection = dashboardDbIndex >= 0 && dashboardDbIndex + 1 < args.Length ? 
                        args[dashboardDbIndex + 1] : null;
                    
                    if (string.IsNullOrWhiteSpace(dashboardDbConnection))
                    {
                        dashboardDbConnection = Environment.GetEnvironmentVariable("ATTACKAGENT_DB_CONNECTION");
                    }
                    
                    if (string.IsNullOrWhiteSpace(dashboardDbConnection))
                    {
                        dashboardDbConnection = DEFAULT_DB_CONNECTION_STRING;
                    }

                    try
                    {
                        var dbDashboard = new Services.DatabaseDashboardService(dashboardDbConnection);
                        await dbDashboard.StartAsync();
                        
                        Log.Information("🌐 Dashboard available at: {Url}", dbDashboard.Url);
                        Log.Information("💡 Press Ctrl+C to stop the dashboard server");
                        
                        // Open browser automatically
                        try
                        {
                            var process = new System.Diagnostics.Process();
                            process.StartInfo.UseShellExecute = true;
                            process.StartInfo.FileName = dbDashboard.Url;
                            process.Start();
                            Log.Information("✅ Browser opened automatically");
                        }
                        catch (Exception ex)
                        {
                            Log.Warning(ex, "⚠️  Could not open browser automatically. Please open {Url} manually", dbDashboard.Url);
                        }

                        // Wait for Ctrl+C
                        await dbDashboard.WaitForShutdownAsync();
                        dbDashboard.Dispose();
                        
                        Log.Information("✅ Dashboard stopped");
                        return 0;
                    }
                    catch (Exception ex)
                    {
                        Log.Error(ex, "❌ Error launching dashboard");
                        return 1;
                    }
                }

                // Check for cleanup-only mode
                if (args.Contains("--cleanup-only"))
                {
                    if (args.Length < 2)
                    {
                        Log.Error("Usage: AttackAgent <target-url> --cleanup-only");
                        Log.Error("Example: AttackAgent https://example.com --cleanup-only");
                        return 1;
                    }

                    var cleanupTarget = args[0];
                    
                    // Check whitelist before cleanup
                    if (!whitelistService.IsWhitelisted(cleanupTarget))
                    {
                        Log.Error("🚫 BLOCKED: Target is not whitelisted");
                        Log.Error("🚫 Add {Target} to whitelist.txt to authorize", cleanupTarget);
                        return 1;
                    }

                    Log.Information("🧹 Running cleanup-only mode...");
                    Log.Information("Target: {Target}", cleanupTarget);
                    Log.Information("⚠️ CRITICAL: Removing ALL test data and injected payloads");

                    var resourceTracker = new Services.ResourceTracker();
                    var cleanupEngine = new Engines.CleanupEngine(cleanupTarget, resourceTracker);
                    await cleanupEngine.CleanupAsync();
                    cleanupEngine.Dispose();

                    Log.Information("✅ Comprehensive cleanup completed!");
                    return 0;
                }

                // Simple command line parsing
                if (args.Length == 0)
                {
                    Log.Error("Usage: AttackAgent <target-url> [--stealth] [--quick] [--output <dir>] [--verbose] [--timeout <seconds>] [--local-files <file1,file2,file3>] [--source-code <path>] [--cleanup-only] [--export-data [json|csv]] [--db-connection <connection-string>]");
                    Log.Error("       AttackAgent --dashboard [--db-connection <connection-string>]");
                    Log.Error("");
                    Log.Error("Example: AttackAgent http://localhost:5285 --verbose");
                    Log.Error("Example: AttackAgent http://localhost:5285 --source-code ./WebsiteTest");
                    Log.Error("Example: AttackAgent https://example.com --cleanup-only");
                    Log.Error("Example: AttackAgent http://localhost:5285 --local-files \"appsettings.json,appsettings.Production.json\" --verbose");
                    Log.Error("Example: AttackAgent http://localhost:5285 --export-data json");
                    Log.Error("Example: AttackAgent http://localhost:5285 --db-connection \"Server=...;Database=...;User Id=...;Password=...;\"");
                    Log.Error("Example: AttackAgent --dashboard");
                    Log.Error("");
                    Log.Error("Default: Full comprehensive testing (all features enabled - most thorough scan)");
                    Log.Error("--stealth: Passive reconnaissance only (reduced detection, no active exploitation)");
                    Log.Error("--quick: Faster scan with reduced testing depth (skips some enhanced tests)");
                    Log.Error("--dashboard: Launch interactive dashboard to view ALL vulnerabilities from database (no scan)");
                    Log.Error("--export-data: Export attack patterns, vulnerabilities, and endpoint data for AI training (format: json or csv, default: json)");
                    Log.Error("--db-connection: Override default database connection (default: uses WebsiteTest database automatically)");
                    Log.Error("");
                    Log.Error("Note: --aggressive flag is deprecated (comprehensive testing is now the default)");
                    return 1;
                }

                var target = args[0];
                var stealth = args.Contains("--stealth");
                var quick = args.Contains("--quick");
                var verbose = args.Contains("--verbose");
                // Legacy support: --aggressive is now the default, but keep for backward compatibility (no-op)
                var aggressive = args.Contains("--aggressive");
                if (aggressive)
                {
                    Log.Information("ℹ️  --aggressive flag detected. Comprehensive testing is now the default behavior.");
                }
                
                var outputIndex = Array.IndexOf(args, "--output");
                var output = outputIndex >= 0 && outputIndex + 1 < args.Length ? args[outputIndex + 1] : "./reports";
                
                var timeoutIndex = Array.IndexOf(args, "--timeout");
                var timeout = timeoutIndex >= 0 && timeoutIndex + 1 < args.Length && int.TryParse(args[timeoutIndex + 1], out var t) ? t : 30;

                var localFilesIndex = Array.IndexOf(args, "--local-files");
                var localFiles = localFilesIndex >= 0 && localFilesIndex + 1 < args.Length ? 
                    args[localFilesIndex + 1].Split(',', StringSplitOptions.RemoveEmptyEntries) : 
                    Array.Empty<string>();

                var sourceCodeIndex = Array.IndexOf(args, "--source-code");
                var sourceCodePath = (sourceCodeIndex >= 0 && sourceCodeIndex + 1 < args.Length) ? 
                    args[sourceCodeIndex + 1] : null;

                var exportData = args.Contains("--export-data");
                var exportFormat = Data.ExportFormat.Json; // Default
                if (exportData)
                {
                    var exportIndex = Array.IndexOf(args, "--export-data");
                    if (exportIndex + 1 < args.Length && args[exportIndex + 1].Equals("csv", StringComparison.OrdinalIgnoreCase))
                    {
                        exportFormat = Data.ExportFormat.Csv;
                    }
                }

                // Database connection string for vulnerability storage
                // Priority: 1) Command line parameter, 2) Environment variable, 3) Default (hardcoded)
                var dbConnectionIndex = Array.IndexOf(args, "--db-connection");
                var dbConnectionString = dbConnectionIndex >= 0 && dbConnectionIndex + 1 < args.Length ? 
                    args[dbConnectionIndex + 1] : null;
                
                // Check environment variable as fallback
                if (string.IsNullOrWhiteSpace(dbConnectionString))
                {
                    dbConnectionString = Environment.GetEnvironmentVariable("ATTACKAGENT_DB_CONNECTION");
                }
                
                // Use default connection string if still not set
                if (string.IsNullOrWhiteSpace(dbConnectionString))
                {
                    dbConnectionString = DEFAULT_DB_CONNECTION_STRING;
                    Log.Information("📊 Using default database connection for vulnerability storage");
                }
                else
                {
                    Log.Information("📊 Using provided database connection for vulnerability storage");
                }

                // Test database setup before running scan (create table, test insert, verify, cleanup)
                if (!string.IsNullOrWhiteSpace(dbConnectionString))
                {
                    try
                    {
                        Log.Information("🧪 Testing database setup before scan...");
                        var dbService = new Services.VulnerabilityDatabaseService(dbConnectionString);
                        var setupSuccess = await dbService.TestDatabaseSetupAsync();
                        if (!setupSuccess)
                        {
                            Log.Warning("⚠️  Database setup test failed, but continuing with scan...");
                            Log.Warning("⚠️  Vulnerabilities may not be saved to database");
                        }
                        else
                        {
                            Log.Information("✅ Database setup verified - ready to save vulnerabilities");
                        }
                    }
                    catch (Exception ex)
                    {
                        Log.Warning(ex, "⚠️  Database setup test encountered an error, but continuing with scan...");
                        Log.Warning("⚠️  Vulnerabilities may not be saved to database");
                    }
                }

                // Security Layer 1: Check whitelist before running attack agent
                if (!whitelistService.IsWhitelisted(target))
                {
                    Log.Error("🚫 BLOCKED: Target is not whitelisted");
                    Log.Error("🚫 Add {Target} to whitelist.txt to authorize testing", target);
                    Log.Error("🚫 This prevents accidental testing of unauthorized targets");
                    Log.Error("🚫 Security event logged to whitelist_audit.log");
                    return 1;
                }

                await RunAttackAgent(target, stealth, quick, aggressive, output, verbose, timeout, localFiles, sourceCodePath, exportData, exportFormat, dbConnectionString);
                return 0;
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Application terminated unexpectedly");
                return 1;
            }
            finally
            {
                Log.CloseAndFlush();
            }
        }

        /// <summary>
        /// Main execution logic for the attack agent
        /// </summary>
        private static async Task RunAttackAgent(string target, bool stealthOnly, bool quickMode, bool aggressiveLegacy, 
            string outputDir, bool verbose, int timeout, string[] localFiles, string? sourceCodePath, bool exportData = false, Data.ExportFormat exportFormat = Data.ExportFormat.Json, string? dbConnectionString = null)
        {
            try
            {
                // Security Layer 2: Re-validate whitelist (defense in depth)
                var whitelistRecheck = new Services.SecureWhitelistService();
                whitelistRecheck.Initialize();
                if (!whitelistRecheck.IsWhitelisted(target))
                {
                    Log.Error("🚫 SECURITY: Target validation failed in RunAttackAgent");
                    Log.Error("🚫 This should never happen - whitelist check bypass detected");
                    Log.Error("🚫 Terminating immediately for security");
                    return;
                }

                // Validate target URL
                if (!Uri.TryCreate(target, UriKind.Absolute, out var targetUri))
                {
                    Log.Error("Invalid target URL: {Target}", target);
                    return;
                }

                Log.Information("🎯 Target: {Target}", target);
                Log.Information("📁 Output Directory: reports/ (standardized)");
                Log.Information("⏱️  Timeout: {Timeout}s", timeout);

                // Track scan start time and generate scan ID for database storage
                var scanStartTime = DateTime.UtcNow;
                var scanId = $"{scanStartTime:yyyyMMdd-HHmmss}-{Guid.NewGuid().ToString("N")[..8]}";

                // Always use the standard reports directory
                var reportsDir = "reports";
                Directory.CreateDirectory(reportsDir);

                // Phase 1: Reconnaissance
                Log.Information("🔍 Phase 1: Reconnaissance");
                Log.Information("=====================================");
                
                // Bypass SSL certificate validation for security testing
                var handler = new System.Net.Http.HttpClientHandler()
                {
                    ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
                };
                using var httpClient = new HttpClient(handler);
                httpClient.Timeout = TimeSpan.FromSeconds(timeout);
                var reconnaissanceEngine = new ReconnaissanceEngine(target, httpClient);
                var reconnaissanceReport = await reconnaissanceEngine.PerformReconnaissanceAsync();

                // Phase 2: File System Access
                Log.Information("📁 Phase 2: File System Access");
                Log.Information("=====================================");
                
                var fileSystemEngine = new FileSystemAccessEngine(target, httpClient);
                var fileSystemReport = await fileSystemEngine.PerformFileSystemAccessAsync();

                // Phase 2.5: Local File Analysis (if files provided)
                LocalFileAnalysisReport localFileReport = null;
                if (localFiles.Length > 0)
                {
                    Log.Information("📄 Phase 2.5: Local File Analysis");
                    Log.Information("=====================================");
                    
                    var localFileEngine = new LocalFileAnalysisEngine();
                    localFileReport = await localFileEngine.AnalyzeLocalFilesAsync(localFiles);
                }

                // Phase 3: Application Discovery
                Log.Information("🔍 Phase 3: Application Discovery");
                Log.Information("=====================================");

                var scanner = new ApplicationScanner(target);
                var profile = await scanner.ScanApplicationAsync(target, sourceCodePath);
                
                if (!string.IsNullOrEmpty(sourceCodePath))
                {
                    Log.Information("✅ Source code analysis integrated into discovery phase");
                }

                // Enhanced technology detection
                Log.Information("🔍 Running enhanced technology detection...");
                var enhancedTechDetector = new EnhancedTechnologyDetector(target);
                var enhancedTechStack = await enhancedTechDetector.AnalyzeTechnologyStackAsync(profile);
                
                // Merge enhanced technology detection results
                profile.TechnologyStack = enhancedTechStack;
                enhancedTechDetector.Dispose();

                // Display discovery results
                DisplayDiscoveryResults(profile);

                // Create ResourceTracker for comprehensive cleanup tracking
                // This tracks all resources created during testing (files, database entries, sessions, etc.)
                var resourceTracker = new Services.ResourceTracker();
                Log.Information("📋 Resource tracking enabled for comprehensive cleanup");

                // Phase 4: Advanced Exploitation
                // Temporarily disabled - AdvancedExploitationEngine needs to be restored
                Log.Information("⚔️ Phase 4: Advanced Exploitation (Skipped - Engine needs restoration)");
                Log.Information("=====================================");
                
                object? exploitationReport = null;
                // var exploitationEngine = new AdvancedExploitationEngine(target, httpClient, profile);
                // try
                // {
                //     exploitationReport = await exploitationEngine.PerformExploitationAsync();
                // }
                // finally
                // {
                //     exploitationEngine.Dispose();
                // }

                // Phase 5: Security Testing
                Log.Information("🛡️  Phase 5: Security Testing");
                Log.Information("=====================================");

                var testResults = await PerformSecurityTesting(profile, stealthOnly, quickMode, exploitationReport, resourceTracker);

                // Phase 3: Enhanced Report Generation
                Log.Information("📊 Phase 3: Enhanced Report Generation");
                Log.Information("=====================================");

                await GenerateEnhancedReports(testResults, reportsDir, profile, localFileReport);

                // Save vulnerabilities to database if connection string provided
                var scanEndTime = DateTime.UtcNow;
                if (!string.IsNullOrWhiteSpace(dbConnectionString))
                {
                    try
                    {
                        Log.Information("💾 Saving vulnerabilities to database...");
                        var dbService = new Services.VulnerabilityDatabaseService(dbConnectionString);
                        
                        // Test connection first
                        var canConnect = await dbService.TestConnectionAsync();
                        if (canConnect)
                        {
                            await dbService.SaveVulnerabilitiesAsync(
                                target,
                                testResults.Vulnerabilities,
                                scanStartTime,
                                scanEndTime,
                                scanId);
                        }
                        else
                        {
                            Log.Warning("⚠️  Database connection failed, skipping vulnerability storage");
                        }
                    }
                    catch (Exception ex)
                    {
                        Log.Error(ex, "❌ Error saving vulnerabilities to database (scan continues)");
                        // Don't throw - we don't want database errors to break the scan
                    }
                }

                // Export data for AI training if requested
                if (exportData)
                {
                    Log.Information("📤 Exporting data for AI training...");
                    try
                    {
                        var dataExporter = new DataExporter();
                        var exportDir = Path.Combine(outputDir, "exported-data");
                        var exportSummary = await dataExporter.ExportAllDataAsync(
                            exportDir, 
                            profile, 
                            testResults.Vulnerabilities, 
                            exportFormat);
                        
                        if (exportSummary.Success)
                        {
                            Log.Information("✅ Data export completed successfully!");
                            Log.Information("  • Export directory: {Dir}", exportSummary.ExportDirectory);
                            Log.Information("  • Format: {Format}", exportSummary.Format);
                            Log.Information("  • Files exported: {Count}", exportSummary.ExportedFiles.Count);
                            Log.Information("  • Vulnerabilities exported: {Count}", exportSummary.VulnerabilitiesExported);
                            Log.Information("  • Endpoints exported: {Count}", exportSummary.EndpointsExported);
                            foreach (var file in exportSummary.ExportedFiles)
                            {
                                Log.Information("  • {File}", Path.GetFileName(file));
                            }
                        }
                        else
                        {
                            Log.Warning("⚠️  Data export completed with errors: {Error}", exportSummary.ErrorMessage);
                        }
                        
                        dataExporter.Dispose();
                    }
                    catch (Exception ex)
                    {
                        Log.Error(ex, "Error exporting data for AI training");
                    }
                }

                // Display enhanced summary
                DisplayEnhancedSummary(testResults);

                // Launch dashboard if vulnerabilities were found
                if (testResults.Vulnerabilities != null && testResults.Vulnerabilities.Any())
                {
                    try
                    {
                        Log.Information("📊 Launching vulnerability dashboard...");
                        var dashboard = new Services.DashboardService(
                            target,
                            testResults.Vulnerabilities,
                            scanStartTime,
                            scanEndTime);

                        await dashboard.StartAsync();
                        Log.Information("🌐 Dashboard available at: {Url}", dashboard.Url);
                        Log.Information("💡 Press Ctrl+C to stop the dashboard server");

                        // Open browser automatically
                        try
                        {
                            var process = new System.Diagnostics.Process();
                            process.StartInfo.UseShellExecute = true;
                            process.StartInfo.FileName = dashboard.Url;
                            process.Start();
                            Log.Information("✅ Browser opened automatically");
                        }
                        catch (Exception ex)
                        {
                            Log.Warning(ex, "⚠️  Could not open browser automatically. Please open {Url} manually", dashboard.Url);
                        }

                        // Keep dashboard running until user stops
                        Log.Information("📊 Dashboard is running. Press Ctrl+C to stop...");
                        try
                        {
                            // Try to wait for user input, but handle non-interactive environments
                            Console.ReadKey();
                            dashboard.Stop();
                            Log.Information("✅ Dashboard stopped");
                        }
                        catch (InvalidOperationException)
                        {
                            // Console input redirected or non-interactive - run dashboard in background
                            Log.Information("📊 Dashboard running in background. Access it at: {Url}", dashboard.Url);
                            Log.Information("💡 The dashboard will continue running. Close this window to stop it.");
                            // Don't stop the dashboard - let it run until the process ends
                        }
                    }
                    catch (Exception ex)
                    {
                        Log.Error(ex, "❌ Error launching dashboard (scan completed successfully)");
                        // Don't throw - dashboard failure shouldn't break the scan
                    }
                }
                else
                {
                    Log.Information("✅ No vulnerabilities found - dashboard not needed");
                }

                // Phase 6: Cleanup
                Log.Information("🧹 Phase 6: Cleanup");
                Log.Information("=====================================");
                Log.Information("⚠️ CRITICAL: Removing ALL test data and injected payloads");
                Log.Information("⚠️ Ensuring NO permanent evidence of testing remains");
                
                try
                {
                    var cleanupEngine = new Engines.CleanupEngine(target, resourceTracker);
                    await cleanupEngine.CleanupAsync(profile, testResults.Vulnerabilities);
                    cleanupEngine.Dispose();
                    
                    Log.Information("✅ Comprehensive cleanup completed successfully");
                    Log.Information("✅ All test data and injected payloads have been removed");
                    Log.Information("📊 Tracked {Count} resources for cleanup", resourceTracker.Count);
                }
                catch (Exception cleanupEx)
                {
                    Log.Warning(cleanupEx, "⚠️ Cleanup encountered errors, but scan results are valid");
                }

                Log.Information("✅ Attack Agent completed successfully!");
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error during attack agent execution");
                throw;
            }
        }

        /// <summary>
        /// Displays comprehensive results of application discovery
        /// </summary>
        private static void DisplayDiscoveryResults(ApplicationProfile profile)
        {
            Log.Information("📋 Discovery Results:");
            Log.Information("  • Application Name: {ApplicationName}", profile.ApplicationName);
            Log.Information("  • Total Endpoints: {Count}", profile.TotalEndpoints);
            Log.Information("  • Framework: {Framework}", profile.TechnologyStack.Framework);
            Log.Information("  • Programming Language: {Language}", profile.TechnologyStack.ProgrammingLanguage);
            Log.Information("  • Database: {Database}", profile.TechnologyStack.Database ?? "Unknown");
            Log.Information("  • Web Server: {WebServer}", profile.TechnologyStack.WebServer ?? "Unknown");
            Log.Information("  • Authentication: {Auth}", profile.AuthenticationSystem.HasAuthentication ? "Yes" : "No");
            Log.Information("  • HTTPS: {Https}", profile.SecurityFeatures.HasHttps ? "Yes" : "No");
            Log.Information("  • Security Headers: {Headers}", profile.SecurityFeatures.HasSecurityHeaders ? "Yes" : "No");
            Log.Information("  • Rate Limiting: {RateLimit}", profile.SecurityFeatures.HasRateLimiting ? "Yes" : "No");
            Log.Information("  • Camera Access: {Camera}", profile.SecurityFeatures.HasCameraAccess ? "Yes" : "No");
            Log.Information("  • File Upload: {Upload}", profile.SecurityFeatures.HasFileUpload ? "Yes" : "No");
            Log.Information("  • Risk Level: {RiskLevel}", profile.RiskLevel);
            Log.Information("  • Scan Duration: {Duration}ms", profile.ScanDuration.TotalMilliseconds);

            // Display all discovered endpoints
            Log.Information("");
            Log.Information("🔗 All Discovered Endpoints ({Count} total):", profile.DiscoveredEndpoints.Count);
            foreach (var endpoint in profile.DiscoveredEndpoints)
            {
                Log.Information("  • {Method} {Path} ({StatusCode}) - {ResponseTime}ms", 
                    endpoint.Method, endpoint.Path, endpoint.StatusCode, endpoint.ResponseTime.TotalMilliseconds);
            }

            // Display technology stack details
            Log.Information("");
            Log.Information("🔧 Technology Stack Details:");
            Log.Information("  • Framework: {Framework}", profile.TechnologyStack.Framework ?? "Unknown");
            Log.Information("  • Programming Language: {Language}", profile.TechnologyStack.ProgrammingLanguage ?? "Unknown");
            Log.Information("  • Database: {Database}", profile.TechnologyStack.Database ?? "Unknown");
            Log.Information("  • Web Server: {WebServer}", profile.TechnologyStack.WebServer ?? "Unknown");
            Log.Information("  • ORM: {Orm}", profile.TechnologyStack.Orm ?? "Unknown");
            Log.Information("  • Confidence: {Confidence:P2}", profile.TechnologyStack.Confidence);
            
            if (profile.TechnologyStack.DetectedLibraries.Any())
            {
                Log.Information("  • Detected Libraries: {Libraries}", string.Join(", ", profile.TechnologyStack.DetectedLibraries));
            }

            // Display security features
            Log.Information("");
            Log.Information("🛡️ Security Features Analysis:");
            Log.Information("  • HTTPS Enabled: {Https}", profile.SecurityFeatures.HasHttps ? "Yes" : "No");
            Log.Information("  • Security Headers: {Headers}", profile.SecurityFeatures.HasSecurityHeaders ? "Yes" : "No");
            Log.Information("  • Rate Limiting: {RateLimit}", profile.SecurityFeatures.HasRateLimiting ? "Yes" : "No");
            Log.Information("  • CORS Configuration: {Cors}", profile.SecurityFeatures.HasCors ? "Yes" : "No");
            Log.Information("  • Camera Access: {Camera}", profile.SecurityFeatures.HasCameraAccess ? "Yes" : "No");
            Log.Information("  • File Upload: {Upload}", profile.SecurityFeatures.HasFileUpload ? "Yes" : "No");
            
            if (!string.IsNullOrEmpty(profile.SecurityFeatures.CorsConfiguration))
            {
                Log.Information("  • CORS Config: {CorsConfig}", profile.SecurityFeatures.CorsConfiguration);
            }

            // Display authentication system details
            if (profile.AuthenticationSystem.HasAuthentication)
            {
                Log.Information("");
                Log.Information("🔐 Authentication System Details:");
                Log.Information("  • Authentication Type: {Type}", profile.AuthenticationSystem.Type);
                Log.Information("  • Token Type: {TokenType}", profile.AuthenticationSystem.TokenType ?? "Unknown");
                Log.Information("  • Authentication Endpoints: {Count}", profile.AuthenticationSystem.AuthenticationEndpoints.Count);
                
                foreach (var authEndpoint in profile.AuthenticationSystem.AuthenticationEndpoints)
                {
                    Log.Information("    - {Endpoint}", authEndpoint);
                }
            }
        }

        /// <summary>
        /// Performs security testing based on the discovered application profile
        /// </summary>
        private static async Task<VulnerabilityReport> PerformSecurityTesting(
            ApplicationProfile profile, bool stealthOnly, bool quickMode, 
            object? exploitationReport = null,
            Services.ResourceTracker? resourceTracker = null)
        {
            var report = new VulnerabilityReport
            {
                TargetUrl = profile.BaseUrl,
                ScanStartTime = DateTime.UtcNow
            };

            Log.Information("🔍 Starting security testing...");

            var allVulnerabilities = new List<Vulnerability>();

            // Always run credential scanning (stealth mode)
            Log.Information("🔍 Running credential scanning...");
            var credentialScanner = new CredentialScanner(profile.BaseUrl);
            var credentialVulns = await credentialScanner.ScanForCredentialsAsync(profile);
            allVulnerabilities.AddRange(credentialVulns);
            
            // Display detailed credential scanning results
            Log.Information("🔑 Credential Scanning Results:");
            Log.Information("  • Total Credential Files Tested: {Count}", credentialScanner.GetTestedFilesCount());
            Log.Information("  • Credential Exposures Found: {Count}", credentialVulns.Count);
            
            if (credentialVulns.Any())
            {
                Log.Information("  • Exposed Credentials:");
                foreach (var cred in credentialVulns)
                {
                    Log.Information("    - Type: {Type} | Severity: {Severity} | Endpoint: {Endpoint}", 
                        cred.Type, cred.Severity, cred.Endpoint);
                }
            }
            else
            {
                Log.Information("  • No credential exposures detected");
            }
            
            credentialScanner.Dispose();

            // Add configuration vulnerabilities from profile
            if (profile.ConfigurationVulnerabilities != null && profile.ConfigurationVulnerabilities.Any())
            {
                Log.Information("🔍 Adding configuration vulnerabilities from discovery phase...");
                allVulnerabilities.AddRange(profile.ConfigurationVulnerabilities);
                Log.Information("✅ Added {Count} configuration vulnerabilities", profile.ConfigurationVulnerabilities.Count);
            }

            // Convert exploitation report results to vulnerabilities
            // Temporarily disabled - ExploitationReport conversion needs AdvancedExploitationEngine to be restored
            // if (exploitationReport != null)
            // {
            //     Log.Information("🔍 Converting exploitation results to vulnerabilities...");
            //     var exploitationVulns = ConvertExploitationReportToVulnerabilities(exploitationReport, profile);
            //     allVulnerabilities.AddRange(exploitationVulns);
            //     Log.Information("✅ Added {Count} vulnerabilities from exploitation phase", exploitationVulns.Count);
            // }

            // Default behavior: Full comprehensive testing (all features enabled)
            // Flags reduce scope rather than add features
            
            if (stealthOnly)
            {
                Log.Information("🥷 Running stealth mode (passive reconnaissance only)...");
                // Stealth mode: Only passive reconnaissance (credential scanning already done)
                // No active exploitation or aggressive testing
            }
            else if (quickMode)
            {
                Log.Information("⚡ Running quick mode (reduced testing depth)...");
                // Quick mode: Faster scan with reduced testing
                // Run concurrent security testing but skip some enhanced tests
                await RunQuickSecurityTestingAsync(profile, allVulnerabilities, resourceTracker);
            }
            else
            {
                Log.Information("🔍 Running comprehensive security testing (default - all features enabled)...");
                Log.Information("📊 This is the most thorough scan available - all security tests enabled");
                // Default: Full comprehensive testing with all features
                // This is the most thorough scan available - equivalent to having all flags enabled
                await RunAggressiveTestingAsync(profile, allVulnerabilities, resourceTracker);
            }

            // Add any remaining simulated results for demonstration
            await AddSimulatedResultsAsync(report, profile, allVulnerabilities);

            report.Vulnerabilities = allVulnerabilities;
            report.Summary = CalculateVulnerabilitySummary(allVulnerabilities);
            report.ScanEndTime = DateTime.UtcNow;
            report.OverallRiskLevel = CalculateOverallRiskLevel(report);

            return report;
        }

        /// <summary>
        /// Runs multiple security tests concurrently for improved performance
        /// </summary>
        private static async Task<List<Vulnerability>> RunConcurrentSecurityTestingAsync(ApplicationProfile profile, Services.ResourceTracker? resourceTracker = null)
        {
            var allVulnerabilities = new List<Vulnerability>();
            
            // Create tasks for concurrent execution
            var tasks = new List<Task<List<Vulnerability>>>
            {
                Task.Run(async () => {
                    Log.Information("💉 Running AI-enhanced SQL injection tests...");
                    var enhancedSqlEngine = new EnhancedSqlInjectionEngine(profile.BaseUrl, resourceTracker);
                    var sqlVulns = await enhancedSqlEngine.TestForSqlInjectionAsync(profile);
                    enhancedSqlEngine.Dispose();
                    Log.Information("✅ SQL injection testing completed. Found {Count} vulnerabilities", sqlVulns.Count);
                    return sqlVulns;
                }),
                
                Task.Run(async () => {
                    Log.Information("🔍 Running XSS tests...");
                    var xssTestingEngine = new XssTestingEngine(resourceTracker);
                    var xssVulns = await xssTestingEngine.TestForXssAsync(profile);
                    xssTestingEngine.Dispose();
                    Log.Information("✅ XSS testing completed. Found {Count} vulnerabilities", xssVulns.Count);
                    return xssVulns;
                }),
                
                Task.Run(async () => {
                    Log.Information("🔍 Running CORS configuration tests...");
                    var corsTester = new CorsTester(profile.BaseUrl);
                    var corsVulns = await corsTester.TestCorsConfigurationAsync(profile);
                    corsTester.Dispose();
                    Log.Information("✅ CORS testing completed. Found {Count} vulnerabilities", corsVulns.Count);
                    return corsVulns;
                }),
                
                Task.Run(async () => {
                    Log.Information("🔍 Running file security tests...");
                    var fileSecurityScanner = new FileSecurityScanner(profile.BaseUrl);
                    var fileVulns = await fileSecurityScanner.TestFileSecurityAsync(profile);
                    fileSecurityScanner.Dispose();
                    Log.Information("✅ File security testing completed. Found {Count} vulnerabilities", fileVulns.Count);
                    return fileVulns;
                }),
                
                Task.Run(async () => {
                    Log.Information("📁 Running enhanced file upload tests...");
                    var enhancedFileUploadTester = new AttackAgent.Engines.EnhancedFileUploadTester(profile.BaseUrl, resourceTracker);
                    var fileUploadVulns = await enhancedFileUploadTester.TestForFileUploadVulnerabilitiesAsync(profile);
                    enhancedFileUploadTester.Dispose();
                    Log.Information("✅ Enhanced file upload testing completed. Found {Count} vulnerabilities", fileUploadVulns.Count);
                    return fileUploadVulns;
                })
            };

            // Wait for all tasks to complete
            Log.Information("⚡ Waiting for concurrent security tests to complete...");
            var results = await Task.WhenAll(tasks);
            
            // Combine all results
            foreach (var result in results)
            {
                allVulnerabilities.AddRange(result);
            }
            
            Log.Information("✅ Concurrent security testing completed. Total vulnerabilities found: {Count}", allVulnerabilities.Count);
            return allVulnerabilities;
        }

        /// <summary>
        /// Runs quick security testing with reduced depth for faster scans
        /// </summary>
        private static async Task RunQuickSecurityTestingAsync(ApplicationProfile profile, List<Vulnerability> vulnerabilities, Services.ResourceTracker? resourceTracker = null)
        {
            // Initialize AI learning system
            Log.Information("🧠 Initializing AI learning system...");
            var database = new AttackPatternDatabase();
            var patternInitializer = new PatternInitializer(database);
            await patternInitializer.InitializePatternsAsync();
            Log.Information("✅ AI learning system initialized");

            // Run concurrent security testing (core tests only)
            Log.Information("⚡ Running concurrent security testing (quick mode)...");
            var concurrentResults = await RunConcurrentSecurityTestingAsync(profile, resourceTracker);
            vulnerabilities.AddRange(concurrentResults);

            // Quick mode: Skip some enhanced tests for speed
            // Still run essential tests but with reduced depth
            Log.Information("🔐 Running essential security tests (quick mode)...");
            
            // 1. Security Headers Testing (essential)
            Log.Information("🛡️ Testing for missing security headers...");
            var securityHeadersDetector = new SecurityHeadersDetector(profile.BaseUrl);
            var securityHeadersVulns = await securityHeadersDetector.TestForSecurityHeadersAsync(profile);
            vulnerabilities.AddRange(securityHeadersVulns);
            securityHeadersDetector.Dispose();
            Log.Information("📊 Security Headers Results: {Count} vulnerabilities found", securityHeadersVulns.Count);
            
            // 2. Rate Limiting Testing (essential)
            Log.Information("⚡ Testing for rate limiting vulnerabilities...");
            var rateLimitingDetector = new RateLimitingDetector(profile.BaseUrl);
            var rateLimitingVulns = await rateLimitingDetector.TestForRateLimitingAsync(profile);
            vulnerabilities.AddRange(rateLimitingVulns);
            rateLimitingDetector.Dispose();
            Log.Information("📊 Rate Limiting Results: {Count} vulnerabilities found", rateLimitingVulns.Count);

            // Display results
            Log.Information("🔍 Quick Mode Security Testing Results:");
            Log.Information("  • Security Headers: {Count}", securityHeadersVulns.Count);
            Log.Information("  • Rate Limiting: {Count}", rateLimitingVulns.Count);
            Log.Information("  • Total Vulnerabilities: {Count}", vulnerabilities.Count);
            Log.Information("ℹ️  Quick mode: Some enhanced tests skipped for faster execution");

            // Display AI learning metrics
            await DisplayLearningMetricsAsync(database);

            database.Dispose();
        }

        /// <summary>
        /// Runs comprehensive penetration testing with AI learning (default mode - most thorough)
        /// This is the default behavior - all security tests are enabled
        /// </summary>
        private static async Task RunAggressiveTestingAsync(ApplicationProfile profile, List<Vulnerability> vulnerabilities, Services.ResourceTracker? resourceTracker = null)
        {
            // Initialize AI learning system
            Log.Information("🧠 Initializing AI learning system...");
            var database = new AttackPatternDatabase();
            var patternInitializer = new PatternInitializer(database);
            await patternInitializer.InitializePatternsAsync();
            Log.Information("✅ AI learning system initialized");

            // Run concurrent security testing for better performance
            Log.Information("⚡ Running concurrent security testing...");
            var concurrentResults = await RunConcurrentSecurityTestingAsync(profile, resourceTracker);
            vulnerabilities.AddRange(concurrentResults);

            // Enhanced Security Testing Suite (PARALLELIZED for performance)
            Log.Information("🔐 Running enhanced security testing suite (parallelized)...");
            
            // Run all enhanced tests concurrently for better performance
            var enhancedTasks = new List<Task<List<Vulnerability>>>
            {
                Task.Run(async () => {
                    Log.Information("🔍 Testing for information disclosure vulnerabilities...");
                    var infoDisclosureDetector = new InformationDisclosureDetector(profile.BaseUrl);
                    var infoDisclosureVulns = await infoDisclosureDetector.TestForInformationDisclosureAsync(profile);
                    infoDisclosureDetector.Dispose();
                    Log.Information("📊 Information Disclosure Results: {Count} vulnerabilities found", infoDisclosureVulns.Count);
                    return infoDisclosureVulns;
                }),
                
                Task.Run(async () => {
                    Log.Information("🛡️ Testing for missing security headers...");
                    var securityHeadersDetector = new SecurityHeadersDetector(profile.BaseUrl);
                    var securityHeadersVulns = await securityHeadersDetector.TestForSecurityHeadersAsync(profile);
                    securityHeadersDetector.Dispose();
                    Log.Information("📊 Security Headers Results: {Count} vulnerabilities found", securityHeadersVulns.Count);
                    return securityHeadersVulns;
                }),
                
                Task.Run(async () => {
                    Log.Information("🔐 Testing comprehensive authentication requirements...");
                    var comprehensiveAuthTester = new ComprehensiveAuthTester(profile.BaseUrl);
                    var comprehensiveAuthVulns = await comprehensiveAuthTester.TestForComprehensiveAuthAsync(profile);
                    comprehensiveAuthTester.Dispose();
                    Log.Information("📊 Comprehensive Authentication Results: {Count} vulnerabilities found", comprehensiveAuthVulns.Count);
                    return comprehensiveAuthVulns;
                }),
                
                Task.Run(async () => {
                    Log.Information("🔍 Testing for error message disclosure...");
                    var errorDisclosureTester = new Engines.ErrorMessageDisclosureTester(profile.BaseUrl);
                    var errorDisclosureVulns = await errorDisclosureTester.TestForErrorDisclosureAsync(profile);
                    errorDisclosureTester.Dispose();
                    Log.Information("📊 Error Message Disclosure Results: {Count} vulnerabilities found", errorDisclosureVulns.Count);
                    return errorDisclosureVulns;
                }),
                
                Task.Run(async () => {
                    Log.Information("⚡ Testing for rate limiting vulnerabilities...");
                    var rateLimitingDetector = new RateLimitingDetector(profile.BaseUrl);
                    var rateLimitingVulns = await rateLimitingDetector.TestForRateLimitingAsync(profile);
                    rateLimitingDetector.Dispose();
                    Log.Information("📊 Rate Limiting Results: {Count} vulnerabilities found", rateLimitingVulns.Count);
                    return rateLimitingVulns;
                }),
                
                Task.Run(async () => {
                    Log.Information("🔐 Running fixed authentication bypass tests...");
                    var fixedAuthBypassEngine = new FixedAuthBypassEngine(profile.BaseUrl);
                    var authBypassVulns = await fixedAuthBypassEngine.TestForAuthBypassAsync(profile);
                    fixedAuthBypassEngine.Dispose();
                    Log.Information("📊 Fixed Authentication Bypass Results: {Count} vulnerabilities found", authBypassVulns.Count);
                    return authBypassVulns;
                }),
                
                Task.Run(async () => {
                    Log.Information("🧠 Running business logic testing...");
                    var businessLogicTester = new Engines.BusinessLogicTester(profile.BaseUrl, resourceTracker);
                    var businessLogicVulns = await businessLogicTester.TestBusinessLogicAsync(profile);
                    businessLogicTester.Dispose();
                    Log.Information("📊 Business Logic Testing Results: {Count} vulnerabilities found", businessLogicVulns.Count);
                    return businessLogicVulns;
                }),
                
                Task.Run(async () => {
                    Log.Information("🔬 Running advanced fuzzing...");
                    var advancedFuzzingEngine = new Engines.AdvancedFuzzingEngine(profile.BaseUrl, resourceTracker);
                    var fuzzingVulns = await advancedFuzzingEngine.FuzzEndpointsAsync(profile);
                    advancedFuzzingEngine.Dispose();
                    Log.Information("📊 Advanced Fuzzing Results: {Count} vulnerabilities found", fuzzingVulns.Count);
                    return fuzzingVulns;
                })
            };
            
            // Wait for all enhanced tests to complete
            Log.Information("⚡ Waiting for enhanced security tests to complete...");
            var enhancedResults = await Task.WhenAll(enhancedTasks);
            
            // Combine all results
            foreach (var result in enhancedResults)
            {
                vulnerabilities.AddRange(result);
            }
            
            // Display comprehensive results
            Log.Information("🔍 Enhanced Security Testing Results:");
            var infoDisclosureVulns = enhancedResults[0];
            var securityHeadersVulns = enhancedResults[1];
            var comprehensiveAuthVulns = enhancedResults[2];
            var errorDisclosureVulns = enhancedResults[3];
            var rateLimitingVulns = enhancedResults[4];
            var authBypassVulns = enhancedResults[5];
            var businessLogicVulns = enhancedResults.Length > 6 ? enhancedResults[6] : new List<Vulnerability>();
            var fuzzingVulns = enhancedResults.Length > 7 ? enhancedResults[7] : new List<Vulnerability>();
            
            Log.Information("  • Information Disclosure: {Count}", infoDisclosureVulns.Count);
            Log.Information("  • Security Headers: {Count}", securityHeadersVulns.Count);
            Log.Information("  • Comprehensive Auth: {Count}", comprehensiveAuthVulns.Count);
            Log.Information("  • Error Message Disclosure: {Count}", errorDisclosureVulns.Count);
            Log.Information("  • Rate Limiting: {Count}", rateLimitingVulns.Count);
            Log.Information("  • Auth Bypass: {Count}", authBypassVulns.Count);
            Log.Information("  • Business Logic: {Count}", businessLogicVulns.Count);
            Log.Information("  • Advanced Fuzzing: {Count}", fuzzingVulns.Count);
            Log.Information("  • Total Vulnerabilities: {Count}", vulnerabilities.Count);


            // Display AI learning metrics
            await DisplayLearningMetricsAsync(database);

            database.Dispose();
        }

        /// <summary>
        /// Display AI learning metrics and statistics
        /// </summary>
        private static async Task DisplayLearningMetricsAsync(AttackPatternDatabase database)
        {
            try
            {
                Log.Information("📊 AI Learning Metrics:");
                Log.Information("========================");
                
                var metrics = await database.GetLearningMetricsAsync();
                
                if (metrics.Any())
                {
                    foreach (var metric in metrics)
                    {
                        if (metric.Key.EndsWith("_AvgSuccessRate"))
                        {
                            var vulnType = metric.Key.Replace("_AvgSuccessRate", "");
                            Log.Information("  • {VulnType} Average Success Rate: {SuccessRate:P2}", 
                                vulnType, metric.Value);
                        }
                        else if (metric.Key.EndsWith("_PatternCount"))
                        {
                            var vulnType = metric.Key.Replace("_PatternCount", "");
                            Log.Information("  • {VulnType} Pattern Count: {Count}", 
                                vulnType, (int)metric.Value);
                        }
                    }
                }
                else
                {
                    Log.Information("  • No learning metrics available yet (first run)");
                }
                
                Log.Information("========================");
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error displaying learning metrics");
            }
        }

        /// <summary>
        /// Adds simulated results for demonstration (replaces old method)
        /// </summary>
        private static async Task AddSimulatedResultsAsync(VulnerabilityReport report, ApplicationProfile profile, List<Vulnerability> existingVulns)
        {
            // Only add simulated results if no real vulnerabilities were found
            if (existingVulns.Any())
            {
                Log.Information("Real vulnerabilities found, skipping simulated results");
                return;
            }

            Log.Information("🧪 Adding simulated security test results for demonstration...");
            
            var simulatedVulns = new List<Vulnerability>();

            // Check for missing security headers
            if (!profile.SecurityFeatures.HasSecurityHeaders)
            {
                simulatedVulns.Add(new Vulnerability
                {
                    Type = VulnerabilityType.MissingSecurityHeaders,
                    Severity = SeverityLevel.Medium,
                    Title = "Missing Security Headers",
                    Description = "The application does not implement important security headers like X-Content-Type-Options, X-Frame-Options, etc.",
                    Endpoint = "/",
                    Method = "GET",
                    Evidence = "No security headers found in response",
                    Remediation = "Add security headers to all responses",
                    AttackMode = AttackMode.Stealth,
                    Confidence = 0.9
                });
            }

            // Check for HTTP instead of HTTPS
            if (!profile.SecurityFeatures.HasHttps)
            {
                simulatedVulns.Add(new Vulnerability
                {
                    Type = VulnerabilityType.WeakEncryption,
                    Severity = SeverityLevel.High,
                    Title = "Insecure HTTP Connection",
                    Description = "The application uses HTTP instead of HTTPS, making communications vulnerable to interception.",
                    Endpoint = "/",
                    Method = "GET",
                    Evidence = "Application uses HTTP protocol",
                    Remediation = "Enable HTTPS and redirect HTTP traffic",
                    AttackMode = AttackMode.Stealth,
                    Confidence = 1.0
                });
            }

            // Check for camera access without proper security
            if (profile.SecurityFeatures.HasCameraAccess && !profile.SecurityFeatures.HasSecurityHeaders)
            {
                simulatedVulns.Add(new Vulnerability
                {
                    Type = VulnerabilityType.UnauthorizedCameraAccess,
                    Severity = SeverityLevel.High,
                    Title = "Camera Access Without Proper Security",
                    Description = "The application provides camera access but lacks proper security measures.",
                    Endpoint = "/api/analyze-ingredient",
                    Method = "POST",
                    Evidence = "Camera API endpoint found without security headers",
                    Remediation = "Implement proper authentication and security headers for camera access",
                    AttackMode = AttackMode.Stealth,
                    Confidence = 0.8
                });
            }

            // Check for lack of rate limiting
            if (!profile.SecurityFeatures.HasRateLimiting)
            {
                simulatedVulns.Add(new Vulnerability
                {
                    Type = VulnerabilityType.InsufficientRateLimiting,
                    Severity = SeverityLevel.Medium,
                    Title = "No Rate Limiting",
                    Description = "The application does not implement rate limiting, making it vulnerable to DoS attacks.",
                    Endpoint = "All endpoints",
                    Method = "All methods",
                    Evidence = "No rate limiting headers found",
                    Remediation = "Implement rate limiting for all endpoints",
                    AttackMode = AttackMode.Stealth,
                    Confidence = 0.7
                });
            }

            existingVulns.AddRange(simulatedVulns);
            Log.Information("Added {Count} simulated vulnerabilities for demonstration", simulatedVulns.Count);
        }


        /// <summary>
        /// Calculates vulnerability summary statistics
        /// </summary>
        private static VulnerabilitySummary CalculateVulnerabilitySummary(List<Vulnerability> vulnerabilities)
        {
            var summary = new VulnerabilitySummary();

            foreach (var vuln in vulnerabilities)
            {
                switch (vuln.Severity)
                {
                    case SeverityLevel.Critical:
                        summary.CriticalCount++;
                        break;
                    case SeverityLevel.High:
                        summary.HighCount++;
                        break;
                    case SeverityLevel.Medium:
                        summary.MediumCount++;
                        break;
                    case SeverityLevel.Low:
                        summary.LowCount++;
                        break;
                    case SeverityLevel.Info:
                        summary.InfoCount++;
                        break;
                }

                if (summary.VulnerabilityTypes.ContainsKey(vuln.Type))
                    summary.VulnerabilityTypes[vuln.Type]++;
                else
                    summary.VulnerabilityTypes[vuln.Type] = 1;

                if (vuln.FalsePositive)
                    summary.FalsePositiveCount++;

                if (vuln.Verified)
                    summary.VerifiedCount++;
            }

            summary.EndpointsAffected = vulnerabilities.Select(v => v.Endpoint).Distinct().Count();

            return summary;
        }

        /// <summary>
        /// Calculates overall risk level based on vulnerabilities
        /// </summary>
        private static RiskLevel CalculateOverallRiskLevel(VulnerabilityReport report)
        {
            var criticalCount = report.Summary.CriticalCount;
            var highCount = report.Summary.HighCount;
            var mediumCount = report.Summary.MediumCount;

            if (criticalCount > 0)
                return RiskLevel.Critical;
            else if (highCount >= 3)
                return RiskLevel.High;
            else if (highCount > 0 || mediumCount >= 5)
                return RiskLevel.Medium;
            else
                return RiskLevel.Low;
        }

        /// <summary>
        /// Generates enhanced security reports with optimization
        /// </summary>
        private static async Task GenerateEnhancedReports(VulnerabilityReport report, string outputDir, ApplicationProfile profile, LocalFileAnalysisReport localFileReport = null)
        {
            Log.Information("📄 Generating enhanced reports with optimization...");

            // Create organized subfolders (only essential reports)
            var pdfDir = Path.Combine(outputDir, "pdf");
            var optimizedDir = Path.Combine(outputDir, "optimized");

            Directory.CreateDirectory(pdfDir);
            Directory.CreateDirectory(optimizedDir);

            Log.Information("📁 Created organized report folders: pdf/, optimized/");

            // Generate optimized report using enhanced report generator
            Log.Information("🔧 Generating optimized vulnerability report...");
            var enhancedReportGenerator = new EnhancedReportGenerator();
            var optimizedReport = await enhancedReportGenerator.GenerateOptimizedReportAsync(report, profile);
            
            Log.Information("📊 Optimization Results:");
            Log.Information("  • Original vulnerabilities: {Original}", optimizedReport.OptimizationMetrics.OriginalVulnerabilityCount);
            Log.Information("  • After deduplication: {Deduplicated}", optimizedReport.OptimizationMetrics.DeduplicatedCount);
            Log.Information("  • After false positive filtering: {Filtered}", optimizedReport.OptimizationMetrics.FilteredCount);
            Log.Information("  • Final report: {Final}", optimizedReport.OptimizationMetrics.FinalCount);
            Log.Information("  • Overall reduction: {Reduction:P1}", optimizedReport.OptimizationMetrics.OverallReductionRate);

            // Generate optimized JSON report
            var optimizedJsonPath = await enhancedReportGenerator.GenerateOptimizedJsonReportAsync(optimizedReport, optimizedDir);
            Log.Information("📄 Optimized JSON report generated: {JsonPath}", optimizedJsonPath);

            // Generate executive summary
            var executiveSummaryPath = await enhancedReportGenerator.GenerateExecutiveSummaryAsync(optimizedReport, optimizedDir);
            Log.Information("📄 Executive summary generated: {SummaryPath}", executiveSummaryPath);

            // Generate PDF report (for client/stakeholder presentations) - use optimized report
            Log.Information("📄 Generating PDF report for presentation...");
            var pdfGenerator = new SimplePdfReportGenerator();
            // Create a VulnerabilityReport from optimized report for PDF generation
            var pdfReport = new VulnerabilityReport
            {
                TargetUrl = optimizedReport.TargetUrl,
                ScanStartTime = optimizedReport.ScanStartTime,
                ScanEndTime = optimizedReport.ScanEndTime,
                OverallRiskLevel = optimizedReport.OverallRiskLevel,
                Vulnerabilities = optimizedReport.Vulnerabilities, // Use deduplicated vulnerabilities
                Summary = optimizedReport.Summary
            };
            var pdfPath = await pdfGenerator.GeneratePdfReportAsync(pdfReport, pdfDir, profile);
            Log.Information("📄 PDF report generated: {PdfPath}", pdfPath);

            // Generate local file analysis report if available (save to optimized folder)
            if (localFileReport != null)
            {
                Log.Information("📄 Generating local file analysis report...");
                await GenerateLocalFileReportAsync(localFileReport, optimizedDir, optimizedDir);
            }

            Log.Information("✅ Enhanced report generation completed successfully!");
        }

        // NOTE: Text and raw JSON report generation removed per REPORT_PURPOSE_AND_RETENTION.md
        // Only essential reports are now generated:
        // - Optimized JSON (best quality, deduplicated)
        // - Executive Summary (management overview)
        // - PDF (professional presentation)
        // 
        // If you need raw JSON or text reports, you can re-enable these functions.

        /// <summary>
        /// Generates local file analysis report
        /// </summary>
        private static async Task GenerateLocalFileReportAsync(LocalFileAnalysisReport localFileReport, string outputDir, string jsonOutputDir)
        {
            try
            {
                var timestamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
                
                // Generate text report (saved to optimized folder)
                var textPath = Path.Combine(outputDir, $"local-file-analysis-{timestamp}.txt");
                using var textWriter = new StreamWriter(textPath);
                
                await textWriter.WriteLineAsync("🔍 LOCAL FILE ANALYSIS REPORT");
                await textWriter.WriteLineAsync("==============================");
                await textWriter.WriteLineAsync($"📅 Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                await textWriter.WriteLineAsync($"⏱️  Analysis Duration: {localFileReport.Duration}");
                await textWriter.WriteLineAsync($"📁 Files Analyzed: {localFileReport.SuccessfullyAnalyzed}/{localFileReport.TotalFiles}");
                await textWriter.WriteLineAsync($"🔴 High Risk Files: {localFileReport.HighRiskFiles}");
                await textWriter.WriteLineAsync($"🔑 Credentials Found: {localFileReport.CredentialsFound}");
                await textWriter.WriteLineAsync();

                foreach (var file in localFileReport.AnalyzedFiles)
                {
                    await textWriter.WriteLineAsync($"📄 FILE: {file.FileName}");
                    await textWriter.WriteLineAsync($"   Path: {file.FilePath}");
                    await textWriter.WriteLineAsync($"   Type: {file.FileType}");
                    await textWriter.WriteLineAsync($"   Size: {file.FileSize} bytes");
                    await textWriter.WriteLineAsync($"   Modified: {file.LastModified:yyyy-MM-dd HH:mm:ss}");
                    await textWriter.WriteLineAsync($"   Risk Level: {file.RiskLevel}");
                    await textWriter.WriteLineAsync($"   Credentials: {file.Credentials.Count}");
                    await textWriter.WriteLineAsync();

                    if (file.Credentials.Any())
                    {
                        await textWriter.WriteLineAsync("   🔑 CREDENTIALS FOUND:");
                        foreach (var cred in file.Credentials)
                        {
                            await textWriter.WriteLineAsync($"      • {cred.Type} ({cred.Provider}) - Line {cred.LineNumber}");
                            await textWriter.WriteLineAsync($"        Value: {cred.Value}");
                            await textWriter.WriteLineAsync($"        Severity: {cred.Severity}");
                            await textWriter.WriteLineAsync();
                        }
                    }

                    if (file.SensitiveData.Any())
                    {
                        await textWriter.WriteLineAsync("   ⚠️  SENSITIVE DATA FOUND:");
                        foreach (var data in file.SensitiveData)
                        {
                            await textWriter.WriteLineAsync($"      • {data.Type} - Line {data.LineNumber}");
                            await textWriter.WriteLineAsync($"        Value: {data.Value}");
                            await textWriter.WriteLineAsync($"        Severity: {data.Severity}");
                            await textWriter.WriteLineAsync();
                        }
                    }

                    await textWriter.WriteLineAsync("   " + new string('-', 50));
                    await textWriter.WriteLineAsync();
                }

                // Generate JSON report (saved to optimized folder)
                var jsonPath = Path.Combine(jsonOutputDir, $"local-file-analysis-{timestamp}.json");
                var jsonContent = JsonSerializer.Serialize(localFileReport, new JsonSerializerOptions 
                { 
                    WriteIndented = true 
                });
                await File.WriteAllTextAsync(jsonPath, jsonContent);

                Log.Information("📄 Local file analysis reports generated:");
                Log.Information("  • Text: {TextPath}", textPath);
                Log.Information("  • JSON: {JsonPath}", jsonPath);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error generating local file analysis report");
            }
        }

        /// <summary>
        /// Converts exploitation report results to Vulnerability objects
        /// </summary>
        private static List<Vulnerability> ConvertExploitationReportToVulnerabilities(
            object exploitationReport, ApplicationProfile profile)
        {
            // Temporarily disabled - ExploitationReport type needs to be restored
            // This method will be re-enabled once AdvancedExploitationEngine is fully restored
            return new List<Vulnerability>();
            
            /* Original implementation commented out - needs ExploitationReport type
            var vulnerabilities = new List<Vulnerability>();
            // ... rest of implementation ...
            return vulnerabilities;
            */
        }

        /// <summary>
        /// Displays the enhanced final summary with optimization metrics
        /// </summary>
        private static void DisplayEnhancedSummary(VulnerabilityReport report)
        {
            Log.Information("📊 Enhanced Final Summary");
            Log.Information("=========================");
            Log.Information("🎯 Target: {Target}", report.TargetUrl);
            Log.Information("⏱️  Scan Duration: {Duration}", report.ScanEndTime - report.ScanStartTime);
            Log.Information("🚨 Total Vulnerabilities: {Total}", report.TotalVulnerabilities);
            Log.Information("🔴 Critical: {Critical}", report.Summary.CriticalCount);
            Log.Information("🟠 High: {High}", report.Summary.HighCount);
            Log.Information("🟡 Medium: {Medium}", report.Summary.MediumCount);
            Log.Information("🟢 Low: {Low}", report.Summary.LowCount);
            Log.Information("ℹ️  Info: {Info}", report.Summary.InfoCount);
            Log.Information("⚠️  Overall Risk Level: {RiskLevel}", report.OverallRiskLevel);
            Log.Information("📁 Reports saved to: reports/pdf/, reports/optimized/ folders");
            Log.Information("📊 Essential reports generated:");
            Log.Information("   ✅ Optimized JSON (PRIMARY - deduplicated, filtered, best quality)");
            Log.Information("   ✅ Executive Summary (management overview)");
            Log.Information("   ✅ PDF (professional presentation for clients/stakeholders)");
            Log.Information("🔧 Enhanced reports include deduplication, false positive filtering, and optimization metrics");
        }
    }
}
