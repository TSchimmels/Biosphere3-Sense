using Serilog;

namespace AttackAgent.Services
{
    /// <summary>
    /// Manages wordlists for endpoint discovery
    /// </summary>
    public class WordlistManager
    {
        private readonly ILogger _logger;
        private readonly Dictionary<string, List<string>> _wordlists;
        private readonly string _wordlistBasePath;

        public WordlistManager(string wordlistBasePath = "wordlists")
        {
            _logger = Log.ForContext<WordlistManager>();
            _wordlists = new Dictionary<string, List<string>>();
            _wordlistBasePath = wordlistBasePath;
            
            // Ensure wordlist directory exists
            if (!Directory.Exists(_wordlistBasePath))
            {
                Directory.CreateDirectory(_wordlistBasePath);
                _logger.Information("Created wordlist directory: {Path}", _wordlistBasePath);
            }
            
            LoadAllWordlists();
        }

        /// <summary>
        /// Loads all wordlists from the wordlist directory
        /// </summary>
        private void LoadAllWordlists()
        {
            // Load directory wordlists
            LoadWordlist("directories/common.txt", "directories");
            LoadWordlist("directories/big.txt", "directories");
            LoadWordlist("directories/medium.txt", "directories");
            
            // Load file wordlists
            LoadWordlist("files/common.txt", "files");
            LoadWordlist("files/extensions.txt", "files");
            
            // Load API wordlists
            LoadWordlist("api/common.txt", "api");
            LoadWordlist("api/routes.txt", "api");
            
            // Load parameter wordlists
            LoadWordlist("parameters/common.txt", "parameters");
            
            // Technology-specific wordlists
            LoadWordlist("technology/aspnet.txt", "aspnet");
            LoadWordlist("technology/nodejs.txt", "nodejs");
            LoadWordlist("technology/python.txt", "python");
            LoadWordlist("technology/php.txt", "php");
            
            _logger.Information("Loaded {Count} wordlist categories with {Total} total entries", 
                _wordlists.Count, GetTotalWordlistCount());
        }

        /// <summary>
        /// Loads a wordlist from a file path
        /// </summary>
        private void LoadWordlist(string relativePath, string category)
        {
            var fullPath = Path.Combine(_wordlistBasePath, relativePath);
            
            try
            {
                if (File.Exists(fullPath))
                {
                    var lines = File.ReadAllLines(fullPath)
                        .Where(l => !string.IsNullOrWhiteSpace(l))
                        .Where(l => !l.TrimStart().StartsWith("#")) // Skip comments
                        .Select(l => l.Trim())
                        .Where(l => l.Length > 0)
                        .Distinct()
                        .ToList();
                    
                    if (!_wordlists.ContainsKey(category))
                    {
                        _wordlists[category] = new List<string>();
                    }
                    
                    _wordlists[category].AddRange(lines);
                    _logger.Debug("Loaded {Count} entries from {Path} (category: {Category})", 
                        lines.Count, relativePath, category);
                }
                else
                {
                    _logger.Debug("Wordlist not found: {Path}, using defaults", fullPath);
                    if (!_wordlists.ContainsKey(category))
                    {
                        _wordlists[category] = GetDefaultWordlist(category);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error loading wordlist: {Path}", fullPath);
                if (!_wordlists.ContainsKey(category))
                {
                    _wordlists[category] = GetDefaultWordlist(category);
                }
            }
        }

        /// <summary>
        /// Gets default wordlist if file doesn't exist
        /// </summary>
        private List<string> GetDefaultWordlist(string category)
        {
            return category switch
            {
                "directories" => new List<string>
                {
                    "/admin", "/api", "/backup", "/config", "/database",
                    "/docs", "/files", "/images", "/js", "/css",
                    "/uploads", "/downloads", "/test", "/dev", "/staging",
                    "/management", "/console", "/control", "/panel",
                    "/administrator", "/wp-admin", "/wp-content", "/wp-includes",
                    "/phpmyadmin", "/mysql", "/sql", "/db", "/database",
                    "/assets", "/static", "/public", "/private", "/secure",
                    "/internal", "/external", "/api/v1", "/api/v2", "/api/v3",
                    "/rest", "/graphql", "/graph", "/rpc", "/soap"
                },
                "files" => new List<string>
                {
                    "robots.txt", "sitemap.xml", ".env", "config.json",
                    "appsettings.json", "web.config", "package.json",
                    ".git/config", ".svn/entries", "composer.json",
                    "package-lock.json", "yarn.lock", "pom.xml",
                    "requirements.txt", "Gemfile", "composer.lock",
                    ".htaccess", ".gitignore", ".dockerignore",
                    "docker-compose.yml", "Dockerfile", ".env.local",
                    "appsettings.Development.json", "appsettings.Production.json"
                },
                "api" => new List<string>
                {
                    "/api/v1", "/api/v2", "/api/v3", "/api/users", "/api/auth",
                    "/api/admin", "/api/health", "/api/status", "/api/info",
                    "/api/config", "/api/test", "/api/debug", "/api/version",
                    "/api/login", "/api/logout", "/api/register", "/api/profile",
                    "/api/account", "/api/settings", "/api/data", "/api/query"
                },
                "parameters" => new List<string>
                {
                    "id", "user", "username", "email", "token",
                    "key", "session", "auth", "admin", "debug",
                    "page", "limit", "offset", "sort", "filter",
                    "search", "q", "query", "action", "method"
                },
                "aspnet" => new List<string>
                {
                    "/api/values", "/api/weatherforecast", "/swagger",
                    "/health", "/health/ready", "/health/live",
                    "/.well-known/openid-configuration", "/connect/token",
                    "/Account/Login", "/Account/Register", "/Account/Logout"
                },
                "nodejs" => new List<string>
                {
                    "/api/users", "/api/auth", "/api/products",
                    "/graphql", "/graphiql", "/api-docs",
                    "/healthcheck", "/status", "/metrics"
                },
                "python" => new List<string>
                {
                    "/api/v1", "/admin", "/api/docs",
                    "/redoc", "/openapi.json", "/health"
                },
                "php" => new List<string>
                {
                    "/wp-admin", "/wp-content", "/wp-includes",
                    "/phpmyadmin", "/admin", "/administrator",
                    "/config.php", "/wp-config.php"
                },
                _ => new List<string>()
            };
        }

        /// <summary>
        /// Gets directory wordlist, optionally filtered by technology
        /// </summary>
        public List<string> GetDirectoryWordlist(string? technology = null)
        {
            var wordlist = _wordlists.GetValueOrDefault("directories", new List<string>());
            
            if (!string.IsNullOrEmpty(technology))
            {
                var techWordlist = _wordlists.GetValueOrDefault(technology.ToLower(), new List<string>());
                wordlist = wordlist.Concat(techWordlist).Distinct().ToList();
            }
            
            return wordlist;
        }

        /// <summary>
        /// Gets file wordlist
        /// </summary>
        public List<string> GetFileWordlist()
        {
            return _wordlists.GetValueOrDefault("files", new List<string>());
        }

        /// <summary>
        /// Gets API wordlist
        /// </summary>
        public List<string> GetApiWordlist()
        {
            return _wordlists.GetValueOrDefault("api", new List<string>());
        }

        /// <summary>
        /// Gets parameter wordlist
        /// </summary>
        public List<string> GetParameterWordlist()
        {
            return _wordlists.GetValueOrDefault("parameters", new List<string>());
        }

        /// <summary>
        /// Gets total wordlist count across all categories
        /// </summary>
        public int GetTotalWordlistCount()
        {
            return _wordlists.Values.Sum(w => w.Count);
        }
    }
}

