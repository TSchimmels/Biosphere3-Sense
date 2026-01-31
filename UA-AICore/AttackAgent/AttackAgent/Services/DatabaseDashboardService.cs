using AttackAgent.Models;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Data.SqlClient;
using Serilog;

namespace AttackAgent.Services
{
    /// <summary>
    /// Service for hosting a web dashboard to display ALL vulnerabilities from the database
    /// Provides sorting, searching, and filtering capabilities
    /// </summary>
    public class DatabaseDashboardService : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly string _connectionString;
        private readonly ILogger _logger;
        private bool _isRunning = false;
        private Task? _serverTask;
        private readonly CancellationTokenSource _cancellationTokenSource = new();

        public int Port { get; private set; }
        public string Url => $"http://localhost:{Port}";

        public DatabaseDashboardService(string connectionString)
        {
            _connectionString = connectionString;
            _logger = Log.ForContext<DatabaseDashboardService>();
            _listener = new HttpListener();
            
            // Find an available port
            Port = FindAvailablePort();
            _listener.Prefixes.Add(Url + "/");
        }

        /// <summary>
        /// Starts the dashboard server
        /// </summary>
        public async Task StartAsync()
        {
            if (_isRunning)
            {
                return;
            }

            try
            {
                _listener.Start();
                _isRunning = true;
                _logger.Information("📊 Database Dashboard server started on {Url}", Url);

                _serverTask = Task.Run(async () => await ListenAsync(_cancellationTokenSource.Token));
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "❌ Failed to start database dashboard server");
                throw;
            }
        }

        /// <summary>
        /// Stops the dashboard server
        /// </summary>
        public void Stop()
        {
            if (!_isRunning)
            {
                return;
            }

            _cancellationTokenSource.Cancel();
            _listener.Stop();
            _isRunning = false;
            _logger.Information("📊 Database Dashboard server stopped");
        }

        /// <summary>
        /// Waits for the server to stop (blocks until Ctrl+C or manual stop)
        /// </summary>
        public async Task WaitForShutdownAsync()
        {
            var tcs = new TaskCompletionSource<bool>();
            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                tcs.SetResult(true);
            };

            await tcs.Task;
            Stop();
        }

        /// <summary>
        /// Main server loop
        /// </summary>
        private async Task ListenAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested && _isRunning)
            {
                try
                {
                    var context = await _listener.GetContextAsync();
                    _ = Task.Run(() => HandleRequestAsync(context, cancellationToken));
                }
                catch (HttpListenerException)
                {
                    // Listener was stopped
                    break;
                }
                catch (Exception ex)
                {
                    if (!cancellationToken.IsCancellationRequested)
                    {
                        _logger.Warning(ex, "Error handling request");
                    }
                }
            }
        }

        /// <summary>
        /// Handles incoming HTTP requests
        /// </summary>
        private async Task HandleRequestAsync(HttpListenerContext context, CancellationToken cancellationToken)
        {
            var request = context.Request;
            var response = context.Response;

            try
            {
                var path = request.Url?.AbsolutePath ?? "/";

                if (path == "/" || path == "/index.html")
                {
                    await ServeDashboardAsync(response);
                }
                else if (path == "/api/vulnerabilities")
                {
                    await ServeVulnerabilitiesApiAsync(response, request);
                }
                else if (path == "/api/stats")
                {
                    await ServeStatsApiAsync(response);
                }
                else
                {
                    response.StatusCode = 404;
                    response.Close();
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error processing request");
                response.StatusCode = 500;
                response.Close();
            }
        }

        /// <summary>
        /// Serves the main dashboard HTML page
        /// </summary>
        private async Task ServeDashboardAsync(HttpListenerResponse response)
        {
            response.ContentType = "text/html; charset=utf-8";
            response.StatusCode = 200;

            var html = GetDashboardHtml();
            var buffer = Encoding.UTF8.GetBytes(html);
            response.ContentLength64 = buffer.Length;
            await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
            response.Close();
        }

        /// <summary>
        /// Serves vulnerabilities from database as JSON API with optional filtering
        /// </summary>
        private async Task ServeVulnerabilitiesApiAsync(HttpListenerResponse response, HttpListenerRequest request)
        {
            try
            {
                response.ContentType = "application/json; charset=utf-8";
                response.StatusCode = 200;
                response.Headers.Add("Access-Control-Allow-Origin", "*");

                var vulnerabilities = await GetVulnerabilitiesFromDatabaseAsync();

                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                };

                var json = JsonSerializer.Serialize(vulnerabilities, options);

                var buffer = Encoding.UTF8.GetBytes(json);
                response.ContentLength64 = buffer.Length;
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                response.Close();
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error fetching vulnerabilities from database");
                response.StatusCode = 500;
                var errorJson = JsonSerializer.Serialize(new { error = ex.Message });
                var buffer = Encoding.UTF8.GetBytes(errorJson);
                response.ContentLength64 = buffer.Length;
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                response.Close();
            }
        }

        /// <summary>
        /// Serves statistics about vulnerabilities in the database
        /// </summary>
        private async Task ServeStatsApiAsync(HttpListenerResponse response)
        {
            try
            {
                response.ContentType = "application/json; charset=utf-8";
                response.StatusCode = 200;
                response.Headers.Add("Access-Control-Allow-Origin", "*");

                var stats = await GetStatsFromDatabaseAsync();

                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                };

                var json = JsonSerializer.Serialize(stats, options);

                var buffer = Encoding.UTF8.GetBytes(json);
                response.ContentLength64 = buffer.Length;
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                response.Close();
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error fetching stats from database");
                response.StatusCode = 500;
                var errorJson = JsonSerializer.Serialize(new { error = ex.Message });
                var buffer = Encoding.UTF8.GetBytes(errorJson);
                response.ContentLength64 = buffer.Length;
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                response.Close();
            }
        }

        /// <summary>
        /// Retrieves all vulnerabilities from the database
        /// </summary>
        private async Task<List<DatabaseVulnerability>> GetVulnerabilitiesFromDatabaseAsync()
        {
            var vulnerabilities = new List<DatabaseVulnerability>();

            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync();

            // Check which columns exist
            var columnsExist = await CheckColumnsExistAsync(connection);

            // Build SQL based on available columns
            var sql = columnsExist 
                ? @"SELECT 
                        Id, VulnerabilityType, Severity, Confidence, 
                        Endpoint, Method, Parameter, Payload, Evidence,
                        FalsePositive, Verified, ScanId, ApplicationScanned, ScanTime
                    FROM AttackAgentVulnerabilities
                    ORDER BY Id DESC"
                : @"SELECT 
                        Id, VulnerabilityType, Severity, Confidence, 
                        Endpoint, Method, Parameter, Payload, Evidence,
                        FalsePositive, Verified
                    FROM AttackAgentVulnerabilities
                    ORDER BY Id DESC";

            using var command = new SqlCommand(sql, connection);
            using var reader = await command.ExecuteReaderAsync();

            while (await reader.ReadAsync())
            {
                var vuln = new DatabaseVulnerability
                {
                    Id = reader.GetInt32(0),
                    VulnerabilityType = reader.GetString(1),
                    Severity = reader.GetString(2),
                    Confidence = (double)reader.GetDecimal(3),
                    Endpoint = reader.IsDBNull(4) ? null : reader.GetString(4),
                    Method = reader.IsDBNull(5) ? null : reader.GetString(5),
                    Parameter = reader.IsDBNull(6) ? null : reader.GetString(6),
                    Payload = reader.IsDBNull(7) ? null : reader.GetString(7),
                    Evidence = reader.IsDBNull(8) ? null : reader.GetString(8),
                    FalsePositive = reader.GetBoolean(9),
                    Verified = reader.GetBoolean(10)
                };

                // Only read new columns if they exist
                if (columnsExist)
                {
                    vuln.ScanId = reader.IsDBNull(11) ? null : reader.GetString(11);
                    vuln.ApplicationScanned = reader.IsDBNull(12) ? null : reader.GetString(12);
                    vuln.ScanTime = reader.IsDBNull(13) ? null : reader.GetDateTime(13);
                }

                vulnerabilities.Add(vuln);
            }

            return vulnerabilities;
        }

        /// <summary>
        /// Checks if the new columns exist in the database
        /// </summary>
        private async Task<bool> CheckColumnsExistAsync(SqlConnection connection)
        {
            try
            {
                var sql = @"SELECT COUNT(*) FROM sys.columns 
                           WHERE object_id = OBJECT_ID(N'[dbo].[AttackAgentVulnerabilities]') 
                           AND name = 'ScanId'";
                using var cmd = new SqlCommand(sql, connection);
                var result = await cmd.ExecuteScalarAsync();
                return result != null && (int)result > 0;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Gets statistics about vulnerabilities in the database
        /// </summary>
        private async Task<DatabaseStats> GetStatsFromDatabaseAsync()
        {
            var stats = new DatabaseStats();

            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync();

            // Get total count
            using (var cmd = new SqlCommand("SELECT COUNT(*) FROM AttackAgentVulnerabilities", connection))
            {
                stats.TotalCount = (int)await cmd.ExecuteScalarAsync();
            }

            // Get counts by severity
            var severitySql = @"
                SELECT Severity, COUNT(*) as Count 
                FROM AttackAgentVulnerabilities 
                GROUP BY Severity";
            using (var cmd = new SqlCommand(severitySql, connection))
            using (var reader = await cmd.ExecuteReaderAsync())
            {
                while (await reader.ReadAsync())
                {
                    var severity = reader.GetString(0);
                    var count = reader.GetInt32(1);
                    stats.BySeverity[severity] = count;
                }
            }

            // Get counts by type
            var typeSql = @"
                SELECT VulnerabilityType, COUNT(*) as Count 
                FROM AttackAgentVulnerabilities 
                GROUP BY VulnerabilityType
                ORDER BY Count DESC";
            using (var cmd = new SqlCommand(typeSql, connection))
            using (var reader = await cmd.ExecuteReaderAsync())
            {
                while (await reader.ReadAsync())
                {
                    var type = reader.GetString(0);
                    var count = reader.GetInt32(1);
                    stats.ByType[type] = count;
                }
            }

            // Get false positive and verified counts
            using (var cmd = new SqlCommand("SELECT COUNT(*) FROM AttackAgentVulnerabilities WHERE FalsePositive = 1", connection))
            {
                stats.FalsePositiveCount = (int)await cmd.ExecuteScalarAsync();
            }

            using (var cmd = new SqlCommand("SELECT COUNT(*) FROM AttackAgentVulnerabilities WHERE Verified = 1", connection))
            {
                stats.VerifiedCount = (int)await cmd.ExecuteScalarAsync();
            }

            return stats;
        }

        /// <summary>
        /// Gets the dashboard HTML content
        /// </summary>
        private string GetDashboardHtml()
        {
            return @"
<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""UTF-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
    <title>AttackAgent - Vulnerability Database Dashboard</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Space+Grotesk:wght@400;500;600;700&display=swap');

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --bg-dark: #0a0e17;
            --bg-card: #111827;
            --bg-card-hover: #1a2332;
            --border-color: #1e293b;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent-cyan: #22d3ee;
            --accent-purple: #a855f7;
            --accent-pink: #ec4899;
            --accent-green: #10b981;
            --accent-yellow: #fbbf24;
            --accent-red: #ef4444;
            --accent-orange: #f97316;
            --accent-blue: #3b82f6;
            --gradient-1: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --gradient-cyber: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
        }

        body {
            font-family: 'Space Grotesk', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-dark);
            background-image: 
                radial-gradient(ellipse at top, rgba(99, 102, 241, 0.1) 0%, transparent 50%),
                radial-gradient(ellipse at bottom, rgba(168, 85, 247, 0.1) 0%, transparent 50%);
            min-height: 100vh;
            color: var(--text-primary);
        }

        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            text-align: center;
            padding: 40px 20px;
            margin-bottom: 30px;
            position: relative;
        }

        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 50%;
            transform: translateX(-50%);
            width: 200px;
            height: 2px;
            background: linear-gradient(90deg, transparent, var(--accent-cyan), transparent);
        }

        .header h1 {
            font-size: 2.8em;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-purple), var(--accent-pink));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 10px;
            letter-spacing: -0.5px;
        }

        .header .subtitle {
            color: var(--text-secondary);
            font-size: 1.1em;
            font-weight: 400;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            text-align: center;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: var(--card-accent, var(--accent-blue));
        }

        .stat-card:hover {
            transform: translateY(-4px);
            border-color: var(--card-accent, var(--accent-blue));
            box-shadow: 0 8px 30px rgba(0,0,0,0.3);
        }

        .stat-card .number {
            font-family: 'JetBrains Mono', monospace;
            font-size: 2.8em;
            font-weight: 600;
            color: var(--card-accent, var(--text-primary));
            margin-bottom: 8px;
        }

        .stat-card .label {
            color: var(--text-secondary);
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            font-weight: 500;
        }

        .stat-card.critical { --card-accent: var(--accent-red); }
        .stat-card.high { --card-accent: var(--accent-orange); }
        .stat-card.medium { --card-accent: var(--accent-yellow); }
        .stat-card.low { --card-accent: var(--accent-cyan); }
        .stat-card.info { --card-accent: var(--text-muted); }
        .stat-card.total { --card-accent: var(--accent-purple); }

        .controls {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 24px;
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
            align-items: center;
        }

        .controls input, .controls select {
            padding: 12px 16px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            font-size: 14px;
            font-family: 'Space Grotesk', sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            transition: all 0.3s ease;
        }

        .controls input:focus, .controls select:focus {
            outline: none;
            border-color: var(--accent-cyan);
            box-shadow: 0 0 0 3px rgba(34, 211, 238, 0.1);
        }

        .controls input {
            flex: 1;
            min-width: 280px;
        }

        .controls input::placeholder {
            color: var(--text-muted);
        }

        .controls select {
            min-width: 160px;
            cursor: pointer;
        }

        .sort-btn {
            padding: 12px 20px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            background: var(--bg-dark);
            color: var(--text-primary);
            cursor: pointer;
            font-family: 'Space Grotesk', sans-serif;
            font-size: 14px;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .sort-btn:hover {
            border-color: var(--accent-purple);
            background: rgba(168, 85, 247, 0.1);
        }

        .sort-btn.active {
            border-color: var(--accent-purple);
            background: rgba(168, 85, 247, 0.2);
        }

        .vulnerabilities-table {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th {
            background: rgba(0,0,0,0.3);
            padding: 16px;
            text-align: left;
            font-weight: 600;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-secondary);
            border-bottom: 1px solid var(--border-color);
            cursor: pointer;
            transition: all 0.3s ease;
            user-select: none;
        }

        th:hover {
            background: rgba(34, 211, 238, 0.1);
            color: var(--accent-cyan);
        }

        th.sorted {
            color: var(--accent-cyan);
        }

        th .sort-indicator {
            margin-left: 8px;
            opacity: 0.5;
        }

        th.sorted .sort-indicator {
            opacity: 1;
        }

        td {
            padding: 16px;
            border-bottom: 1px solid var(--border-color);
            font-size: 0.95em;
            vertical-align: top;
        }

        tr {
            transition: all 0.2s ease;
        }

        tr:hover {
            background: var(--bg-card-hover);
        }

        tr:last-child td {
            border-bottom: none;
        }

        .severity-badge {
            display: inline-block;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .severity-badge.critical { background: rgba(239, 68, 68, 0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }
        .severity-badge.high { background: rgba(249, 115, 22, 0.2); color: var(--accent-orange); border: 1px solid var(--accent-orange); }
        .severity-badge.medium { background: rgba(251, 191, 36, 0.2); color: var(--accent-yellow); border: 1px solid var(--accent-yellow); }
        .severity-badge.low { background: rgba(34, 211, 238, 0.2); color: var(--accent-cyan); border: 1px solid var(--accent-cyan); }
        .severity-badge.info { background: rgba(100, 116, 139, 0.2); color: var(--text-muted); border: 1px solid var(--text-muted); }

        .type-badge {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85em;
            color: var(--accent-purple);
        }

        .endpoint-cell {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85em;
            color: var(--accent-green);
            word-break: break-all;
            max-width: 300px;
        }

        .method-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75em;
            font-weight: 600;
            background: rgba(59, 130, 246, 0.2);
            color: var(--accent-blue);
            margin-right: 8px;
        }

        .confidence-bar {
            width: 80px;
            height: 6px;
            background: var(--border-color);
            border-radius: 3px;
            overflow: hidden;
            display: inline-block;
            vertical-align: middle;
            margin-right: 8px;
        }

        .confidence-bar-fill {
            height: 100%;
            background: var(--accent-green);
            border-radius: 3px;
            transition: width 0.3s ease;
        }

        .confidence-text {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85em;
            color: var(--text-secondary);
        }

        .status-icon {
            font-size: 1.2em;
        }

        .status-icon.verified { color: var(--accent-green); }
        .status-icon.false-positive { color: var(--accent-red); }
        .status-icon.pending { color: var(--text-muted); }

        .id-cell {
            font-family: 'JetBrains Mono', monospace;
            color: var(--text-muted);
            font-size: 0.85em;
        }

        .timestamp-cell {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8em;
            color: var(--text-secondary);
            white-space: nowrap;
        }

        .app-cell {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8em;
            color: var(--accent-blue);
            max-width: 150px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .app-cell:hover {
            white-space: normal;
            word-break: break-all;
        }

        .scan-id-cell {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75em;
            color: var(--text-muted);
        }

        .false-positive-row {
            opacity: 0.5;
            background: rgba(239, 68, 68, 0.05);
        }

        .false-positive-row:hover {
            opacity: 0.7;
        }

        .payload-cell {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8em;
            color: var(--accent-pink);
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .payload-cell:hover {
            white-space: normal;
            word-break: break-all;
        }

        .no-data {
            text-align: center;
            padding: 60px 20px;
            color: var(--text-secondary);
        }

        .no-data h2 {
            font-size: 1.5em;
            margin-bottom: 10px;
            color: var(--text-primary);
        }

        .loading {
            text-align: center;
            padding: 60px 20px;
            color: var(--accent-cyan);
        }

        .loading::after {
            content: '';
            animation: pulse 1.5s ease-in-out infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .results-count {
            color: var(--text-secondary);
            font-size: 0.9em;
            padding: 12px 16px;
            background: rgba(0,0,0,0.2);
            border-bottom: 1px solid var(--border-color);
        }

        .results-count strong {
            color: var(--accent-cyan);
            font-family: 'JetBrains Mono', monospace;
        }

        /* Scrollbar styling */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }

        ::-webkit-scrollbar-track {
            background: var(--bg-dark);
        }

        ::-webkit-scrollbar-thumb {
            background: var(--border-color);
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: var(--text-muted);
        }

        .table-container {
            overflow-x: auto;
        }

        /* Make rows clickable */
        tbody tr {
            cursor: pointer;
            transition: all 0.2s ease;
        }

        tbody tr:hover {
            background: rgba(0, 212, 255, 0.1);
            transform: scale(1.001);
        }

        /* Modal Styles */
        .modal-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.85);
            backdrop-filter: blur(5px);
            z-index: 1000;
            animation: fadeIn 0.2s ease;
        }

        .modal-overlay.active {
            display: flex;
            justify-content: center;
            align-items: center;
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        .modal {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            width: 90%;
            max-width: 800px;
            max-height: 90vh;
            overflow: hidden;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.5);
            animation: slideUp 0.3s ease;
        }

        @keyframes slideUp {
            from { transform: translateY(20px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 24px;
            background: linear-gradient(135deg, var(--bg-dark) 0%, rgba(0, 212, 255, 0.1) 100%);
            border-bottom: 1px solid var(--border-color);
        }

        .modal-header h2 {
            margin: 0;
            font-size: 1.3em;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .modal-close {
            background: none;
            border: none;
            color: var(--text-secondary);
            font-size: 1.8em;
            cursor: pointer;
            padding: 0;
            line-height: 1;
            transition: all 0.2s ease;
        }

        .modal-close:hover {
            color: var(--accent-red);
            transform: scale(1.1);
        }

        .modal-body {
            padding: 24px;
            overflow-y: auto;
            max-height: calc(90vh - 140px);
        }

        .detail-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 16px;
            margin-bottom: 20px;
        }

        .detail-item {
            background: rgba(0, 0, 0, 0.3);
            border-radius: 8px;
            padding: 14px;
            border: 1px solid var(--border-color);
        }

        .detail-item.full-width {
            grid-column: span 2;
        }

        .detail-label {
            font-size: 0.75em;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            margin-bottom: 6px;
        }

        .detail-value {
            color: var(--text-primary);
            font-size: 0.95em;
            word-break: break-word;
        }

        .detail-value.mono {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85em;
        }

        .detail-value.code {
            background: rgba(0, 0, 0, 0.4);
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            white-space: pre-wrap;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8em;
            max-height: 150px;
            overflow-y: auto;
        }

        .detail-value .severity-badge {
            font-size: 1em;
        }

        .solution-section {
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.1) 0%, rgba(16, 185, 129, 0.05) 100%);
            border: 1px solid rgba(16, 185, 129, 0.3);
            border-radius: 8px;
            padding: 16px;
            margin-top: 16px;
        }

        .solution-section h3 {
            color: #10b981;
            margin: 0 0 12px 0;
            font-size: 1em;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .solution-section p {
            color: var(--text-secondary);
            margin: 0;
            line-height: 1.6;
        }

        .modal-footer {
            padding: 16px 24px;
            background: var(--bg-dark);
            border-top: 1px solid var(--border-color);
            display: flex;
            justify-content: flex-end;
            gap: 12px;
        }

        .btn {
            padding: 10px 20px;
            border-radius: 6px;
            font-size: 0.9em;
            cursor: pointer;
            transition: all 0.2s ease;
            border: none;
        }

        .btn-secondary {
            background: var(--border-color);
            color: var(--text-primary);
        }

        .btn-secondary:hover {
            background: var(--text-muted);
        }

        .btn-primary {
            background: var(--accent-cyan);
            color: var(--bg-dark);
            font-weight: 600;
        }

        .btn-primary:hover {
            background: #00b8d9;
        }

        .status-badges {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }

        .status-badge {
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: 500;
        }

        .status-badge.verified {
            background: rgba(16, 185, 129, 0.2);
            color: #10b981;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }

        .status-badge.false-positive {
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }

        .status-badge.pending {
            background: rgba(251, 191, 36, 0.2);
            color: #fbbf24;
            border: 1px solid rgba(251, 191, 36, 0.3);
        }
    </style>
</head>
<body>
    <div class=""container"">
        <div class=""header"">
            <h1>🛡️ AttackAgent Database</h1>
            <div class=""subtitle"">All Vulnerabilities from Security Scans</div>
        </div>

        <div id=""stats"" class=""stats-grid"">
            <div class=""stat-card total"">
                <div class=""number"" id=""totalCount"">-</div>
                <div class=""label"">Total</div>
            </div>
            <div class=""stat-card critical"">
                <div class=""number"" id=""criticalCount"">-</div>
                <div class=""label"">Critical</div>
            </div>
            <div class=""stat-card high"">
                <div class=""number"" id=""highCount"">-</div>
                <div class=""label"">High</div>
            </div>
            <div class=""stat-card medium"">
                <div class=""number"" id=""mediumCount"">-</div>
                <div class=""label"">Medium</div>
            </div>
            <div class=""stat-card low"">
                <div class=""number"" id=""lowCount"">-</div>
                <div class=""label"">Low</div>
            </div>
            <div class=""stat-card info"">
                <div class=""number"" id=""infoCount"">-</div>
                <div class=""label"">Info</div>
            </div>
        </div>

        <div class=""controls"">
            <input type=""text"" id=""searchInput"" placeholder=""🔍 Search by type, endpoint, payload, evidence..."" />
            <select id=""severityFilter"">
                <option value="""">All Severities</option>
                <option value=""Critical"">Critical</option>
                <option value=""High"">High</option>
                <option value=""Medium"">Medium</option>
                <option value=""Low"">Low</option>
                <option value=""Info"">Info</option>
            </select>
            <select id=""typeFilter"">
                <option value="""">All Types</option>
            </select>
            <select id=""statusFilter"">
                <option value="""">All Status</option>
                <option value=""realOnly"">Real Only (Hide FPs)</option>
                <option value=""verified"">Verified Only</option>
                <option value=""falsePositive"">False Positives Only</option>
                <option value=""pending"">Pending Review</option>
            </select>
        </div>

        <div class=""vulnerabilities-table"">
            <div class=""results-count"" id=""resultsCount"">Loading...</div>
            <div class=""table-container"">
                <table>
                    <thead>
                        <tr>
                            <th data-sort=""id"">ID <span class=""sort-indicator"">↕</span></th>
                            <th data-sort=""scanTime"">Timestamp <span class=""sort-indicator"">↕</span></th>
                            <th data-sort=""applicationScanned"">Application <span class=""sort-indicator"">↕</span></th>
                            <th data-sort=""scanId"">Scan ID <span class=""sort-indicator"">↕</span></th>
                            <th data-sort=""severity"">Severity <span class=""sort-indicator"">↕</span></th>
                            <th data-sort=""vulnerabilityType"">Type <span class=""sort-indicator"">↕</span></th>
                            <th data-sort=""endpoint"">Endpoint <span class=""sort-indicator"">↕</span></th>
                            <th data-sort=""confidence"">Confidence <span class=""sort-indicator"">↕</span></th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody id=""vulnerabilitiesBody"">
                        <tr><td colspan=""9"" class=""loading"">Loading vulnerabilities from database...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Vulnerability Detail Modal -->
    <div class=""modal-overlay"" id=""vulnModal"">
        <div class=""modal"">
            <div class=""modal-header"">
                <h2><span id=""modalIcon"">🔴</span> <span id=""modalTitle"">Vulnerability Details</span></h2>
                <button class=""modal-close"" onclick=""closeModal()"">&times;</button>
            </div>
            <div class=""modal-body"">
                <div class=""detail-grid"">
                    <div class=""detail-item"">
                        <div class=""detail-label"">ID</div>
                        <div class=""detail-value mono"" id=""modalId"">-</div>
                    </div>
                    <div class=""detail-item"">
                        <div class=""detail-label"">Severity</div>
                        <div class=""detail-value"" id=""modalSeverity"">-</div>
                    </div>
                    <div class=""detail-item"">
                        <div class=""detail-label"">Vulnerability Type</div>
                        <div class=""detail-value"" id=""modalType"">-</div>
                    </div>
                    <div class=""detail-item"">
                        <div class=""detail-label"">Confidence</div>
                        <div class=""detail-value"" id=""modalConfidence"">-</div>
                    </div>
                    <div class=""detail-item"">
                        <div class=""detail-label"">Scan ID</div>
                        <div class=""detail-value mono"" id=""modalScanId"">-</div>
                    </div>
                    <div class=""detail-item"">
                        <div class=""detail-label"">Timestamp</div>
                        <div class=""detail-value"" id=""modalTimestamp"">-</div>
                    </div>
                    <div class=""detail-item full-width"">
                        <div class=""detail-label"">Application Scanned</div>
                        <div class=""detail-value mono"" id=""modalApp"">-</div>
                    </div>
                    <div class=""detail-item full-width"">
                        <div class=""detail-label"">Endpoint</div>
                        <div class=""detail-value mono"" id=""modalEndpoint"">-</div>
                    </div>
                    <div class=""detail-item"">
                        <div class=""detail-label"">HTTP Method</div>
                        <div class=""detail-value"" id=""modalMethod"">-</div>
                    </div>
                    <div class=""detail-item"">
                        <div class=""detail-label"">Parameter</div>
                        <div class=""detail-value mono"" id=""modalParameter"">-</div>
                    </div>
                    <div class=""detail-item full-width"">
                        <div class=""detail-label"">Payload Used</div>
                        <div class=""detail-value code"" id=""modalPayload"">-</div>
                    </div>
                    <div class=""detail-item full-width"">
                        <div class=""detail-label"">Evidence</div>
                        <div class=""detail-value code"" id=""modalEvidence"">-</div>
                    </div>
                    <div class=""detail-item"">
                        <div class=""detail-label"">Status</div>
                        <div class=""detail-value"" id=""modalStatus"">-</div>
                    </div>
                </div>
                <div class=""solution-section"">
                    <h3>💡 Recommended Solution</h3>
                    <p id=""modalSolution"">Loading solution...</p>
                </div>
            </div>
            <div class=""modal-footer"">
                <button class=""btn btn-secondary"" onclick=""closeModal()"">Close</button>
            </div>
        </div>
    </div>

    <script>
        let allVulnerabilities = [];
        let stats = null;
        let currentSort = { field: 'id', direction: 'desc' };

        async function loadData() {
            try {
                const [vulnsResponse, statsResponse] = await Promise.all([
                    fetch('/api/vulnerabilities'),
                    fetch('/api/stats')
                ]);

                allVulnerabilities = await vulnsResponse.json();
                stats = await statsResponse.json();

                renderStats();
                populateTypeFilter();
                renderTable();
            } catch (error) {
                console.error('Error loading data:', error);
                document.getElementById('vulnerabilitiesBody').innerHTML = 
                    '<tr><td colspan=""9"" class=""no-data""><h2>❌ Error loading data</h2><p>' + error.message + '</p></td></tr>';
            }
        }

        function renderStats() {
            if (!stats) return;

            document.getElementById('totalCount').textContent = stats.totalCount || 0;
            document.getElementById('criticalCount').textContent = stats.bySeverity?.Critical || 0;
            document.getElementById('highCount').textContent = stats.bySeverity?.High || 0;
            document.getElementById('mediumCount').textContent = stats.bySeverity?.Medium || 0;
            document.getElementById('lowCount').textContent = stats.bySeverity?.Low || 0;
            document.getElementById('infoCount').textContent = stats.bySeverity?.Info || 0;
        }

        function populateTypeFilter() {
            const types = [...new Set(allVulnerabilities.map(v => v.vulnerabilityType))].sort();
            const typeFilter = document.getElementById('typeFilter');
            typeFilter.innerHTML = '<option value="""">All Types</option>';
            
            types.forEach(type => {
                const option = document.createElement('option');
                option.value = type;
                option.textContent = formatType(type);
                typeFilter.appendChild(option);
            });
        }

        function getFilteredAndSorted() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            const severityFilter = document.getElementById('severityFilter').value;
            const typeFilter = document.getElementById('typeFilter').value;
            const statusFilter = document.getElementById('statusFilter').value;

            let filtered = allVulnerabilities.filter(v => {
                const matchesSearch = !searchTerm || 
                    (v.vulnerabilityType && v.vulnerabilityType.toLowerCase().includes(searchTerm)) ||
                    (v.endpoint && v.endpoint.toLowerCase().includes(searchTerm)) ||
                    (v.payload && v.payload.toLowerCase().includes(searchTerm)) ||
                    (v.evidence && v.evidence.toLowerCase().includes(searchTerm)) ||
                    (v.parameter && v.parameter.toLowerCase().includes(searchTerm));

                const matchesSeverity = !severityFilter || v.severity === severityFilter;
                const matchesType = !typeFilter || v.vulnerabilityType === typeFilter;
                
                let matchesStatus = true;
                if (statusFilter === 'realOnly') matchesStatus = !v.falsePositive;
                else if (statusFilter === 'verified') matchesStatus = v.verified;
                else if (statusFilter === 'falsePositive') matchesStatus = v.falsePositive;
                else if (statusFilter === 'pending') matchesStatus = !v.verified && !v.falsePositive;

                return matchesSearch && matchesSeverity && matchesType && matchesStatus;
            });

            // Sort
            filtered.sort((a, b) => {
                let aVal = a[currentSort.field];
                let bVal = b[currentSort.field];

                // Handle severity sorting
                if (currentSort.field === 'severity') {
                    const severityOrder = { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1 };
                    aVal = severityOrder[aVal] || 0;
                    bVal = severityOrder[bVal] || 0;
                }

                if (aVal === null || aVal === undefined) aVal = '';
                if (bVal === null || bVal === undefined) bVal = '';

                if (typeof aVal === 'string') aVal = aVal.toLowerCase();
                if (typeof bVal === 'string') bVal = bVal.toLowerCase();

                if (aVal < bVal) return currentSort.direction === 'asc' ? -1 : 1;
                if (aVal > bVal) return currentSort.direction === 'asc' ? 1 : -1;
                return 0;
            });

            return filtered;
        }

        function renderTable() {
            const filtered = getFilteredAndSorted();
            const tbody = document.getElementById('vulnerabilitiesBody');
            const resultsCount = document.getElementById('resultsCount');

            resultsCount.innerHTML = `Showing <strong>${filtered.length}</strong> of <strong>${allVulnerabilities.length}</strong> vulnerabilities`;

            if (filtered.length === 0) {
                tbody.innerHTML = '<tr><td colspan=""9"" class=""no-data""><h2>No vulnerabilities found</h2><p>Try adjusting your filters</p></td></tr>';
                return;
            }

            tbody.innerHTML = filtered.map(v => `
                <tr class=""${v.falsePositive ? 'false-positive-row' : ''}"" data-id=""${v.id}"" onclick=""showVulnerabilityDetail(${v.id})"">
                    <td class=""id-cell"">#${v.id}</td>
                    <td class=""timestamp-cell"">${formatTimestamp(v.scanTime)}</td>
                    <td class=""app-cell"" title=""${escapeHtml(v.applicationScanned || '')}"">${escapeHtml(truncateUrl(v.applicationScanned) || '-')}</td>
                    <td class=""scan-id-cell"">${escapeHtml(v.scanId || '-')}</td>
                    <td><span class=""severity-badge ${(v.severity || '').toLowerCase()}"">${v.severity}</span></td>
                    <td class=""type-badge"">${formatType(v.vulnerabilityType)}</td>
                    <td class=""endpoint-cell"">
                        ${v.method ? `<span class=""method-badge"">${escapeHtml(v.method)}</span>` : ''}
                        ${escapeHtml(v.endpoint || 'N/A')}
                    </td>
                    <td>
                        <div class=""confidence-bar""><div class=""confidence-bar-fill"" style=""width: ${v.confidence * 100}%""></div></div>
                        <span class=""confidence-text"">${(v.confidence * 100).toFixed(0)}%</span>
                    </td>
                    <td>
                        ${v.verified ? '<span class=""status-icon verified"" title=""Verified"">✓</span>' : ''}
                        ${v.falsePositive ? '<span class=""status-icon false-positive"" title=""False Positive"">✗</span>' : ''}
                        ${!v.verified && !v.falsePositive ? '<span class=""status-icon pending"" title=""Pending Review"">○</span>' : ''}
                    </td>
                </tr>
            `).join('');

            // Update sort indicators
            document.querySelectorAll('th[data-sort]').forEach(th => {
                th.classList.toggle('sorted', th.dataset.sort === currentSort.field);
                const indicator = th.querySelector('.sort-indicator');
                if (th.dataset.sort === currentSort.field) {
                    indicator.textContent = currentSort.direction === 'asc' ? '↑' : '↓';
                } else {
                    indicator.textContent = '↕';
                }
            });
        }

        function formatType(type) {
            if (!type) return 'Unknown';
            return type.replace(/([A-Z])/g, ' $1').trim();
        }

        function truncateUrl(url) {
            if (!url) return null;
            // Extract path from URL, truncate if needed
            try {
                const urlObj = new URL(url);
                const path = urlObj.pathname;
                return path.length > 30 ? '...' + path.slice(-27) : path;
            } catch {
                return url.length > 30 ? '...' + url.slice(-27) : url;
            }
        }

        function formatTimestamp(dateStr) {
            if (!dateStr) return '-';
            try {
                const date = new Date(dateStr);
                const year = date.getFullYear();
                const month = String(date.getMonth() + 1).padStart(2, '0');
                const day = String(date.getDate()).padStart(2, '0');
                const hours = String(date.getHours()).padStart(2, '0');
                const mins = String(date.getMinutes()).padStart(2, '0');
                const secs = String(date.getSeconds()).padStart(2, '0');
                return `${year}-${month}-${day} ${hours}:${mins}:${secs}`;
            } catch {
                return '-';
            }
        }

        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Event listeners
        document.getElementById('searchInput').addEventListener('input', renderTable);
        document.getElementById('severityFilter').addEventListener('change', renderTable);
        document.getElementById('typeFilter').addEventListener('change', renderTable);
        document.getElementById('statusFilter').addEventListener('change', renderTable);

        // Sort handling
        document.querySelectorAll('th[data-sort]').forEach(th => {
            th.addEventListener('click', () => {
                const field = th.dataset.sort;
                if (currentSort.field === field) {
                    currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
                } else {
                    currentSort.field = field;
                    currentSort.direction = 'desc';
                }
                renderTable();
            });
        });

        // Modal functions
        function showVulnerabilityDetail(id) {
            const vuln = allVulnerabilities.find(v => v.id === id);
            if (!vuln) return;

            // Set severity icon
            const icons = { Critical: '🔴', High: '🟠', Medium: '🟡', Low: '🟢', Info: 'ℹ️' };
            document.getElementById('modalIcon').textContent = icons[vuln.severity] || '⚠️';
            document.getElementById('modalTitle').textContent = formatType(vuln.vulnerabilityType);

            // Populate details
            document.getElementById('modalId').textContent = '#' + vuln.id;
            document.getElementById('modalSeverity').innerHTML = `<span class=""severity-badge ${(vuln.severity || '').toLowerCase()}"">${vuln.severity}</span>`;
            document.getElementById('modalType').textContent = formatType(vuln.vulnerabilityType);
            document.getElementById('modalConfidence').textContent = (vuln.confidence * 100).toFixed(0) + '%';
            document.getElementById('modalScanId').textContent = vuln.scanId || '-';
            document.getElementById('modalTimestamp').textContent = formatTimestamp(vuln.scanTime);
            document.getElementById('modalApp').textContent = vuln.applicationScanned || '-';
            document.getElementById('modalEndpoint').textContent = vuln.endpoint || '-';
            document.getElementById('modalMethod').innerHTML = vuln.method ? `<span class=""method-badge"">${escapeHtml(vuln.method)}</span>` : '-';
            document.getElementById('modalParameter').textContent = vuln.parameter || '-';
            document.getElementById('modalPayload').textContent = vuln.payload || 'No payload recorded';
            document.getElementById('modalEvidence').textContent = vuln.evidence || 'No evidence recorded';

            // Status badges
            let statusHtml = '<div class=""status-badges"">';
            if (vuln.verified) statusHtml += '<span class=""status-badge verified"">✓ Verified</span>';
            if (vuln.falsePositive) statusHtml += '<span class=""status-badge false-positive"">✗ False Positive</span>';
            if (!vuln.verified && !vuln.falsePositive) statusHtml += '<span class=""status-badge pending"">○ Pending Review</span>';
            statusHtml += '</div>';
            document.getElementById('modalStatus').innerHTML = statusHtml;

            // Get solution
            document.getElementById('modalSolution').textContent = getSolution(vuln.vulnerabilityType, vuln.severity);

            // Show modal
            document.getElementById('vulnModal').classList.add('active');
            document.body.style.overflow = 'hidden';
        }

        function closeModal() {
            document.getElementById('vulnModal').classList.remove('active');
            document.body.style.overflow = '';
        }

        // Close modal on overlay click
        document.getElementById('vulnModal').addEventListener('click', function(e) {
            if (e.target === this) closeModal();
        });

        // Close modal on Escape key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') closeModal();
        });

        function getSolution(type, severity) {
            const solutions = {
                'ReflectedXss': 'Implement proper output encoding/escaping for all user-supplied data. Use Content Security Policy (CSP) headers. Validate and sanitize all input on the server side. Consider using auto-escaping template engines.',
                'StoredXss': 'Sanitize and validate all user input before storing in the database. Implement output encoding when displaying stored content. Use CSP headers. Consider implementing a content review process for user-generated content.',
                'SqlInjection': 'Use parameterized queries or prepared statements exclusively. Never concatenate user input into SQL queries. Implement input validation. Use an ORM with proper escaping. Apply principle of least privilege to database accounts.',
                'CommandInjection': 'Avoid system commands where possible. Use language-specific APIs instead of shell commands. If commands are necessary, use allowlists for permitted values. Never pass unsanitized user input to system commands.',
                'PathTraversal': 'Validate and sanitize file paths. Use allowlists for permitted files/directories. Implement proper access controls. Never use user input directly in file paths. Use chroot jails or containers.',
                'AuthenticationBypass': 'Implement proper authentication checks on all protected endpoints. Use secure session management. Apply authentication at the API/controller level, not just the UI. Conduct regular security reviews.',
                'InformationDisclosure': 'Remove sensitive information from error messages and responses. Disable debug mode in production. Implement proper access controls. Review all API responses for sensitive data leakage.',
                'ExposedCredentials': 'Remove credentials from source code and configuration files. Use environment variables or secure secret management. Rotate all exposed credentials immediately. Implement secret scanning in CI/CD.',
                'InsecureDirectObjectReference': 'Implement proper authorization checks for all object access. Use indirect references (GUIDs) instead of sequential IDs. Verify user permissions before returning data.',
                'SecurityMisconfiguration': 'Review and harden all security configurations. Disable unnecessary features and services. Keep all software updated. Implement security headers. Follow security hardening guides.',
                'CorsVulnerability': 'Configure CORS to allow only trusted origins. Avoid using wildcard (*) for Access-Control-Allow-Origin. Validate the Origin header server-side. Use credentials mode appropriately.',
                'MissingSecurityHeaders': 'Implement security headers: Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, X-XSS-Protection. Configure headers at the web server or application level.',
                'RateLimitingIssue': 'Implement rate limiting on all endpoints, especially authentication. Use exponential backoff for repeated failures. Consider CAPTCHA for suspicious activity. Monitor for abuse patterns.',
                'FileUploadVulnerability': 'Validate file types using magic bytes, not just extensions. Store uploads outside web root. Rename uploaded files. Scan for malware. Implement size limits. Use Content-Disposition headers.',
                'DenialOfService': 'Implement rate limiting and request throttling. Use connection timeouts. Deploy behind a CDN or DDoS protection service. Monitor for abnormal traffic patterns.',
                'Default': 'Review the vulnerability details and implement appropriate security controls. Consult OWASP guidelines for specific remediation steps. Consider engaging a security professional for complex issues.'
            };

            let solution = solutions[type] || solutions['Default'];
            
            if (severity === 'Critical' || severity === 'High') {
                solution = '⚠️ HIGH PRIORITY: ' + solution + ' This should be addressed immediately due to its severity.';
            }
            
            return solution;
        }

        // Load data on page load
        loadData();
    </script>
</body>
</html>";
        }

        /// <summary>
        /// Finds an available port starting from 5000
        /// </summary>
        private int FindAvailablePort()
        {
            for (int port = 5000; port < 5100; port++)
            {
                try
                {
                    var listener = new HttpListener();
                    listener.Prefixes.Add($"http://localhost:{port}/");
                    listener.Start();
                    listener.Stop();
                    return port;
                }
                catch
                {
                    // Port is in use, try next
                }
            }
            throw new Exception("Could not find an available port for dashboard");
        }

        public void Dispose()
        {
            Stop();
            _cancellationTokenSource.Dispose();
            _listener.Close();
        }
    }

    /// <summary>
    /// Represents a vulnerability from the database
    /// </summary>
    public class DatabaseVulnerability
    {
        public int Id { get; set; }
        public string VulnerabilityType { get; set; } = "";
        public string Severity { get; set; } = "";
        public double Confidence { get; set; }
        public string? Endpoint { get; set; }
        public string? Method { get; set; }
        public string? Parameter { get; set; }
        public string? Payload { get; set; }
        public string? Evidence { get; set; }
        public bool FalsePositive { get; set; }
        public bool Verified { get; set; }
        public string? ScanId { get; set; }
        public string? ApplicationScanned { get; set; }
        public DateTime? ScanTime { get; set; }
    }

    /// <summary>
    /// Statistics about vulnerabilities in the database
    /// </summary>
    public class DatabaseStats
    {
        public int TotalCount { get; set; }
        public Dictionary<string, int> BySeverity { get; set; } = new();
        public Dictionary<string, int> ByType { get; set; } = new();
        public int FalsePositiveCount { get; set; }
        public int VerifiedCount { get; set; }
    }
}

