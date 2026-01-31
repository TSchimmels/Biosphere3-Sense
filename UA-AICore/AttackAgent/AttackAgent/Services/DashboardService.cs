using AttackAgent.Models;
using System.Net;
using System.Text;
using System.Text.Json;
using Serilog;

namespace AttackAgent.Services
{
    /// <summary>
    /// Service for hosting a web dashboard to display scan results
    /// Shows only vulnerabilities from the current scan (not database)
    /// </summary>
    public class DashboardService : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly List<Vulnerability> _vulnerabilities;
        private readonly VulnerabilityReport _report;
        private readonly string _targetUrl;
        private readonly DateTime _scanStartTime;
        private readonly DateTime _scanEndTime;
        private readonly ILogger _logger;
        private bool _isRunning = false;
        private Task? _serverTask;
        private readonly CancellationTokenSource _cancellationTokenSource = new();

        public int Port { get; private set; }
        public string Url => $"http://localhost:{Port}";

        public DashboardService(
            string targetUrl,
            List<Vulnerability> vulnerabilities,
            DateTime scanStartTime,
            DateTime scanEndTime)
        {
            _targetUrl = targetUrl;
            _vulnerabilities = vulnerabilities ?? new List<Vulnerability>();
            _scanStartTime = scanStartTime;
            _scanEndTime = scanEndTime;
            _logger = Log.ForContext<DashboardService>();

            // Create a vulnerability report for the dashboard
            _report = new VulnerabilityReport
            {
                TargetUrl = targetUrl,
                ScanStartTime = scanStartTime,
                ScanEndTime = scanEndTime,
                Vulnerabilities = _vulnerabilities
            };

            // Calculate summary
            _report.Summary = CalculateSummary(_vulnerabilities);
            _report.RiskScore = CalculateRiskScore(_vulnerabilities);
            _report.OverallRiskLevel = DetermineRiskLevel(_report.RiskScore);

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
                _logger.Information("📊 Dashboard server started on {Url}", Url);

                _serverTask = Task.Run(async () => await ListenAsync(_cancellationTokenSource.Token));
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "❌ Failed to start dashboard server");
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
            _logger.Information("📊 Dashboard server stopped");
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
                    await ServeVulnerabilitiesApiAsync(response);
                }
                else if (path == "/api/report")
                {
                    await ServeReportApiAsync(response);
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
        /// Serves vulnerabilities as JSON API
        /// </summary>
        private async Task ServeVulnerabilitiesApiAsync(HttpListenerResponse response)
        {
            try
            {
                response.ContentType = "application/json; charset=utf-8";
                response.StatusCode = 200;
                response.Headers.Add("Access-Control-Allow-Origin", "*");

                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
                };

                var json = JsonSerializer.Serialize(_vulnerabilities, options);

                var buffer = Encoding.UTF8.GetBytes(json);
                response.ContentLength64 = buffer.Length;
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                response.Close();
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error serializing vulnerabilities to JSON");
                response.StatusCode = 500;
                var errorJson = JsonSerializer.Serialize(new { error = ex.Message });
                var buffer = Encoding.UTF8.GetBytes(errorJson);
                response.ContentLength64 = buffer.Length;
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                response.Close();
            }
        }

        /// <summary>
        /// Serves full report as JSON API
        /// </summary>
        private async Task ServeReportApiAsync(HttpListenerResponse response)
        {
            try
            {
                response.ContentType = "application/json; charset=utf-8";
                response.StatusCode = 200;
                response.Headers.Add("Access-Control-Allow-Origin", "*");

                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
                };

                var json = JsonSerializer.Serialize(_report, options);

                var buffer = Encoding.UTF8.GetBytes(json);
                response.ContentLength64 = buffer.Length;
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                response.Close();
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error serializing report to JSON");
                response.StatusCode = 500;
                var errorJson = JsonSerializer.Serialize(new { error = ex.Message });
                var buffer = Encoding.UTF8.GetBytes(errorJson);
                response.ContentLength64 = buffer.Length;
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                response.Close();
            }
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
    <title>AttackAgent - Vulnerability Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
            color: #333;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .header .subtitle {
            opacity: 0.9;
            font-size: 1.1em;
        }

        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }

        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }

        .stat-card .number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }

        .stat-card .label {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .stat-card.critical .number { color: #dc3545; }
        .stat-card.high .number { color: #fd7e14; }
        .stat-card.medium .number { color: #ffc107; }
        .stat-card.low .number { color: #17a2b8; }
        .stat-card.info .number { color: #6c757d; }
        .stat-card.total .number { color: #667eea; }

        .controls {
            padding: 20px 30px;
            background: white;
            border-bottom: 1px solid #e9ecef;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }

        .controls input, .controls select {
            padding: 10px 15px;
            border: 2px solid #e9ecef;
            border-radius: 6px;
            font-size: 14px;
            transition: border-color 0.3s;
        }

        .controls input:focus, .controls select:focus {
            outline: none;
            border-color: #667eea;
        }

        .controls input {
            flex: 1;
            min-width: 200px;
        }

        .controls select {
            min-width: 150px;
        }

        .vulnerabilities {
            padding: 30px;
        }

        .vulnerability-item {
            background: white;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            margin-bottom: 15px;
            overflow: hidden;
            transition: all 0.3s;
        }

        .vulnerability-item:hover {
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            border-color: #667eea;
        }

        .vulnerability-header {
            padding: 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #f8f9fa;
        }

        .vulnerability-header:hover {
            background: #e9ecef;
        }

        .vulnerability-title {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .severity-badge {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .severity-badge.critical { background: #dc3545; color: white; }
        .severity-badge.high { background: #fd7e14; color: white; }
        .severity-badge.medium { background: #ffc107; color: #333; }
        .severity-badge.low { background: #17a2b8; color: white; }
        .severity-badge.info { background: #6c757d; color: white; }

        .vulnerability-type {
            font-size: 1.2em;
            font-weight: 600;
            color: #333;
        }

        .vulnerability-endpoint {
            color: #666;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }

        .expand-icon {
            font-size: 1.5em;
            color: #667eea;
            transition: transform 0.3s;
        }

        .vulnerability-item.expanded .expand-icon {
            transform: rotate(180deg);
        }

        .vulnerability-details {
            padding: 0 20px;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s, padding 0.3s;
        }

        .vulnerability-item.expanded .vulnerability-details {
            max-height: 2000px;
            padding: 20px;
        }

        .detail-row {
            margin-bottom: 15px;
        }

        .detail-label {
            font-weight: 600;
            color: #667eea;
            margin-bottom: 5px;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
        }

        .detail-value {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            word-break: break-all;
        }

        .no-vulnerabilities {
            text-align: center;
            padding: 60px 20px;
            color: #666;
        }

        .no-vulnerabilities h2 {
            font-size: 2em;
            margin-bottom: 10px;
            color: #28a745;
        }

        .loading {
            text-align: center;
            padding: 60px 20px;
            color: #667eea;
        }

        .loading::after {
            content: '...';
            animation: dots 1.5s steps(4, end) infinite;
        }

        @keyframes dots {
            0%, 20% { content: '.'; }
            40% { content: '..'; }
            60%, 100% { content: '...'; }
        }

        .scan-info {
            padding: 20px 30px;
            background: #f8f9fa;
            border-bottom: 1px solid #e9ecef;
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 15px;
        }

        .scan-info-item {
            display: flex;
            flex-direction: column;
        }

        .scan-info-label {
            font-size: 0.85em;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .scan-info-value {
            font-size: 1.1em;
            font-weight: 600;
            color: #333;
        }
    </style>
</head>
<body>
    <div class=""container"">
        <div class=""header"">
            <h1>🛡️ AttackAgent Dashboard</h1>
            <div class=""subtitle"">Security Vulnerability Report</div>
        </div>
        <div id=""scanInfo"" class=""scan-info""></div>
        <div id=""summary"" class=""summary""></div>
        <div class=""controls"">
            <input type=""text"" id=""searchInput"" placeholder=""🔍 Search vulnerabilities (endpoint, parameter, payload...)"" />
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
        </div>
        <div id=""vulnerabilities"" class=""vulnerabilities"">
            <div class=""loading"">Loading vulnerabilities</div>
        </div>
    </div>

    <script>
        let allVulnerabilities = [];
        let report = null;

        async function loadData() {
            try {
                const [vulnsResponse, reportResponse] = await Promise.all([
                    fetch('/api/vulnerabilities'),
                    fetch('/api/report')
                ]);

                if (!vulnsResponse.ok) {
                    throw new Error(`Vulnerabilities API error: ${vulnsResponse.status} ${vulnsResponse.statusText}`);
                }
                if (!reportResponse.ok) {
                    throw new Error(`Report API error: ${reportResponse.status} ${reportResponse.statusText}`);
                }

                const vulnsText = await vulnsResponse.text();
                const reportText = await reportResponse.text();

                try {
                    allVulnerabilities = JSON.parse(vulnsText);
                    report = JSON.parse(reportText);
                } catch (parseError) {
                    console.error('JSON Parse Error:', parseError);
                    console.error('Vulnerabilities response:', vulnsText.substring(0, 500));
                    console.error('Report response:', reportText.substring(0, 500));
                    throw new Error('Failed to parse JSON: ' + parseError.message);
                }

                renderScanInfo();
                renderSummary();
                renderVulnerabilities();
                populateTypeFilter();
            } catch (error) {
                console.error('Error loading data:', error);
                document.getElementById('vulnerabilities').innerHTML = 
                    '<div class=""no-vulnerabilities""><h2>❌ Error loading data</h2><p>' + escapeHtml(error.message) + '</p><p>Check the browser console (F12) for more details.</p></div>';
            }
        }

        function renderScanInfo() {
            if (!report) return;

            const scanInfo = document.getElementById('scanInfo');
            const duration = Math.round((new Date(report.scanEndTime) - new Date(report.scanStartTime)) / 1000);
            const minutes = Math.floor(duration / 60);
            const seconds = duration % 60;

            scanInfo.innerHTML = `
                <div class=""scan-info-item"">
                    <div class=""scan-info-label"">Target URL</div>
                    <div class=""scan-info-value"">${escapeHtml(report.targetUrl)}</div>
                </div>
                <div class=""scan-info-item"">
                    <div class=""scan-info-label"">Scan Duration</div>
                    <div class=""scan-info-value"">${minutes}m ${seconds}s</div>
                </div>
                <div class=""scan-info-item"">
                    <div class=""scan-info-label"">Total Vulnerabilities</div>
                    <div class=""scan-info-value"">${report.totalVulnerabilities}</div>
                </div>
                <div class=""scan-info-item"">
                    <div class=""scan-info-label"">Risk Level</div>
                    <div class=""scan-info-value"">${report.overallRiskLevel || 'N/A'}</div>
                </div>
            `;
        }

        function renderSummary() {
            if (!report || !report.summary) return;

            const summary = report.summary;
            const summaryDiv = document.getElementById('summary');

            summaryDiv.innerHTML = `
                <div class=""stat-card total"">
                    <div class=""number"">${report.totalVulnerabilities}</div>
                    <div class=""label"">Total Vulnerabilities</div>
                </div>
                <div class=""stat-card critical"">
                    <div class=""number"">${summary.criticalCount || 0}</div>
                    <div class=""label"">Critical</div>
                </div>
                <div class=""stat-card high"">
                    <div class=""number"">${summary.highCount || 0}</div>
                    <div class=""label"">High</div>
                </div>
                <div class=""stat-card medium"">
                    <div class=""number"">${summary.mediumCount || 0}</div>
                    <div class=""label"">Medium</div>
                </div>
                <div class=""stat-card low"">
                    <div class=""number"">${summary.lowCount || 0}</div>
                    <div class=""label"">Low</div>
                </div>
                <div class=""stat-card info"">
                    <div class=""number"">${summary.infoCount || 0}</div>
                    <div class=""label"">Info</div>
                </div>
            `;
        }

        function populateTypeFilter() {
            const types = [...new Set(allVulnerabilities.map(v => v.type))].sort();
            const typeFilter = document.getElementById('typeFilter');
            
            types.forEach(type => {
                const option = document.createElement('option');
                option.value = type;
                option.textContent = formatType(type);
                typeFilter.appendChild(option);
            });
        }

        function renderVulnerabilities() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            const severityFilter = document.getElementById('severityFilter').value;
            const typeFilter = document.getElementById('typeFilter').value;

            let filtered = allVulnerabilities.filter(v => {
                const matchesSearch = !searchTerm || 
                    (v.endpoint && v.endpoint.toLowerCase().includes(searchTerm)) ||
                    (v.parameter && v.parameter.toLowerCase().includes(searchTerm)) ||
                    (v.payload && v.payload.toLowerCase().includes(searchTerm)) ||
                    (v.type && v.type.toLowerCase().includes(searchTerm));

                const matchesSeverity = !severityFilter || 
                    (v.severity && v.severity.toLowerCase() === severityFilter.toLowerCase());
                const matchesType = !typeFilter || 
                    (v.type && v.type.toLowerCase() === typeFilter.toLowerCase());

                return matchesSearch && matchesSeverity && matchesType;
            });

            const container = document.getElementById('vulnerabilities');

            if (filtered.length === 0) {
                container.innerHTML = '<div class=""no-vulnerabilities""><h2>✅ No vulnerabilities found</h2><p>Great job! No vulnerabilities match your filters.</p></div>';
                return;
            }

            container.innerHTML = filtered.map((v, index) => `
                <div class=""vulnerability-item"" onclick=""toggleDetails(${index})"">
                    <div class=""vulnerability-header"">
                        <div class=""vulnerability-title"">
                            <span class=""severity-badge ${(v.severity || '').toLowerCase()}"">${capitalizeFirst(v.severity || '')}</span>
                            <span class=""vulnerability-type"">${formatType(v.type)}</span>
                            <span class=""vulnerability-endpoint"">${escapeHtml(v.method || '')} ${escapeHtml(v.endpoint || 'N/A')}</span>
                        </div>
                        <span class=""expand-icon"">▼</span>
                    </div>
                    <div class=""vulnerability-details"" id=""details-${index}"">
                        ${v.parameter ? `<div class=""detail-row""><div class=""detail-label"">Parameter</div><div class=""detail-value"">${escapeHtml(v.parameter)}</div></div>` : ''}
                        ${v.payload ? `<div class=""detail-row""><div class=""detail-label"">Payload</div><div class=""detail-value"">${escapeHtml(v.payload)}</div></div>` : ''}
                        ${v.evidence ? `<div class=""detail-row""><div class=""detail-label"">Evidence</div><div class=""detail-value"">${escapeHtml(v.evidence)}</div></div>` : ''}
                        ${v.description ? `<div class=""detail-row""><div class=""detail-label"">Description</div><div class=""detail-value"">${escapeHtml(v.description)}</div></div>` : ''}
                        ${v.remediation ? `<div class=""detail-row""><div class=""detail-label"">Remediation</div><div class=""detail-value"">${escapeHtml(v.remediation)}</div></div>` : ''}
                        <div class=""detail-row"">
                            <div class=""detail-label"">Confidence</div>
                            <div class=""detail-value"">${(v.confidence * 100).toFixed(1)}%</div>
                        </div>
                    </div>
                </div>
            `).join('');

            // Store filtered vulnerabilities for toggleDetails
            window.filteredVulnerabilities = filtered;
        }

        function toggleDetails(index) {
            const item = event.currentTarget;
            item.classList.toggle('expanded');
        }

        function formatType(type) {
            return type.replace(/([A-Z])/g, ' $1').trim();
        }

        function capitalizeFirst(str) {
            if (!str) return '';
            return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
        }

        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Event listeners
        document.getElementById('searchInput').addEventListener('input', renderVulnerabilities);
        document.getElementById('severityFilter').addEventListener('change', renderVulnerabilities);
        document.getElementById('typeFilter').addEventListener('change', renderVulnerabilities);

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

        /// <summary>
        /// Calculates vulnerability summary
        /// </summary>
        private VulnerabilitySummary CalculateSummary(List<Vulnerability> vulnerabilities)
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

                if (!summary.VulnerabilityTypes.ContainsKey(vuln.Type))
                {
                    summary.VulnerabilityTypes[vuln.Type] = 0;
                }
                summary.VulnerabilityTypes[vuln.Type]++;
            }

            summary.EndpointsAffected = vulnerabilities.Select(v => v.Endpoint).Distinct().Count();
            summary.FalsePositiveCount = vulnerabilities.Count(v => v.FalsePositive);
            summary.VerifiedCount = vulnerabilities.Count(v => v.Verified);

            return summary;
        }

        /// <summary>
        /// Calculates overall risk score (0-100)
        /// </summary>
        private double CalculateRiskScore(List<Vulnerability> vulnerabilities)
        {
            if (!vulnerabilities.Any())
            {
                return 0;
            }

            double score = 0;
            foreach (var vuln in vulnerabilities)
            {
                if (vuln.FalsePositive) continue;

                double severityWeight = vuln.Severity switch
                {
                    SeverityLevel.Critical => 10.0,
                    SeverityLevel.High => 7.0,
                    SeverityLevel.Medium => 4.0,
                    SeverityLevel.Low => 2.0,
                    SeverityLevel.Info => 0.5,
                    _ => 0
                };

                score += severityWeight * vuln.Confidence;
            }

            // Normalize to 0-100 scale (max possible score is roughly 10 * count)
            return Math.Min(100, score);
        }

        /// <summary>
        /// Determines overall risk level from score
        /// </summary>
        private RiskLevel DetermineRiskLevel(double riskScore)
        {
            return riskScore switch
            {
                >= 70 => RiskLevel.Critical,
                >= 40 => RiskLevel.High,
                >= 20 => RiskLevel.Medium,
                >= 5 => RiskLevel.Low,
                _ => RiskLevel.Unknown
            };
        }

        public void Dispose()
        {
            Stop();
            _cancellationTokenSource.Dispose();
            _listener.Close();
        }
    }
}

