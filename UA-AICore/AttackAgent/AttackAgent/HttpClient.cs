using System.Net;
using System.Text;
using System.Text.Json;
using Serilog;

namespace AttackAgent
{
    /// <summary>
    /// Custom HTTP client for making requests to target applications
    /// with security testing capabilities and intelligent request handling
    /// </summary>
    public class SecurityHttpClient
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public SecurityHttpClient(string baseUrl = "")
        {
            _logger = Log.ForContext<SecurityHttpClient>();
            
            // Configure HttpClient with security testing capabilities
            // Bypass SSL certificate validation for security testing purposes
            var handler = new HttpClientHandler()
            {
                AllowAutoRedirect = true,
                MaxAutomaticRedirections = 5,
                UseCookies = true,
                CookieContainer = new CookieContainer(),
                ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
            };

            _httpClient = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30),
                BaseAddress = !string.IsNullOrEmpty(baseUrl) ? new Uri(baseUrl) : null
            };

            // Set default headers to mimic a real browser
            _httpClient.DefaultRequestHeaders.Add("User-Agent", 
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
            _httpClient.DefaultRequestHeaders.Add("Accept", 
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
            _httpClient.DefaultRequestHeaders.Add("Accept-Language", "en-US,en;q=0.5");
            _httpClient.DefaultRequestHeaders.Add("Accept-Encoding", "gzip, deflate");
            _httpClient.DefaultRequestHeaders.Add("Connection", "keep-alive");
            _httpClient.DefaultRequestHeaders.Add("Upgrade-Insecure-Requests", "1");
        }

        /// <summary>
        /// Makes a GET request to the specified URL
        /// </summary>
        public async Task<HttpResponse> GetAsync(string url, Dictionary<string, string>? headers = null)
        {
            return await MakeRequestAsync(HttpMethod.Get, url, null, headers);
        }

        /// <summary>
        /// Makes a POST request to the specified URL with the given data
        /// </summary>
        public async Task<HttpResponse> PostAsync(string url, string? data = null, 
            Dictionary<string, string>? headers = null, string contentType = "application/json")
        {
            return await MakeRequestAsync(HttpMethod.Post, url, data, headers, contentType);
        }

        /// <summary>
        /// Makes a PUT request to the specified URL with the given data
        /// </summary>
        public async Task<HttpResponse> PutAsync(string url, string? data = null, 
            Dictionary<string, string>? headers = null, string contentType = "application/json")
        {
            return await MakeRequestAsync(HttpMethod.Put, url, data, headers, contentType);
        }

        /// <summary>
        /// Makes a DELETE request to the specified URL
        /// </summary>
        public async Task<HttpResponse> DeleteAsync(string url, Dictionary<string, string>? headers = null)
        {
            return await MakeRequestAsync(HttpMethod.Delete, url, null, headers);
        }

        /// <summary>
        /// Makes a custom HTTP request with the specified method and parameters
        /// </summary>
        public async Task<HttpResponse> MakeRequestAsync(HttpMethod method, string url, string? data = null, 
            Dictionary<string, string>? headers = null, string contentType = "application/json")
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            
            try
            {
                _logger.Debug("Making {Method} request to {Url}", method, url);

                // Ensure we have an absolute URI
                Uri requestUri;
                if (Uri.IsWellFormedUriString(url, UriKind.Absolute))
                {
                    requestUri = new Uri(url);
                }
                else if (!string.IsNullOrEmpty(_httpClient.BaseAddress?.ToString()))
                {
                    requestUri = new Uri(_httpClient.BaseAddress, url);
                }
                else
                {
                    throw new InvalidOperationException($"Cannot make request to relative URL '{url}' without BaseAddress set");
                }

                using var request = new HttpRequestMessage(method, requestUri);

                // Add custom headers
                if (headers != null)
                {
                    foreach (var header in headers)
                    {
                        try
                        {
                            request.Headers.Add(header.Key, header.Value);
                        }
                        catch (Exception ex)
                        {
                            _logger.Warning("Failed to add header {Header}: {Error}", header.Key, ex.Message);
                        }
                    }
                }

                // Add request body for POST/PUT requests
                if (!string.IsNullOrEmpty(data) && (method == HttpMethod.Post || method == HttpMethod.Put))
                {
                    request.Content = new StringContent(data, Encoding.UTF8, contentType);
                }

                // Make the request
                var response = await _httpClient.SendAsync(request);
                stopwatch.Stop();

                // Read response content
                var content = await response.Content.ReadAsStringAsync();
                var responseHeaders = new Dictionary<string, string>();
                
                foreach (var header in response.Headers)
                {
                    responseHeaders[header.Key] = string.Join(", ", header.Value);
                }

                foreach (var header in response.Content.Headers)
                {
                    responseHeaders[header.Key] = string.Join(", ", header.Value);
                }

                var httpResponse = new HttpResponse
                {
                    StatusCode = response.StatusCode,
                    Content = content,
                    Headers = responseHeaders,
                    ResponseTime = stopwatch.Elapsed,
                    Url = url,
                    Method = method.Method,
                    Success = response.IsSuccessStatusCode
                };

                _logger.Debug("Request completed: {StatusCode} in {ResponseTime}ms", 
                    response.StatusCode, stopwatch.ElapsedMilliseconds);

                return httpResponse;
            }
            catch (HttpRequestException ex)
            {
                stopwatch.Stop();
                _logger.Warning("HTTP request failed for {Url}: {Error}", url, ex.Message);
                
                return new HttpResponse
                {
                    StatusCode = HttpStatusCode.ServiceUnavailable,
                    Content = ex.Message,
                    Headers = new Dictionary<string, string>(),
                    ResponseTime = stopwatch.Elapsed,
                    Url = url,
                    Method = method.Method,
                    Success = false,
                    Error = ex.Message
                };
            }
            catch (TaskCanceledException ex)
            {
                stopwatch.Stop();
                _logger.Warning("Request timeout for {Url}: {Error}", url, ex.Message);
                
                return new HttpResponse
                {
                    StatusCode = HttpStatusCode.RequestTimeout,
                    Content = "Request timeout",
                    Headers = new Dictionary<string, string>(),
                    ResponseTime = stopwatch.Elapsed,
                    Url = url,
                    Method = method.Method,
                    Success = false,
                    Error = "Request timeout"
                };
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                _logger.Error(ex, "Unexpected error making request to {Url}", url);
                
                return new HttpResponse
                {
                    StatusCode = HttpStatusCode.InternalServerError,
                    Content = ex.Message,
                    Headers = new Dictionary<string, string>(),
                    ResponseTime = stopwatch.Elapsed,
                    Url = url,
                    Method = method.Method,
                    Success = false,
                    Error = ex.Message
                };
            }
        }

        /// <summary>
        /// Tests if a URL is accessible
        /// </summary>
        public async Task<bool> IsAccessibleAsync(string url)
        {
            try
            {
                var response = await GetAsync(url);
                return response.Success;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Gets the base URL from a full URL
        /// </summary>
        public static string GetBaseUrl(string url)
        {
            try
            {
                var uri = new Uri(url);
                return $"{uri.Scheme}://{uri.Host}:{uri.Port}";
            }
            catch
            {
                return url;
            }
        }

        /// <summary>
        /// Makes a PATCH request to the specified URL
        /// </summary>
        public async Task<HttpResponse> HeadAsync(string url, Dictionary<string, string>? headers = null)
        {
            return await MakeRequestAsync(HttpMethod.Head, url, null, headers);
        }

        public async Task<HttpResponse> OptionsAsync(string url, Dictionary<string, string>? headers = null)
        {
            return await MakeRequestAsync(HttpMethod.Options, url, null, headers);
        }

        public async Task<HttpResponse> PatchAsync(string url, string data, Dictionary<string, string>? headers = null)
        {
            return await MakeRequestAsync(HttpMethod.Patch, url, data, headers);
        }

        /// <summary>
        /// Sends a custom HTTP request message
        /// </summary>
        public async Task<HttpResponse> SendAsync(HttpRequestMessage request)
        {
            var startTime = DateTime.UtcNow;
            
            try
            {
                var response = await _httpClient.SendAsync(request);
                var content = await response.Content.ReadAsStringAsync();
                var responseTime = DateTime.UtcNow - startTime;
                
                return new HttpResponse
                {
                    Success = response.IsSuccessStatusCode,
                    StatusCode = response.StatusCode,
                    Content = content,
                    ResponseTime = responseTime,
                    Headers = response.Headers.ToDictionary(h => h.Key, h => string.Join(", ", h.Value))
                };
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error sending HTTP request to {Url}", request.RequestUri);
                return new HttpResponse
                {
                    Success = false,
                    StatusCode = HttpStatusCode.InternalServerError,
                    Content = ex.Message,
                    ResponseTime = DateTime.UtcNow - startTime,
                    Headers = new Dictionary<string, string>()
                };
            }
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }

    /// <summary>
    /// Represents an HTTP response with additional metadata
    /// </summary>
    public class HttpResponse
    {
        public HttpStatusCode StatusCode { get; set; }
        public string Content { get; set; } = string.Empty;
        public Dictionary<string, string> Headers { get; set; } = new();
        public TimeSpan ResponseTime { get; set; }
        public string Url { get; set; } = string.Empty;
        public string Method { get; set; } = string.Empty;
        public bool Success { get; set; }
        public string? Error { get; set; }

        /// <summary>
        /// Gets the content length
        /// </summary>
        public int ContentLength => Content?.Length ?? 0;

        /// <summary>
        /// Checks if the response contains a specific string
        /// </summary>
        public bool Contains(string text, StringComparison comparison = StringComparison.OrdinalIgnoreCase)
        {
            return Content?.Contains(text, comparison) ?? false;
        }

        /// <summary>
        /// Gets a specific header value
        /// </summary>
        public string? GetHeader(string name)
        {
            return Headers.TryGetValue(name, out var value) ? value : null;
        }

        /// <summary>
        /// Checks if a specific header exists
        /// </summary>
        public bool HasHeader(string name)
        {
            return Headers.ContainsKey(name);
        }

        /// <summary>
        /// Gets the response as JSON
        /// </summary>
        public T? GetJson<T>()
        {
            try
            {
                return JsonSerializer.Deserialize<T>(Content);
            }
            catch
            {
                return default;
            }
        }
    }
}
