using Biosphere3.Data;
using Biosphere3.Models;
using System.Net;
using System.Text;
using System.Text.Json;

namespace Biosphere3;

public class Program
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // Add services to the container.
        builder.Services.AddControllers();
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();
        builder.Services.AddHttpClient();
        builder.Services.AddProblemDetails();

        // Register database helper
        var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
            ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
        builder.Services.AddSingleton(new DatabaseHelper(connectionString));

        var app = builder.Build();

        // Initialize database (create table + seed data)
        using (var scope = app.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<DatabaseHelper>();
            db.InitializeAsync().GetAwaiter().GetResult();
        }

        // Configure the HTTP request pipeline.
        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/error");
        }

        // Request logging
        app.Use(async (context, next) =>
        {
            Console.WriteLine($"[REQ] {DateTime.UtcNow:O} {context.Request.Method} {context.Request.Path} UA={context.Request.Headers.UserAgent}");
            await next();
        });

        // Security headers — registered before Swagger so ALL responses get headers
        app.Use(async (context, next) =>
        {
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";
            context.Response.Headers["X-Download-Options"] = "noopen";
            context.Response.Headers["X-DNS-Prefetch-Control"] = "off";
            context.Response.Headers["X-Frame-Options"] = "DENY";
            context.Response.Headers["X-XSS-Protection"] = "1; mode=block";
            context.Response.Headers["Referrer-Policy"] = "no-referrer";
            context.Response.Headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
            context.Response.Headers["X-Permitted-Cross-Domain-Policies"] = "none";
            context.Response.Headers["Cross-Origin-Opener-Policy"] = "same-origin";
            context.Response.Headers["Cross-Origin-Resource-Policy"] = "same-origin";
            context.Response.Headers["Cross-Origin-Embedder-Policy"] = "require-corp";
            context.Response.Headers["Content-Security-Policy"] =
                "default-src 'self'; " +
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com; " +
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com; " +
                "img-src 'self' data:; " +
                "connect-src 'self'; " +
                "frame-src 'self';";
            context.Response.Headers["Cache-Control"] = "no-store";
            context.Response.Headers["Pragma"] = "no-cache";
            if (context.Request.IsHttps)
            {
                context.Response.Headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
            }
            await next();
        });

        // Rate limiting — registered before Swagger so ALL requests are rate-limited
        app.Use(async (context, next) =>
        {
            var key = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var limiter = RateLimitStore.GetLimiter(key);
            var allowed = limiter.AllowRequest();
            var remaining = limiter.GetRemaining();
            var reset = limiter.GetResetSeconds();
            context.Response.Headers["RateLimit-Limit"] = "2000";
            context.Response.Headers["RateLimit-Remaining"] = remaining.ToString();
            context.Response.Headers["RateLimit-Reset"] = reset.ToString();
            context.Response.Headers["X-RateLimit-Limit"] = "2000";
            context.Response.Headers["X-RateLimit-Remaining"] = remaining.ToString();
            context.Response.Headers["X-RateLimit-Reset"] = reset.ToString();
            if (!allowed)
            {
                context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                context.Response.Headers["Retry-After"] = limiter.GetRetryAfterSeconds().ToString();
                return;
            }
            await next();
        });

        // Swagger — now AFTER security headers and rate limiting
        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
        }

        app.UseDefaultFiles();
        app.UseStaticFiles();

        app.UseHttpsRedirection();
        app.UseAuthorization();
        app.MapControllers();
        app.MapGet("/", () => Results.File(Path.Combine(app.Environment.WebRootPath ?? "wwwroot", "index.html"), "text/html"));
        app.MapGet("/lite", () => Results.File(Path.Combine(app.Environment.WebRootPath ?? "wwwroot", "index-lite.html"), "text/html"));
        app.MapGet("/full", () => Results.File(Path.Combine(app.Environment.WebRootPath ?? "wwwroot", "index.html"), "text/html"));
        app.MapGet("/full-hybrid", async (DatabaseHelper db) =>
        {
            var sensors = await db.GetAllSensorsAsync(false);
            var html = BuildHybridPage(sensors);
            return Results.Content(html, "text/html");
        });
        app.MapGet("/map", async (DatabaseHelper db) =>
        {
            var sensors = await db.GetAllSensorsAsync(false);
            var html = BuildMapPage(sensors);
            return Results.Content(html, "text/html");
        });
        app.MapGet("/bootstrap.js", async (HttpContext ctx, DatabaseHelper db) =>
        {
            var sensors = await db.GetAllSensorsAsync(false);
            var json = JsonSerializer.Serialize(sensors, JsonOptions);
            var js = $"window.__SERVER_SENSORS = {json};" +
                     $"window.__SERVER_SENSORS_TS = '{DateTime.UtcNow:O}';";
            ctx.Response.Headers["Cache-Control"] = "no-store";
            ctx.Response.Headers["Pragma"] = "no-cache";
            return Results.Content(js, "application/javascript");
        });
        app.MapGet("/server", async (DatabaseHelper db) =>
        {
            var sensors = await db.GetAllSensorsAsync(false);
            var html = BuildServerPage(sensors);
            return Results.Content(html, "text/html");
        });
        app.MapFallbackToFile("index.html");
        app.MapGet("/error", () => Results.Problem());
        app.MapGet("/ping", () => Results.Text("pong"));
        app.MapGet("/plain", () => Results.Content("<!doctype html><html><head><meta charset='utf-8'><title>Biosphere3 Plain</title></head><body style='font-family:Segoe UI, sans-serif; background:#111827; color:#e5e7eb; padding:16px;'>Biosphere3 plain page loaded.</body></html>", "text/html"));
        app.MapGet("/render", () => Results.Content("<!doctype html><html><head><meta charset='utf-8'><title>Biosphere3 Render Test</title></head><body style='font-family:Segoe UI, sans-serif; background:#000; color:#0f0; padding:24px; font-size:20px;'>RENDER TEST OK</body></html>", "text/html"));
        app.MapGet("/plain.txt", () => Results.Text("Biosphere3 plain text endpoint loaded."));
        app.MapGet("/diag", (HttpContext ctx) => Results.Json(new { ok = true, path = ctx.Request.Path.Value, host = ctx.Request.Host.Value, time = DateTime.UtcNow.ToString("O") }));

        app.Run();
    }

    private static string BuildServerPage(List<Sensor> sensors)
    {
        var sb = new StringBuilder();
        sb.Append("<!doctype html><html><head><meta charset=\"utf-8\">");
        sb.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        sb.Append("<title>Biosphere3 Server Render</title>");
        sb.Append("<style>");
        sb.Append("body{font-family:Segoe UI,Tahoma,sans-serif;background:#0d121b;color:#e5e9f0;margin:0;padding:24px;}");
        sb.Append("h1{font-size:20px;margin:0 0 6px;} .muted{color:#94a3b8;font-size:12px;}");
        sb.Append(".card{background:#111827;border:1px solid #1f2a3a;border-radius:10px;padding:16px;margin:16px 0;}");
        sb.Append("table{width:100%;border-collapse:collapse;font-size:13px;} th,td{padding:8px;border-bottom:1px solid #1f2a3a;text-align:left;}");
        sb.Append(".chip{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;}");
        sb.Append(".online{background:#0f766e;color:#e2fdf5;} .warn{background:#92400e;color:#fff7ed;} .off{background:#991b1b;color:#fee2e2;}");
        sb.Append("</style></head><body>");

        sb.Append("<h1>Biosphere3 Server Render</h1>");
        sb.Append("<div class=\"muted\">This page is server-rendered to verify data flow without client JS.</div>");
        sb.Append("<div class=\"card\">");
        sb.Append($"<strong>Sensors:</strong> {sensors.Count}");
        sb.Append("</div>");

        sb.Append("<div class=\"card\">");
        sb.Append("<h2 style=\"font-size:16px;margin:0 0 10px;\">Sensor Map (SVG)</h2>");
        sb.Append("<svg width=\"960\" height=\"360\" viewBox=\"0 0 960 360\" style=\"background:#0b0f16;border:1px solid #1f2a3a;border-radius:8px;\">");
        sb.Append("<rect x=\"0\" y=\"0\" width=\"960\" height=\"360\" fill=\"#0b0f16\" />");
        sb.Append("<g stroke=\"rgba(56,189,248,0.15)\">");
        for (var x = 0; x <= 960; x += 40) sb.Append($"<line x1=\"{x}\" y1=\"0\" x2=\"{x}\" y2=\"360\" />");
        for (var y = 0; y <= 360; y += 40) sb.Append($"<line x1=\"0\" y1=\"{y}\" x2=\"960\" y2=\"{y}\" />");
        sb.Append("</g>");

        foreach (var s in sensors)
        {
            var x = Math.Clamp((s.PosX % 50.0) / 50.0 * 960.0, 0, 960);
            var y = Math.Clamp((s.PosY % 20.0) / 20.0 * 360.0, 0, 360);
            var color = s.Status == "Offline" ? "#ef4444" : s.Status == "Warning" ? "#fbbf24" : "#22c55e";
            sb.Append($"<circle cx=\"{x:F1}\" cy=\"{y:F1}\" r=\"4\" fill=\"{color}\" />");
        }
        sb.Append("</svg>");
        sb.Append("</div>");

        sb.Append("<div class=\"card\">");
        sb.Append("<h2 style=\"font-size:16px;margin:0 0 10px;\">Sensor Table</h2>");
        if (sensors.Count == 0)
        {
            sb.Append("<div class=\"muted\">No sensors returned from database.</div>");
        }
        else
        {
            sb.Append("<table><thead><tr>");
            sb.Append("<th>ID</th><th>Name</th><th>Location</th><th>Type</th><th>Reading</th><th>Unit</th><th>Status</th>");
            sb.Append("</tr></thead><tbody>");
            foreach (var s in sensors)
            {
                var statusClass = s.Status == "Offline" ? "off" : s.Status == "Warning" ? "warn" : "online";
                sb.Append("<tr>");
                sb.Append($"<td>{s.Id}</td>");
                sb.Append($"<td>{WebUtility.HtmlEncode(s.Name)}</td>");
                sb.Append($"<td>{WebUtility.HtmlEncode(s.Location)}</td>");
                sb.Append($"<td>{WebUtility.HtmlEncode(s.Type)}</td>");
                sb.Append($"<td>{s.LastReading}</td>");
                sb.Append($"<td>{WebUtility.HtmlEncode(s.Unit)}</td>");
                sb.Append($"<td><span class=\"chip {statusClass}\">{WebUtility.HtmlEncode(s.Status)}</span></td>");
                sb.Append("</tr>");
            }
            sb.Append("</tbody></table>");
        }
        sb.Append("</div>");

        sb.Append("</body></html>");
        return sb.ToString();
    }

    private static string BuildHybridPage(List<Sensor> sensors)
    {
        var sb = new StringBuilder();
        sb.Append("<!doctype html><html><head><meta charset=\"utf-8\">");
        sb.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        sb.Append("<title>Biosphere3 Full View</title>");
        sb.Append("<script src=\"https://cdn.jsdelivr.net/npm/three@0.160.0/build/three.min.js\"></script>");
        sb.Append("<style>");
        sb.Append("body{font-family:Segoe UI,Tahoma,sans-serif;background:#0d121b;color:#e5e9f0;margin:0;padding:24px;}");
        sb.Append("h1{font-size:20px;margin:0 0 6px;} .muted{color:#94a3b8;font-size:12px;}");
        sb.Append(".grid{display:grid;grid-template-columns:1.1fr 1fr;gap:18px;}");
        sb.Append(".card{background:#111827;border:1px solid #1f2a3a;border-radius:10px;padding:16px;}");
        sb.Append("table{width:100%;border-collapse:collapse;font-size:13px;} th,td{padding:8px;border-bottom:1px solid #1f2a3a;text-align:left;}");
        sb.Append(".chip{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;}");
        sb.Append(".online{background:#0f766e;color:#e2fdf5;} .warn{background:#92400e;color:#fff7ed;} .off{background:#991b1b;color:#fee2e2;}");
        sb.Append("#threeView{width:100%;height:420px;border:1px solid #1f2a3a;border-radius:10px;background:#0b0f16;}");
        sb.Append("</style></head><body>");

        sb.Append("<h1>Biosphere3 Full View</h1>");
        sb.Append("<div class=\"muted\">Server-rendered data + client 3D (no app.js dependency).</div>");
        sb.Append("<div class=\"card\"><strong>Sensors:</strong> ");
        sb.Append(sensors.Count);
        sb.Append("</div>");

        sb.Append("<div class=\"grid\">");
        sb.Append("<div class=\"card\">");
        sb.Append("<h2 style=\"font-size:16px;margin:0 0 10px;\">3D Sensor Map</h2>");
        sb.Append("<div id=\"threeView\"></div>");
        sb.Append("</div>");

        sb.Append("<div class=\"card\">");
        sb.Append("<h2 style=\"font-size:16px;margin:0 0 10px;\">Sensor Table</h2>");
        if (sensors.Count == 0)
        {
            sb.Append("<div class=\"muted\">No sensors returned from database.</div>");
        }
        else
        {
            sb.Append("<table><thead><tr>");
            sb.Append("<th>ID</th><th>Name</th><th>Location</th><th>Type</th><th>Reading</th><th>Unit</th><th>Status</th>");
            sb.Append("</tr></thead><tbody>");
            foreach (var s in sensors)
            {
                var statusClass = s.Status == "Offline" ? "off" : s.Status == "Warning" ? "warn" : "online";
                sb.Append("<tr>");
                sb.Append($"<td>{s.Id}</td>");
                sb.Append($"<td>{WebUtility.HtmlEncode(s.Name)}</td>");
                sb.Append($"<td>{WebUtility.HtmlEncode(s.Location)}</td>");
                sb.Append($"<td>{WebUtility.HtmlEncode(s.Type)}</td>");
                sb.Append($"<td>{s.LastReading}</td>");
                sb.Append($"<td>{WebUtility.HtmlEncode(s.Unit)}</td>");
                sb.Append($"<td><span class=\"chip {statusClass}\">{WebUtility.HtmlEncode(s.Status)}</span></td>");
                sb.Append("</tr>");
            }
            sb.Append("</tbody></table>");
        }
        sb.Append("</div></div>");

        var sensorJson = JsonSerializer.Serialize(sensors, JsonOptions);
        sb.Append("<script>");
        sb.Append("const sensors = ");
        sb.Append(sensorJson);
        sb.Append(";");
        sb.Append("const host = document.getElementById('threeView');");
        sb.Append("if (host && window.THREE) {");
        sb.Append("const w = host.clientWidth || 600;");
        sb.Append("const h = host.clientHeight || 360;");
        sb.Append("const scene = new THREE.Scene();");
        sb.Append("scene.background = new THREE.Color(0x0b0f16);");
        sb.Append("const camera = new THREE.PerspectiveCamera(45, w / h, 0.1, 200);");
        sb.Append("camera.position.set(0, 22, 36);");
        sb.Append("const renderer = new THREE.WebGLRenderer({ antialias: true });");
        sb.Append("renderer.setSize(w, h);");
        sb.Append("renderer.setPixelRatio(window.devicePixelRatio || 1);");
        sb.Append("host.appendChild(renderer.domElement);");
        sb.Append("const ambient = new THREE.AmbientLight(0x94a3b8, 0.7); scene.add(ambient);");
        sb.Append("const dir = new THREE.DirectionalLight(0xffffff, 0.9); dir.position.set(20, 30, 10); scene.add(dir);");
        sb.Append("const grid = new THREE.GridHelper(60, 20, 0x38bdf8, 0x1f2a3a); scene.add(grid);");
        sb.Append("const group = new THREE.Group(); scene.add(group);");
        sb.Append("sensors.forEach(s => {");
        sb.Append("const geometry = new THREE.SphereGeometry(0.6, 16, 16);");
        sb.Append("const color = s.status === 'Offline' ? 0xef4444 : s.status === 'Warning' ? 0xfbbf24 : 0x22c55e;");
        sb.Append("const material = new THREE.MeshStandardMaterial({ color });");
        sb.Append("const mesh = new THREE.Mesh(geometry, material);");
        sb.Append("mesh.position.set((s.posX || 0) - 25, (s.posZ || 0), (s.posY || 0) - 10);");
        sb.Append("group.add(mesh);");
        sb.Append("});");
        sb.Append("let t = 0; const animate = () => { t += 0.003; group.rotation.y = t; renderer.render(scene, camera); requestAnimationFrame(animate); }; animate();");
        sb.Append("} else if (host) { host.innerHTML = '<div class=\"muted\">Three.js unavailable. Check CDN access.</div>'; }");
        sb.Append("</script>");

        sb.Append("</body></html>");
        return sb.ToString();
    }

    private static string BuildMapPage(List<Sensor> sensors)
    {
        var sb = new StringBuilder();
        sb.Append("<!doctype html><html><head><meta charset=\"utf-8\">");
        sb.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        sb.Append("<title>Biosphere Map</title>");
        sb.Append("<script src=\"https://cdn.jsdelivr.net/npm/three@0.160.0/build/three.min.js\"></script>");
        sb.Append("<style>");
        sb.Append("html,body{height:100%;margin:0;background:#0b0f16;}");
        sb.Append("#root{width:100%;height:100%;}");
        sb.Append("</style></head><body>");
        sb.Append("<div id=\"root\"></div>");

        var sensorJson = JsonSerializer.Serialize(sensors, JsonOptions);
        sb.Append("<script>");
        sb.Append("const sensors = ");
        sb.Append(sensorJson);
        sb.Append(";");
        sb.Append("const host = document.getElementById('root');");
        sb.Append("if (host && window.THREE) {");
        sb.Append("const w = host.clientWidth || 600;");
        sb.Append("const h = host.clientHeight || 360;");
        sb.Append("const scene = new THREE.Scene();");
        sb.Append("scene.background = new THREE.Color(0x0b0f16);");
        sb.Append("const camera = new THREE.PerspectiveCamera(45, w / h, 0.1, 200);");
        sb.Append("camera.position.set(0, 24, 40);");
        sb.Append("camera.lookAt(0, 6, 0);");
        sb.Append("const renderer = new THREE.WebGLRenderer({ antialias: true });");
        sb.Append("renderer.setSize(w, h);");
        sb.Append("renderer.setPixelRatio(window.devicePixelRatio || 1);");
        sb.Append("host.appendChild(renderer.domElement);");
        sb.Append("const ambient = new THREE.AmbientLight(0x94a3b8, 0.65); scene.add(ambient);");
        sb.Append("const dir = new THREE.DirectionalLight(0xffffff, 0.9); dir.position.set(20, 30, 10); scene.add(dir);");
        sb.Append("const grid = new THREE.GridHelper(70, 28, 0x38bdf8, 0x1f2a3a); scene.add(grid);");
        sb.Append("const base = new THREE.Mesh(new THREE.PlaneGeometry(70, 40), new THREE.MeshStandardMaterial({ color: 0x0b1220, roughness: 0.8, metalness: 0.1 }));");
        sb.Append("base.rotation.x = -Math.PI / 2; base.position.y = -0.02; scene.add(base);");
        sb.Append("const shellMat = new THREE.MeshStandardMaterial({ color: 0x2dd4bf, transparent: true, opacity: 0.18, roughness: 0.2 });");
        sb.Append("const frameMat = new THREE.MeshStandardMaterial({ color: 0x38bdf8, transparent: true, opacity: 0.35, wireframe: true });");
        sb.Append("const domeA = new THREE.Mesh(new THREE.SphereGeometry(9, 32, 20, 0, Math.PI * 2, 0, Math.PI / 2), shellMat); domeA.position.set(-14, 6, -6); scene.add(domeA);");
        sb.Append("const domeAFrame = new THREE.Mesh(new THREE.SphereGeometry(9, 16, 12, 0, Math.PI * 2, 0, Math.PI / 2), frameMat); domeAFrame.position.copy(domeA.position); scene.add(domeAFrame);");
        sb.Append("const domeB = new THREE.Mesh(new THREE.SphereGeometry(8, 32, 20, 0, Math.PI * 2, 0, Math.PI / 2), shellMat); domeB.position.set(10, 5.5, -4); scene.add(domeB);");
        sb.Append("const domeBFrame = new THREE.Mesh(new THREE.SphereGeometry(8, 16, 12, 0, Math.PI * 2, 0, Math.PI / 2), frameMat); domeBFrame.position.copy(domeB.position); scene.add(domeBFrame);");
        sb.Append("const domeC = new THREE.Mesh(new THREE.SphereGeometry(6.5, 28, 18, 0, Math.PI * 2, 0, Math.PI / 2), shellMat); domeC.position.set(16, 4.5, 9); scene.add(domeC);");
        sb.Append("const domeCFrame = new THREE.Mesh(new THREE.SphereGeometry(6.5, 16, 10, 0, Math.PI * 2, 0, Math.PI / 2), frameMat); domeCFrame.position.copy(domeC.position); scene.add(domeCFrame);");
        sb.Append("const greenhouse = new THREE.Mesh(new THREE.BoxGeometry(12, 3.5, 6), new THREE.MeshStandardMaterial({ color: 0x1e293b, transparent: true, opacity: 0.5 })); greenhouse.position.set(-2, 1.8, 10); scene.add(greenhouse);");
        sb.Append("const greenhouseFrame = new THREE.Mesh(new THREE.BoxGeometry(12.2, 3.6, 6.2), frameMat); greenhouseFrame.position.copy(greenhouse.position); scene.add(greenhouseFrame);");
        sb.Append("const hub = new THREE.Mesh(new THREE.CylinderGeometry(2.2, 2.2, 3.2, 16), new THREE.MeshStandardMaterial({ color: 0x0ea5e9 })); hub.position.set(-2, 1.6, 0); scene.add(hub);");
        sb.Append("const sensorGroup = new THREE.Group(); scene.add(sensorGroup);");
        sb.Append("sensors.forEach(s => {");
        sb.Append("const geometry = new THREE.SphereGeometry(0.6, 16, 16);");
        sb.Append("const color = s.status === 'Offline' ? 0xef4444 : s.status === 'Warning' ? 0xfbbf24 : 0x22c55e;");
        sb.Append("const material = new THREE.MeshStandardMaterial({ color, emissive: 0x0, roughness: 0.4 });");
        sb.Append("const mesh = new THREE.Mesh(geometry, material);");
        sb.Append("mesh.position.set((s.posX || 0) - 25, (s.posZ || 0) + 0.8, (s.posY || 0) - 10);");
        sb.Append("sensorGroup.add(mesh);");
        sb.Append("});");
        sb.Append("const render = () => { renderer.render(scene, camera); requestAnimationFrame(render); }; render();");
        sb.Append("}");
        sb.Append("</script>");
        sb.Append("</body></html>");
        return sb.ToString();
    }
}
