# Biosphere3 - 10,000 Sensor Activity Monitoring System

Full-stack .NET 9 web application built as part of the **AI Core Full Stack Coding Work Plan**. Biosphere3 simulates a biosphere habitat monitoring system with 10,000 sensors, featuring CRUD operations, real-time 3D visualization, an AI chatbot, and security hardening.

## Tech Stack

- **Backend:** ASP.NET Core 9, raw ADO.NET (no Entity Framework)
- **Database:** SQL Server (hosted on site4now.net)
- **Frontend:** Vanilla HTML/CSS/JS, Three.js r147 (3D), Chart.js
- **API Docs:** Swagger / OpenAPI via Swashbuckle
- **AI:** OpenAI GPT-4o-mini (server-side proxy)
- **Security Testing:** AttackAgent (.NET 9 console app)

## Work Plan Phases

### Phase 1: CRUD Application
- ASP.NET Core Web API with Controllers
- SQL Server with raw ADO.NET (`Microsoft.Data.SqlClient`)
- Full CRUD: Create, Read, Update, Delete, Archive/Restore, Bulk Import
- Swagger UI for API documentation
- Static HTML/CSS/JS dashboard with sensor table, 3D map, waveforms, mini-map

### Phase 2: API Programming
- OpenAI ChatBot integration via `POST /api/chat`
- Server-side proxy to GPT-4o-mini (API key never exposed to client)
- Chat UI embedded in dashboard

### Phase 3: Security
- AttackAgent security scanner (15+ attack types, 6 scan phases)
- Vulnerability report generation (JSON, PDF, executive summary)
- Remediation cycle: scan -> fix -> re-scan until 0 vulnerabilities
- Security hardening applied:
  - HTTPS redirection (all environments)
  - HSTS (`Strict-Transport-Security`)
  - 12 security headers (CSP, X-Frame-Options, X-Content-Type-Options, etc.)
  - Rate limiting (2000 req/min per IP)
  - Middleware ordering fix (headers/rate-limiting before Swagger)

## Getting Started

### Prerequisites
- [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
- SQL Server instance (or use the provided remote DB)
- OpenAI API key (for Phase 2 chatbot)

### Setup

1. Clone the repo:
   ```bash
   git clone https://github.com/TSchimmels/Biosphere3.git
   cd Biosphere3
   ```

2. Copy the secrets template and fill in your credentials:
   ```bash
   cp appsettings.Development.template.json appsettings.Development.json
   ```
   Edit `appsettings.Development.json` with your SQL Server connection string and OpenAI API key.

3. Run the application:
   ```bash
   dotnet run --launch-profile https
   ```

4. Open in browser:
   - **Dashboard:** https://localhost:7182
   - **Swagger:** https://localhost:7182/swagger
   - **API:** https://localhost:7182/api/sensors

### Running AttackAgent (Phase 3)

```bash
cd UA-AICore/AttackAgent/AttackAgent
dotnet run -- https://localhost:7182 --verbose
```

Reports are generated in `reports/` (PDF, JSON, executive summary).

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/sensors` | List all active sensors |
| GET | `/api/sensors/{id}` | Get sensor by ID |
| POST | `/api/sensors` | Create sensor |
| PUT | `/api/sensors/{id}` | Update sensor |
| DELETE | `/api/sensors/{id}` | Soft-delete (archive) sensor |
| PATCH | `/api/sensors/{id}/restore` | Restore archived sensor |
| POST | `/api/sensors/import` | Bulk import sensors |
| GET | `/HelloWorld` | Hello World endpoint |
| POST | `/api/chat` | AI chatbot (GPT-4o-mini) |
| GET | `/swagger` | Swagger UI |

## Project Structure

```
Biosphere3/
  Controllers/        # API controllers (Sensors, Chat, HelloWorld)
  Data/               # DatabaseHelper (ADO.NET)
  Models/             # Sensor model
  Properties/         # Launch settings (HTTP + HTTPS profiles)
  wwwroot/            # Static frontend (HTML, CSS, JS)
  Program.cs          # App config, middleware pipeline
  RateLimitStore.cs   # Fixed-window rate limiter
  UA-AICore/
    AttackAgent/      # Security scanner (Phase 3)
```

## Security Headers

All responses include:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Content-Security-Policy` (restrictive)
- `Strict-Transport-Security` (HTTPS only)
- `Referrer-Policy: no-referrer`
- `Permissions-Policy` (camera, mic, geo disabled)
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Resource-Policy: same-origin`
- `Cross-Origin-Embedder-Policy: require-corp`
- `RateLimit-Limit` / `RateLimit-Remaining` / `RateLimit-Reset`
