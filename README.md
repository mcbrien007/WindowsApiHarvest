# WindowsApiHarvest

Passive, read-only API endpoint discovery for Windows servers. Discovers APIs across multiple runtimes from logs, config files, and source code without modifying any server configuration.

Sends inventory to [Akamai API Security](https://www.akamai.com/products/api-security) as synthetic traffic packets via the Custom Traffic Source integration, and pushes run telemetry to Dynatrace.

---

## Supported Runtimes

| Runtime | Sources |
|---------|---------|
| **Apache Tomcat** | Access logs, web.xml servlet mappings, deployed WARs |
| **IIS** | W3SVC access logs, applicationHost.config bindings, web.config handlers |
| **Node.js** (Express/Koa) | PM2/process logs, source route scan (`app.get/post/...`) |
| **.NET Kestrel / ASP.NET Core** | Kestrel stdout logs, `[HttpGet/Post]` route attribute scan |
| **Python** (Flask/FastAPI/uvicorn) | Gunicorn/Waitress/uvicorn logs, `@app.route` / `@app.get` decorator scan |

All sources feed into a single deduplicated inventory by `host + path + method`.

---

## Requirements

- PowerShell 5.1 or later (PS 7+ recommended for TLS bypass support)
- Read access to log files and config directories
- No changes made to any server configuration

---

## Quick Start

```powershell
# Discover all APIs on this machine and print to console
.\Get-WindowsApiHarvest.ps1

# Tomcat only
.\Get-WindowsApiHarvest.ps1 -CatalinaHome "C:\apache-tomcat-10.1.54"

# Export to JSON
.\Get-WindowsApiHarvest.ps1 -OutputFormat JSON -OutputPath .\inventory.json

# Send to Akamai API Security engine
.\Get-WindowsApiHarvest.ps1 `
    -EngineUrl "https://<engine>/engine" `
    -SourceType 49 -SourceIndex 3 -SourceKey "abc123"

# Full run with Dynatrace observability
.\Get-WindowsApiHarvest.ps1 `
    -EngineUrl "https://<engine>/engine" `
    -SourceType 49 -SourceIndex 3 -SourceKey "abc123" `
    -DynatraceUrl "https://<tenant>.live.dynatrace.com" `
    -DynatraceToken "dt0c01...." `
    -Verbose
```

---

## Parameters

### Core

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-CatalinaHome` | auto-detect | Tomcat installation directory |
| `-Port` | `8080` | Port for netstat filtering and packet `tcp.dst` |
| `-LogDays` | `7` | Days of logs to scan |
| `-OutputFormat` | `Console` | `Console`, `CSV`, or `JSON` |
| `-OutputPath` | | Required for CSV/JSON output |
| `-MaxLogLines` | `500000` | Line cap per log file (prevents OOM) |

### Akamai API Security Engine

| Parameter | Description |
|-----------|-------------|
| `-EngineUrl` | HTTPS URL of the engine endpoint (requires HTTPS) |
| `-SourceType` | `sourceType` from Management API registration (default: `49`) |
| `-SourceIndex` | `sourceIndex` from Management API registration |
| `-SourceKey` | `sourceKey` from Management API registration -- required with `-EngineUrl` |
| `-BatchSize` | Packets per POST batch (default: `100`) |
| `-SkipTlsVerify` | Bypass TLS cert validation -- test environments only |

### Dynatrace

| Parameter | Description |
|-----------|-------------|
| `-DynatraceUrl` | Tenant base URL: `https://<tenant>.live.dynatrace.com` |
| `-DynatraceToken` | API token with `metrics.ingest` + `logs.ingest` scopes |

### Runtime Discovery Overrides

| Parameter | Description |
|-----------|-------------|
| `-IISLogPath` | Override IIS W3SVC log root |
| `-IISConfigPath` | Override `applicationHost.config` path |
| `-NodeLogPath` | PM2 / node process log directory |
| `-NodeAppPath` | Root directory to scan for Node.js route definitions |
| `-DotNetLogPath` | Kestrel / ASP.NET Core stdout log directory |
| `-DotNetAppPath` | Root directory to scan for .NET route attributes |
| `-PythonLogPath` | Gunicorn / uvicorn / Waitress log directory |
| `-PythonAppPath` | Root directory to scan for Flask/FastAPI route decorators |
| `-SkipIIS` | Skip all IIS discovery |
| `-SkipNode` | Skip all Node.js discovery |
| `-SkipDotNet` | Skip all .NET discovery |
| `-SkipPython` | Skip all Python discovery |

---

## Observability

Every run produces a structured run summary and emits to Dynatrace when configured.

### Dynatrace Metrics (metrics.ingest v2)

| Metric | Description |
|--------|-------------|
| `tomcat.inventory.endpoints_unique` | Unique endpoints discovered |
| `tomcat.inventory.packets_sent` | Packets sent to engine |
| `tomcat.inventory.packets_failed` | Failed engine sends |
| `tomcat.inventory.cert_days_left` | Engine TLS cert days remaining |
| `tomcat.inventory.success` | `1` = clean exit, `0` = error |
| `tomcat.inventory.duration_sec` | Total run time in seconds |
| + 5 more | log files, lines, raw endpoints, batches sent/failed |

All metrics tagged with `run.id` and `host` dimensions.

### Dynatrace Log Events (logs.ingest v2)

- 1 run summary record with all telemetry fields, severity `INFO`/`WARN`/`ERROR`
- 1 record per discovered endpoint -- queryable by `api.host`, `api.path`, `api.method`, `api.status`, `api.source`

---

## Error Codes

| Code | Meaning |
|------|---------|
| `E1001` | EngineUrl is not a valid URI |
| `E1002` | EngineUrl scheme is not HTTPS |
| `E1004` | `-SourceKey` required with `-EngineUrl` |
| `E1005` | `-OutputPath` required for CSV/JSON |
| `E2001` | Engine preflight failed -- unreachable |
| `E2002` | Engine batch POST failed |
| `E2003` | TLS certificate invalid, expired, or hostname mismatch |
| `E3001` | Tomcat log directory not found |
| `E3002` | Tomcat log file read error |
| `E3003` | Log line cap reached |
| `E4001` | webapps directory not found |
| `E4002` | web.xml parse error |
| `E4003` | server.xml parse error |
| `E4004` | Hosts file read error |
| `E5001` | No API endpoints discovered |
| `E5002` | Tomcat home not found |
| `E6001` | IIS log directory not found |
| `E6002` | IIS log file read error |
| `E6003` | IIS applicationHost.config not found or parse error |
| `E6004` | IIS web.config parse error |
| `E7001` | Node.js log directory not found |
| `E7002` | Node.js log/source read error |
| `E8001` | .NET log directory not found |
| `E8002` | .NET app/config read error |
| `E9001` | Python log directory not found |
| `E9002` | Python app/source read error |

---

## Akamai API Security Setup

1. Register a Custom Traffic Source via the Management API:
   ```
   POST /api/v3/sources/custom-integration
   ```
2. Record `sourceType`, `sourceIndex`, `sourceKey` from the response.
3. Run this script with those values and your engine URL.

---

## Security Notes

- **Read-only** -- never writes to any server config, log, or application file
- **XXE-safe** -- all XML parsed with `DtdProcessing=Prohibit` and `XmlResolver=null`
- **TLS enforced** -- engine URL must be HTTPS; cert validated and expiry reported
- **Log streaming** -- files read line-by-line with configurable line cap, never loaded fully into memory
- **Hostname validation** -- all discovered hostnames validated against `^[a-z0-9][a-z0-9._-]*$`
- **PS 5.1 compatible** -- TLS bypass scoped per-call via ServicePointManager restore pattern
