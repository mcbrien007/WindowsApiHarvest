<#
.SYNOPSIS
    Builds an API endpoint inventory from a Windows Tomcat server by combining
    multiple discovery sources: access logs, deployed WAR/servlet mappings,
    web.xml descriptors, and live netstat connections.

.DESCRIPTION
    Interrogates the local Tomcat installation and produces a deduplicated list
    of { Host, Path, Method } tuples representing discovered API endpoints.
    Output can be printed to the console, exported to CSV/JSON, or POSTed
    directly to an Akamai API Security engine as inventory-only packets.

    Discovery sources (all optional - script uses whatever is available):
      1. Tomcat access logs       - real observed host/path/method from traffic
      2. web.xml servlet mappings - declared URL patterns per deployed app
      3. WAR file manifests       - app context roots from deployed WARs
      4. Netstat                  - active TCP connections on the Tomcat port

    Error codes:
      E1001  EngineUrl is not a valid URI
      E1002  EngineUrl scheme is not HTTPS
      E1004  -SourceKey is required when -EngineUrl is provided
      E1005  -OutputPath is required for CSV/JSON output
      E2001  Engine preflight failed - cannot reach engine
      E2002  Engine batch POST failed
      E2003  TLS certificate invalid (expired, untrusted, or hostname mismatch)
      E3001  Log directory not found
      E3002  Log file read error
      E3003  Log line cap reached
      E4001  webapps directory not found
      E4002  web.xml parse error
      E4003  server.xml parse error
      E4004  hosts file read error
      E5001  No API endpoints discovered
      E5002  Tomcat home not found
      E6001  IIS log directory not found
      E6002  IIS log file read error
      E6003  IIS applicationHost.config not found or parse error
      E6004  IIS web.config parse error
      E7001  Node.js log directory not found
      E7002  Node.js log/app read error
      E8001  .NET Kestrel log directory not found
      E8002  .NET app/config read error
      E9001  Python log directory not found
      E9002  Python app/config read error

.PARAMETER CatalinaHome
    Path to the Tomcat installation directory.
    Defaults to the CATALINA_HOME environment variable, then common install paths.

.PARAMETER Port
    The HTTP/HTTPS port Tomcat is listening on. Used for netstat filtering.
    Default: 8080

.PARAMETER LogDays
    How many days back to scan access logs. Default: 7

.PARAMETER OutputFormat
    Console (default), CSV, or JSON.

.PARAMETER OutputPath
    File path for CSV or JSON output. Required when OutputFormat is CSV or JSON.

.PARAMETER EngineUrl
    If provided, POST inventory packets to this Akamai API Security engine URL.

.PARAMETER SourceType
    sourceType from the Management API registration. Required with EngineUrl.

.PARAMETER SourceIndex
    sourceIndex from the Management API registration. Required with EngineUrl.

.PARAMETER SourceKey
    sourceKey from the Management API registration. Required with EngineUrl.

.PARAMETER SkipTlsVerify
    Skip TLS certificate verification when posting to the engine. Use only in
    test environments.

.PARAMETER BatchSize
    Number of packets to send per HTTP POST to the engine. Default: 100

.PARAMETER MaxLogLines
    Maximum lines to read per log file. Prevents OOM on very large logs. Default: 500000

.PARAMETER DynatraceUrl
    Dynatrace tenant base URL, e.g. https://<tenant>.live.dynatrace.com
    When provided, run metrics and a log event are pushed to Dynatrace at exit.

.PARAMETER DynatraceToken
    Dynatrace API token. Required scopes: metrics.ingest, logs.ingest.

.EXAMPLE
    # Print discovered endpoints to console
    .\Get-TomcatApiInventory.ps1

.EXAMPLE
    # Export to JSON
    .\Get-TomcatApiInventory.ps1 -OutputFormat JSON -OutputPath .\inventory.json

.EXAMPLE
    # Post to Akamai API Security engine
    .\Get-TomcatApiInventory.ps1 -EngineUrl "https://engine/engine" `
        -SourceType 49 -SourceIndex 3 -SourceKey "abc123"

.EXAMPLE
    # Full verbose run with custom batch size
    .\Get-TomcatApiInventory.ps1 -EngineUrl "https://engine/engine" `
        -SourceType 49 -SourceIndex 3 -SourceKey "abc123" `
        -BatchSize 50 -Verbose
#>

[CmdletBinding()]
param(
    [string]  $CatalinaHome    = "",
    [int]     $Port            = 8080,
    [int]     $LogDays         = 7,
    [ValidateSet("Console","CSV","JSON")]
    [string]  $OutputFormat    = "Console",
    [string]  $OutputPath      = "",
    [string]  $EngineUrl       = "",
    [int]     $SourceType      = 49,
    [int]     $SourceIndex     = 0,
    [string]  $SourceKey       = "",
    [switch]  $SkipTlsVerify,
    [int]     $MaxLogLines     = 500000,
    [int]     $BatchSize       = 100,

    # Dynatrace observability (optional)
    # DynatraceUrl  : https://<tenant>.live.dynatrace.com  OR  https://<activegate>/e/<env-id>
    # DynatraceToken: API token with metrics.ingest + logs.ingest scopes
    [string]  $DynatraceUrl   = "",
    [string]  $DynatraceToken = "",

    # Additional runtime discovery (all optional - auto-detected when not specified)
    [string]  $IISLogPath     = "",   # Override IIS W3SVC log root (default: %SystemDrive%\inetpub\logs\LogFiles)
    [string]  $IISConfigPath  = "",   # Override applicationHost.config path
    [string]  $NodeLogPath    = "",   # PM2 / node log directory
    [string]  $NodeAppPath    = "",   # Root of Node.js apps to scan for routes
    [string]  $DotNetLogPath  = "",   # Kestrel / ASP.NET Core stdout log directory
    [string]  $DotNetAppPath  = "",   # Root of .NET apps (looks for launchSettings.json)
    [string]  $PythonLogPath  = "",   # Waitress / Gunicorn / uvicorn log directory
    [string]  $PythonAppPath  = "",   # Root of Python apps to scan for Flask/FastAPI routes
    [switch]  $SkipIIS,               # Skip IIS discovery
    [switch]  $SkipNode,              # Skip Node.js discovery
    [switch]  $SkipDotNet,            # Skip .NET Kestrel discovery
    [switch]  $SkipPython             # Skip Python discovery
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# PS 5.1 TLS bypass helper
# PS 6+: use -SkipCertificateCheck (per-call, safe)
# PS 5.1: temporarily override ServicePointManager callback, then restore
# ---------------------------------------------------------------------------

function Invoke-RestSkipTls {
    param([hashtable]$Args_)
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $Args_['SkipCertificateCheck'] = $true
        return Invoke-RestMethod @Args_
    } else {
        $prev = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        try {
            return Invoke-RestMethod @Args_
        } finally {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $prev
        }
    }
}

# ---------------------------------------------------------------------------
# Observability: structured logging, timing, and run telemetry
# ---------------------------------------------------------------------------

$Script:RunStart   = Get-Date
$Script:ErrorCodes = [System.Collections.Generic.List[string]]::new()
$Script:Telemetry  = [ordered]@{
    RunId           = [System.Guid]::NewGuid().ToString('N').Substring(0,8).ToUpper()
    StartTime       = $Script:RunStart.ToString('o')
    Host_           = $env:COMPUTERNAME
    PSVersion       = $PSVersionTable.PSVersion.ToString()
    CatalinaHome    = ""
    LogFilesScanned = 0
    LogLinesRead    = 0
    LogLineCapped   = $false
    EndpointsRaw    = 0
    EndpointsUnique = 0
    EngineUrl       = $EngineUrl
    CertSubject     = ""
    CertExpiry      = ""
    CertDaysLeft    = ""
    PacketsSent     = 0
    PacketsFailed   = 0
    BatchesSent     = 0
    BatchesFailed   = 0
    ErrorCodes      = ""
    DurationSec     = 0
    ExitCode        = 0
}

function Write-Log {
    param(
        [string] $Level,      # INFO | WARN | ERROR
        [string] $Message,
        [string] $Code = ""   # E-code, e.g. "E3002"
    )
    $ts     = (Get-Date).ToString('HH:mm:ss.fff')
    $prefix = if ($Code) { "[$Code] " } else { "" }
    $line   = "$ts  $Level  $prefix$Message"

    switch ($Level) {
        "ERROR" {
            Write-Host $line -ForegroundColor Red
            if ($Code) { $Script:ErrorCodes.Add($Code) }
        }
        "WARN"  { Write-Host $line -ForegroundColor Yellow }
        default { Write-Host $line -ForegroundColor White  }
    }
}

function Write-Header([string]$text) {
    Write-Host ""
    Write-Host "=== $text ===" -ForegroundColor Cyan
}

function Get-Elapsed {
    return [math]::Round(((Get-Date) - $Script:RunStart).TotalSeconds, 2)
}

function Write-RunSummary {
    $Script:Telemetry['DurationSec']  = Get-Elapsed
    $Script:Telemetry['ErrorCodes']   = ($Script:ErrorCodes | Select-Object -Unique) -join ', '

    Write-Host ""
    Write-Host "======================================================" -ForegroundColor Cyan
    Write-Host "               RUN SUMMARY" -ForegroundColor Cyan
    Write-Host "======================================================" -ForegroundColor Cyan
    $t = $Script:Telemetry
    Write-Host "  Run ID         : $($t['RunId'])"
    Write-Host "  Host           : $($t['Host_'])"
    Write-Host "  PS Version     : $($t['PSVersion'])"
    Write-Host "  Catalina Home  : $($t['CatalinaHome'])"
    Write-Host "  Duration       : $($t['DurationSec'])s"
    Write-Host ""
    Write-Host "  Log files      : $($t['LogFilesScanned'])"
    Write-Host "  Log lines read : $($t['LogLinesRead'])"
    Write-Host "  Line cap hit   : $($t['LogLineCapped'])"
    Write-Host "  Raw endpoints  : $($t['EndpointsRaw'])"
    Write-Host "  Unique endpoints: $($t['EndpointsUnique'])"
    if ($t['EngineUrl']) {
        Write-Host ""
        Write-Host "  Engine URL     : $($t['EngineUrl'])"
        if ($t['CertSubject']) {
            Write-Host "  Cert subject   : $($t['CertSubject'])"
            $certColor = if ($t['CertDaysLeft'] -gt 30) { "Green" } elseif ($t['CertDaysLeft'] -gt 7) { "Yellow" } else { "Red" }
            Write-Host "  Cert expiry    : $($t['CertExpiry'])  ($($t['CertDaysLeft']) days left)" -ForegroundColor $certColor
        }
        Write-Host "  Packets sent   : $($t['PacketsSent'])"
        Write-Host "  Packets failed : $($t['PacketsFailed'])"
        Write-Host "  Batches sent   : $($t['BatchesSent'])"
        Write-Host "  Batches failed : $($t['BatchesFailed'])"
    }
    if ($t['ErrorCodes']) {
        Write-Host ""
        Write-Host "  Error codes    : $($t['ErrorCodes'])" -ForegroundColor Red
    } else {
        Write-Host ""
        Write-Host "  Error codes    : none" -ForegroundColor Green
    }
    Write-Host "  Exit code      : $($t['ExitCode'])"
    Write-Host ""
}

function Exit-Script([int]$code) {
    $Script:Telemetry['ExitCode'] = $code
    Write-RunSummary
    if ($DynatraceUrl -and $DynatraceToken) {
        Send-ToDynatrace
    }
    exit $code
}

# ---------------------------------------------------------------------------
# Dynatrace observability: metrics ingest v2 + log ingest v2
# Metrics: all numeric telemetry counters as gauges, tagged with run.id
# Log:     full telemetry as a single structured log event
# ---------------------------------------------------------------------------

function Send-ToDynatrace {
    $t       = $Script:Telemetry
    $baseUrl = $DynatraceUrl.TrimEnd('/')
    $headers = @{
        'Authorization' = 'Api-Token ' + $DynatraceToken
        'Content-Type'  = 'text/plain; charset=utf-8'
    }

    # ------------------------------------------------------------------
    # Metrics (Dynatrace Metrics Ingest v2 line protocol)
    # Format: metric.key,dim1=val1,dim2=val2 gauge,<value> <timestamp_ms>
    # ------------------------------------------------------------------
    $tsMs    = [long]([double]::Parse((Get-Date -UFormat %s)) * 1000)
    $runId   = $t['RunId']
    $host_   = $t['Host_'] -replace '[^a-zA-Z0-9._-]', '_'
    $dims    = "run.id=$runId,host=$host_"
    $success = if ($t['ExitCode'] -eq 0) { 1 } else { 0 }

    $lines = @(
        "tomcat.inventory.log_files_scanned,$dims gauge,$($t['LogFilesScanned']) $tsMs",
        "tomcat.inventory.log_lines_read,$dims gauge,$($t['LogLinesRead']) $tsMs",
        "tomcat.inventory.endpoints_raw,$dims gauge,$($t['EndpointsRaw']) $tsMs",
        "tomcat.inventory.endpoints_unique,$dims gauge,$($t['EndpointsUnique']) $tsMs",
        "tomcat.inventory.packets_sent,$dims gauge,$($t['PacketsSent']) $tsMs",
        "tomcat.inventory.packets_failed,$dims gauge,$($t['PacketsFailed']) $tsMs",
        "tomcat.inventory.batches_sent,$dims gauge,$($t['BatchesSent']) $tsMs",
        "tomcat.inventory.batches_failed,$dims gauge,$($t['BatchesFailed']) $tsMs",
        "tomcat.inventory.duration_sec,$dims gauge,$($t['DurationSec']) $tsMs",
        "tomcat.inventory.success,$dims gauge,$success $tsMs"
    )

    if ($t['CertDaysLeft'] -ne '') {
        $lines += "tomcat.inventory.cert_days_left,$dims gauge,$($t['CertDaysLeft']) $tsMs"
    }

    try {
        $metricsUrl  = $baseUrl + '/api/v2/metrics/ingest'
        $metricsBody = $lines -join "`n"
        $mArgs = @{
            Uri     = $metricsUrl
            Method  = 'POST'
            Headers = $headers
            Body    = $metricsBody
            ErrorAction = 'Stop'
        }
        Invoke-RestMethod @mArgs | Out-Null
        Write-Log INFO ("Dynatrace: " + $lines.Count + " metrics sent to " + $metricsUrl)
    } catch {
        Write-Log WARN ("Dynatrace metrics ingest failed: " + $_)
    }

    # ------------------------------------------------------------------
    # Log event (Dynatrace Log Ingest v2)
    # Single JSON array with one structured log record
    # ------------------------------------------------------------------
    $logHeaders = @{
        'Authorization' = 'Api-Token ' + $DynatraceToken
        'Content-Type'  = 'application/json; charset=utf-8'
    }

    $errorCodesVal = if ($t['ErrorCodes']) { $t['ErrorCodes'] } else { 'none' }
    $severity      = if ($t['ExitCode'] -ne 0) { 'ERROR' } elseif ($t['ErrorCodes']) { 'WARN' } else { 'INFO' }

    $logRecord = [ordered]@{
        timestamp         = $tsMs
        severity          = $severity
        content           = ('tomcat-api-inventory run ' + $runId + ' on ' + $t['Host_'] + ': ' + $t['EndpointsUnique'] + ' endpoints, exit=' + $t['ExitCode'])
        'run.id'          = $runId
        'host.name'       = $t['Host_']
        'ps.version'      = $t['PSVersion']
        'catalina.home'   = $t['CatalinaHome']
        'duration.sec'    = $t['DurationSec']
        'log.files'       = $t['LogFilesScanned']
        'log.lines'       = $t['LogLinesRead']
        'log.line_capped' = $t['LogLineCapped']
        'endpoints.raw'   = $t['EndpointsRaw']
        'endpoints.unique'= $t['EndpointsUnique']
        'engine.url'      = $t['EngineUrl']
        'packets.sent'    = $t['PacketsSent']
        'packets.failed'  = $t['PacketsFailed']
        'cert.subject'    = $t['CertSubject']
        'cert.expiry'     = $t['CertExpiry']
        'cert.days_left'  = $t['CertDaysLeft']
        'error.codes'     = $errorCodesVal
        'exit.code'       = $t['ExitCode']
    }

    try {
        $logsUrl  = $baseUrl + '/api/v2/logs/ingest'
        $logsBody = ConvertTo-Json @($logRecord) -Depth 4 -Compress
        $lArgs = @{
            Uri     = $logsUrl
            Method  = 'POST'
            Headers = $logHeaders
            Body    = $logsBody
            ErrorAction = 'Stop'
        }
        Invoke-RestMethod @lArgs | Out-Null
        Write-Log INFO ("Dynatrace: log event sent to " + $logsUrl)
    } catch {
        Write-Log WARN ("Dynatrace log ingest failed: " + $_)
    }
}

# ---------------------------------------------------------------------------
# Push full endpoint inventory to Dynatrace log ingest
# One log record per endpoint — queryable by host, path, method, status, source
# Batched at 100 records per POST (DT recommended max per request)
# ---------------------------------------------------------------------------

function Send-EndpointsToDynatrace([array]$inventory) {
    if (-not $inventory -or $inventory.Count -eq 0) { return }

    $baseUrl    = $DynatraceUrl.TrimEnd('/')
    $logsUrl    = $baseUrl + '/api/v2/logs/ingest'
    $logHeaders = @{
        'Authorization' = 'Api-Token ' + $DynatraceToken
        'Content-Type'  = 'application/json; charset=utf-8'
    }

    $runId  = $Script:Telemetry['RunId']
    $host_  = $Script:Telemetry['Host_']
    $tsMs   = [long]([double]::Parse((Get-Date -UFormat %s)) * 1000)
    $dtBatch = 100
    $sent   = 0
    $failed = 0

    for ($i = 0; $i -lt $inventory.Count; $i += $dtBatch) {
        $slice   = $inventory[$i .. [Math]::Min($i + $dtBatch - 1, $inventory.Count - 1)]
        $records = foreach ($ep in $slice) {
            [ordered]@{
                timestamp        = $tsMs
                severity         = 'INFO'
                content          = ($ep.Method + ' ' + $ep.Host + $ep.Path)
                'run.id'         = $runId
                'host.name'      = $host_
                'api.host'       = $ep.Host
                'api.path'       = $ep.Path
                'api.method'     = $ep.Method
                'api.status'     = if ($ep.Status) { [string]$ep.Status } else { '' }
                'api.source'     = $ep.Source
                'api.contenttype'= $ep.ContentType
            }
        }

        try {
            $body = ConvertTo-Json @($records) -Depth 4 -Compress
            $lArgs = @{
                Uri     = $logsUrl
                Method  = 'POST'
                Headers = $logHeaders
                Body    = $body
                ErrorAction = 'Stop'
            }
            Invoke-RestMethod @lArgs | Out-Null
            $sent += $slice.Count
        } catch {
            Write-Log WARN ("Dynatrace endpoint batch failed (offset " + $i + "): " + $_)
            $failed += $slice.Count
        }
    }

    Write-Log INFO ("Dynatrace: " + $sent + " endpoint records sent, " + $failed + " failed.")
}

# ---------------------------------------------------------------------------
# Fix 1 + E1xxx: Validate engine URL is HTTPS before doing any work
# ---------------------------------------------------------------------------
if ($EngineUrl) {
    try {
        $parsedUri = [System.Uri]::new($EngineUrl)
        if ($parsedUri.Scheme -ne 'https') {
            Write-Log ERROR "EngineUrl must use HTTPS. Got: '$($parsedUri.Scheme)'." "E1002"
            Exit-Script 1
        }
    } catch {
        Write-Log ERROR "EngineUrl is not a valid URI: '$EngineUrl'" "E1001"
        Exit-Script 1
    }
}

# ---------------------------------------------------------------------------
# Preflight: verify the engine is reachable and responds with "OK"
# ---------------------------------------------------------------------------

function Test-EngineConnectivity([string]$engineUrl, [bool]$skipTls) {
    $t0 = Get-Date
    Write-Log INFO "Preflight: checking engine at $engineUrl ..."
    try {
        $checkArgs = @{ Uri = $engineUrl; Method = 'GET'; ErrorAction = 'Stop' }
        $resp = if ($skipTls) { Invoke-RestSkipTls $checkArgs } else { Invoke-RestMethod @checkArgs }
        $ms   = [math]::Round(((Get-Date) - $t0).TotalMilliseconds)
        if ("$resp" -match '(?i)ok') {
            Write-Log INFO ("Engine preflight passed (OK) in " + $ms + "ms.")
        } else {
            Write-Log WARN ("Engine reachable (" + $ms + "ms) but response does not contain OK: " + $resp)
            Write-Log WARN "Proceeding - engine may not expose a health endpoint."
        }
    } catch {
        Write-Log ERROR ("Engine preflight failed - cannot reach " + $engineUrl + ": " + $_) "E2001"
        Exit-Script 1
    }
}

# ---------------------------------------------------------------------------
# TLS certificate check - validates cert, reports expiry, fails on E2003
# Uses raw TCP + SslStream so it works on PS 5.1 without Invoke-WebRequest hacks
# ---------------------------------------------------------------------------

function Test-TlsCertificate([string]$engineUrl, [bool]$skipTls) {
    $uri = [System.Uri]::new($engineUrl)
    if ($uri.Scheme -ne 'https') { return }   # nothing to check for plain HTTP

    $host_ = $uri.Host
    $port_ = if ($uri.Port -gt 0) { $uri.Port } else { 443 }

    Write-Log INFO ("TLS check: connecting to " + $host_ + ":" + $port_ + " ...")

    $tcp    = $null
    $ssl    = $null
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new($host_, $port_)

        if ($skipTls) {
            # Accept any cert - just retrieve it for reporting
            $callback = [System.Net.Security.RemoteCertificateValidationCallback]{
                param($s,$c,$ch,$e) return $true
            }
            $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, $callback)
        } else {
            $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false)
        }

        $ssl.AuthenticateAsClient($host_)
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)

        $expiry    = $cert.NotAfter
        $daysLeft  = [math]::Floor(($expiry - (Get-Date)).TotalDays)
        $subject   = $cert.Subject
        $thumbprint = $cert.Thumbprint

        $Script:Telemetry['CertSubject']  = $subject
        $Script:Telemetry['CertExpiry']   = $expiry.ToString('yyyy-MM-dd')
        $Script:Telemetry['CertDaysLeft'] = $daysLeft

        if (-not $skipTls) {
            # Verify hostname matches cert CN or SAN
            $sans = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' }
            $sanText = if ($sans) { $sans.Format($false) } else { "" }
            $cnMatch  = $subject -match ('CN=' + [regex]::Escape($host_))
            $sanMatch = $sanText -match [regex]::Escape($host_)
            if (-not $cnMatch -and -not $sanMatch) {
                Write-Log ERROR ("TLS hostname mismatch: cert is for '" + $subject + "', expected '" + $host_ + "'") "E2003"
                Exit-Script 1
            }
        }

        if ($daysLeft -le 0) {
            Write-Log ERROR ("TLS cert EXPIRED on " + $expiry.ToString('yyyy-MM-dd') + " (" + [math]::Abs($daysLeft) + " days ago). Thumbprint: " + $thumbprint) "E2003"
            if (-not $skipTls) { Exit-Script 1 }
        } elseif ($daysLeft -le 7) {
            Write-Log ERROR ("TLS cert expires in " + $daysLeft + " days (" + $expiry.ToString('yyyy-MM-dd') + "). Renew immediately.") "E2003"
        } elseif ($daysLeft -le 30) {
            Write-Log WARN ("TLS cert expires in " + $daysLeft + " days (" + $expiry.ToString('yyyy-MM-dd') + "). Plan renewal.")
        } else {
            Write-Log INFO ("TLS cert valid. Subject: " + $subject + "  Expires: " + $expiry.ToString('yyyy-MM-dd') + " (" + $daysLeft + " days)")
        }

    } catch [System.Security.Authentication.AuthenticationException] {
        Write-Log ERROR ("TLS handshake failed for " + $host_ + " - untrusted or invalid certificate: " + $_.Exception.Message) "E2003"
        if (-not $skipTls) { Exit-Script 1 }
    } catch {
        Write-Log WARN ("TLS check could not complete for " + $host_ + ": " + $_)
    } finally {
        if ($ssl) { $ssl.Close() }
        if ($tcp) { $tcp.Close() }
    }
}

if ($EngineUrl) {
    # Preflight before spending time on discovery
    Test-TlsCertificate $EngineUrl $SkipTlsVerify.IsPresent
    Test-EngineConnectivity $EngineUrl $SkipTlsVerify.IsPresent
}

# ---------------------------------------------------------------------------
# Catalina home resolution
# ---------------------------------------------------------------------------

function Resolve-CatalinaHome {
    if ($CatalinaHome -and (Test-Path $CatalinaHome)) { return $CatalinaHome }

    $fromEnv = $env:CATALINA_HOME
    if ($fromEnv -and (Test-Path $fromEnv)) { return $fromEnv }

    $candidates = @(
        "C:\Program Files\Apache Software Foundation\Tomcat*",
        "C:\Program Files\Tomcat*",
        "C:\Program Files (x86)\Apache Software Foundation\Tomcat*",
        "C:\Tomcat*",
        "C:\apache-tomcat*",
        "C:\tools\tomcat*",
        "C:\Apps\*tomcat*",
        "C:\Apps\*Tomcat*",
        "C:\WWW\*tomcat*",
        "C:\WWW\*Tomcat*",
        "C:\inetpub\*tomcat*"
    )

    try {
        $svc = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -match 'tomcat' -or $_.DisplayName -match 'tomcat' } |
               Select-Object -First 1
        if ($svc -and $svc.PathName) {
            $exePath = ($svc.PathName -split '"' | Where-Object { $_ -match '\.exe' } | Select-Object -First 1)
            if (-not $exePath) { $exePath = $svc.PathName.Split(' ')[0].Trim('"') }
            $svcHome = Split-Path (Split-Path $exePath -Parent) -Parent
            if ($svcHome -and (Test-Path $svcHome)) {
                Write-Verbose "Found Tomcat via Windows service: $svcHome"
                return $svcHome
            }
        }
    } catch { }

    foreach ($pattern in $candidates) {
        $match = Get-Item $pattern -ErrorAction SilentlyContinue | Select-Object -Last 1
        if ($match) { return $match.FullName }
    }

    Write-Log WARN "Could not locate Tomcat installation. Set -CatalinaHome or CATALINA_HOME." "E5002"
    return $null
}

# ---------------------------------------------------------------------------
# Discover hostnames from hosts file
# ---------------------------------------------------------------------------

function Resolve-LocalHostnames {
    $hostsPath = "C:\Windows\System32\drivers\etc\hosts"
    $names     = [System.Collections.Generic.List[string]]::new()

    try {
        $fs     = [System.IO.File]::Open($hostsPath,
                    [System.IO.FileMode]::Open,
                    [System.IO.FileAccess]::Read,
                    [System.IO.FileShare]::ReadWrite)
        $reader = [System.IO.StreamReader]::new($fs)
        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine().Trim()
            if ($line -match '^\s*#' -or $line -eq '') { continue }
            if ($line -match '^(127\.0\.0\.1|::1|0\.0\.0\.0)\s+(.+)') {
                $Matches[2] -split '\s+' | ForEach-Object {
                    $n = $_.Trim().ToLower()
                    if ($n -and $n -ne 'localhost' -and $n -notmatch '^#' -and
                        $n -match '^[a-z0-9][a-z0-9._-]*(?::\d{1,5})?$') {
                        $names.Add($n)
                    } elseif ($n -and $n -ne 'localhost' -and $n -notmatch '^#') {
                        Write-Verbose "  Skipping invalid hostname from hosts file: '$n'"
                    }
                }
            }
        }
        $reader.Close(); $fs.Close()
    } catch {
        Write-Log WARN "Could not read hosts file: $_" "E4004"
    }

    if ($names.Count -eq 0) { $names.Add("localhost") }
    Write-Log INFO "  Hosts file hostnames: $($names -join ', ')"
    return $names.ToArray()
}

# ---------------------------------------------------------------------------
# Read virtual host names from server.xml (read-only, XXE-safe)
# ---------------------------------------------------------------------------

function Resolve-HostnamesFromServerXml([string]$catalinaHome) {
    $serverXml = Join-Path $catalinaHome "conf\server.xml"
    $names     = [System.Collections.Generic.List[string]]::new()

    if (-not (Test-Path $serverXml)) {
        Write-Verbose "  server.xml not found at $serverXml"
        return $names.ToArray()
    }

    try {
        $xmlDoc    = [System.Xml.XmlDocument]::new()
        $xmlReader = $null
        try {
            $settings = [System.Xml.XmlReaderSettings]::new()
            $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
            $settings.XmlResolver   = $null
            $xmlReader = [System.Xml.XmlReader]::Create($serverXml, $settings)
            $xmlDoc.Load($xmlReader)
        } finally {
            if ($xmlReader) { $xmlReader.Close() }
        }

        $xpHost  = "//*[local-name()='Host']"
        $xpAlias = "*[local-name()='Alias']"
        $hostNodes = $xmlDoc.SelectNodes($xpHost)
        foreach ($node in $hostNodes) {
            $n = $node.GetAttribute("name")
            if ($n -and $n -match '^[a-z0-9][a-z0-9._-]*$') { $names.Add($n.ToLower()) }
            foreach ($alias in $node.SelectNodes($xpAlias)) {
                $a = $alias.InnerText.Trim().ToLower()
                if ($a -and $a -match '^[a-z0-9][a-z0-9._-]*$') { $names.Add($a) }
            }
        }
    } catch {
        Write-Log WARN "Could not parse server.xml: $_" "E4003"
    }

    Write-Log INFO "  server.xml hostnames: $($names -join ', ')"
    return $names.ToArray()
}

# ---------------------------------------------------------------------------
# Path filter
# ---------------------------------------------------------------------------

$SkipExtensions = @(
    ".html",".htm",".js",".css",".ico",".png",".jpg",".jpeg",".gif",
    ".svg",".woff",".woff2",".ttf",".eot",".map",".txt",".xml",
    ".pdf",".zip",".tar",".gz"
)

function Test-ApiPath([string]$path) {
    $bare = $path -replace '\?.*', ''
    $ext  = [System.IO.Path]::GetExtension($bare).ToLower()
    return ($SkipExtensions -notcontains $ext)
}

# ---------------------------------------------------------------------------
# SOURCE 1: Access logs
# ---------------------------------------------------------------------------

function Get-EndpointsFromLogs([string]$catalinaHome) {
    Write-Header "Source 1: Access Logs"
    $t0 = Get-Date

    $logDir = Join-Path $catalinaHome "logs"
    if (-not (Test-Path $logDir)) {
        Write-Log WARN "Log directory not found: $logDir" "E3001"
        return @()
    }

    $cutoff  = (Get-Date).AddDays(-$LogDays)
    $logFiles = @(Get-ChildItem $logDir -Filter "*.txt" -ErrorAction SilentlyContinue) +
                @(Get-ChildItem $logDir -Filter "*.log" -ErrorAction SilentlyContinue) |
                Where-Object { $_ -and $_.LastWriteTime -ge $cutoff }

    if (-not $logFiles) {
        Write-Log WARN "No log files found in the last $LogDays days." "E3001"
        return @()
    }

    $Script:Telemetry['LogFilesScanned'] = @($logFiles).Count
    Write-Log INFO "Scanning $(@($logFiles).Count) log file(s) since $($cutoff.ToString('yyyy-MM-dd'))..."

    $results   = [System.Collections.Generic.HashSet[string]]::new()
    $endpoints = [System.Collections.Generic.List[PSCustomObject]]::new()
    $totalLines = 0

    $combinedPattern = [string]'"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)\s+(\S+)\s+HTTP'
    $w3cPattern      = [string]'\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)\s+(\S+)\s'
    $hostPattern     = [string]'^([a-zA-Z0-9._-]+)(?::\d+)?\s+\S+\s+\S+\s+\S+\s+\['

    foreach ($file in $logFiles) {
        Write-Verbose "  Scanning $($file.Name) ($([math]::Round($file.Length/1KB))KB)"
        $ft0    = Get-Date
        $fs     = $null
        $reader = $null
        $fileLines = 0
        try {
            $fs     = [System.IO.File]::Open($file.FullName,
                          [System.IO.FileMode]::Open,
                          [System.IO.FileAccess]::Read,
                          [System.IO.FileShare]::ReadWrite)
            $reader = [System.IO.StreamReader]::new($fs)

            while (-not $reader.EndOfStream) {
                $line = $reader.ReadLine()
                $fileLines++
                $totalLines++
                if ($totalLines -gt $MaxLogLines) {
                    Write-Log WARN "$($file.Name): reached $MaxLogLines line cap, stopping early." "E3003"
                    $Script:Telemetry['LogLineCapped'] = $true
                    break
                }

                $m = [regex]::Match($line, $combinedPattern)
                if (-not $m.Success) { $m = [regex]::Match($line, $w3cPattern) }
                if (-not $m.Success) { continue }

                $method = $m.Groups[1].Value.ToUpper()
                $path   = $m.Groups[2].Value
                if (-not (Test-ApiPath $path)) { continue }

                $logHost      = "localhost"
                $hostHdrMatch = [regex]::Match($line, $hostPattern)
                if ($hostHdrMatch.Success) {
                    $candidate = $hostHdrMatch.Groups[1].Value.ToLower()
                    if ($candidate -match '^[a-z0-9][a-z0-9._-]*$' -and $candidate -ne '-') {
                        $logHost = $candidate
                    }
                }

                $statusMatch = [regex]::Match($line, '"\s+(\d{3})\s+')
                $status      = if ($statusMatch.Success) { [int]$statusMatch.Groups[1].Value } else { $null }

                $ctMatch     = [regex]::Match($line, 'application/(?:json|xml|x-www-form-urlencoded|grpc|graphql|msgpack|cbor|octet-stream)|text/xml', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                $contentType = if ($ctMatch.Success) { $ctMatch.Value.ToLower() } else { "" }

                $key = "$method|$logHost|$($path -replace '\?.*','')"
                if ($results.Add($key)) {
                    $endpoints.Add([PSCustomObject]@{
                        Host           = $logHost
                        Path           = ($path -replace '\?.*','')
                        Method         = $method
                        Source         = "AccessLog"
                        Status         = $status
                        ContentType    = $contentType
                        SampleRequest  = ""
                        SampleResponse = ""
                    })
                }
            }
            $fms = [math]::Round(((Get-Date) - $ft0).TotalMilliseconds)
            Write-Verbose "  $($file.Name): $fileLines lines in ${fms}ms"
        } catch {
            Write-Log WARN "Could not read $($file.Name): $_" "E3002"
        } finally {
            if ($reader) { $reader.Close() }
            if ($fs)     { $fs.Close() }
        }
    }

    $Script:Telemetry['LogLinesRead'] = $totalLines
    $elapsed = [math]::Round(((Get-Date) - $t0).TotalSeconds, 2)
    Write-Log INFO "Access logs: $($endpoints.Count) unique endpoints from $totalLines lines in ${elapsed}s."
    return $endpoints
}

# ---------------------------------------------------------------------------
# SOURCE 2: web.xml servlet mappings
# ---------------------------------------------------------------------------

function Get-EndpointsFromWebXml([string]$catalinaHome, [string[]]$hostnames) {
    Write-Header "Source 2: web.xml Servlet Mappings"
    $t0 = Get-Date

    $webappsDir = Join-Path $catalinaHome "webapps"
    if (-not (Test-Path $webappsDir)) {
        Write-Log WARN "webapps directory not found: $webappsDir" "E4001"
        return @()
    }

    $endpoints   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $seen        = [System.Collections.Generic.HashSet[string]]::new()
    $webXmlFiles = Get-ChildItem $webappsDir -Recurse -Filter "web.xml" -ErrorAction SilentlyContinue
    $parseErrors = 0

    foreach ($wxf in $webXmlFiles) {
        Write-Verbose "  Parsing $($wxf.FullName)"
        try {
            $xmlDoc    = [System.Xml.XmlDocument]::new()
            $xmlReader = $null
            try {
                $settings = [System.Xml.XmlReaderSettings]::new()
                $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
                $settings.XmlResolver   = $null
                $xmlReader = [System.Xml.XmlReader]::Create($wxf.FullName, $settings)
                $xmlDoc.Load($xmlReader)
            } finally {
                if ($xmlReader) { $xmlReader.Close() }
            }

            $appDir      = $wxf.Directory.Parent.FullName
            $appName     = Split-Path $appDir -Leaf
            $contextRoot = if ($appName -eq "ROOT") { "" } else { "/$appName" }

            $mappings = $xmlDoc.SelectNodes("//servlet-mapping")
            if (-not $mappings -or $mappings.Count -eq 0) {
                $mappings = $xmlDoc.SelectNodes("//*[local-name()='servlet-mapping']")
            }

            foreach ($mapping in $mappings) {
                $pattern = $mapping.SelectSingleNode("url-pattern")
                if (-not $pattern) { $pattern = $mapping.SelectSingleNode("*[local-name()='url-pattern']") }
                if (-not $pattern) { continue }

                $urlPattern = $pattern.InnerText.Trim()
                if ($urlPattern -eq "/*" -or $urlPattern -eq "/") { continue }
                if ($urlPattern -match '^\*\.\w+$') { continue }

                $fullPath = $contextRoot + $urlPattern
                if (-not (Test-ApiPath $fullPath)) { continue }

                foreach ($hn in $hostnames) {
                    foreach ($method in @("GET","POST","PUT","DELETE","PATCH")) {
                        $key = "$method|$hn|$fullPath"
                        if ($seen.Add($key)) {
                            $endpoints.Add([PSCustomObject]@{
                                Host           = $hn
                                Path           = $fullPath
                                Method         = $method
                                Source         = "web.xml:$($wxf.FullName)"
                                Status         = $null
                                ContentType    = ""
                                SampleRequest  = ""
                                SampleResponse = ""
                            })
                        }
                    }
                }
            }
        } catch {
            Write-Log WARN "Could not parse $($wxf.FullName): $_" "E4002"
            $parseErrors++
        }
    }

    $elapsed = [math]::Round(((Get-Date) - $t0).TotalSeconds, 2)
    Write-Log INFO "web.xml: $($endpoints.Count) endpoint/method combos from $(@($webXmlFiles).Count) file(s) in ${elapsed}s$(if ($parseErrors) { " [$parseErrors parse errors]" })."
    return $endpoints
}

# ---------------------------------------------------------------------------
# SOURCE 3: Deployed WAR context roots
# ---------------------------------------------------------------------------

function Get-EndpointsFromWars([string]$catalinaHome, [string[]]$hostnames) {
    Write-Header "Source 3: Deployed WARs / App Context Roots"
    $t0 = Get-Date

    $webappsDir = Join-Path $catalinaHome "webapps"
    if (-not (Test-Path $webappsDir)) { return @() }

    $endpoints = [System.Collections.Generic.List[PSCustomObject]]::new()
    $wars      = Get-ChildItem $webappsDir -Filter "*.war" -ErrorAction SilentlyContinue

    foreach ($war in $wars) {
        $contextRoot = "/" + [System.IO.Path]::GetFileNameWithoutExtension($war.Name)
        if ($contextRoot -eq "/ROOT") { $contextRoot = "" }
        Write-Verbose "  WAR: $($war.Name) -> $contextRoot/"

        foreach ($hn in $hostnames) {
            foreach ($method in @("GET","POST")) {
                $endpoints.Add([PSCustomObject]@{
                    Host           = $hn
                    Path           = "$contextRoot/"
                    Method         = $method
                    Source         = "WAR:$($war.Name)"
                    Status         = $null
                    ContentType    = ""
                    SampleRequest  = ""
                    SampleResponse = ""
                })
            }
        }
    }

    $elapsed = [math]::Round(((Get-Date) - $t0).TotalSeconds, 2)
    Write-Log INFO "WARs: $($endpoints.Count) context-root endpoints from $(@($wars).Count) WAR(s) in ${elapsed}s."
    return $endpoints
}

# ---------------------------------------------------------------------------
# SOURCE 4: Active connections via netstat
# ---------------------------------------------------------------------------

function Get-EndpointsFromNetstat([int]$port) {
    Write-Header "Source 4: Active TCP Connections (netstat)"
    $t0 = Get-Date

    $endpoints = [System.Collections.Generic.List[PSCustomObject]]::new()
    $seen      = [System.Collections.Generic.HashSet[string]]::new()

    try {
        $connections = Get-NetTCPConnection -LocalPort $port -State Established `
                       -ErrorAction SilentlyContinue
        if (-not $connections) {
            Write-Log INFO "No active established connections on port $port."
            return @()
        }

        foreach ($conn in $connections) {
            $remote = $conn.RemoteAddress
            $key    = "CONNECTED|$remote"
            if ($seen.Add($key)) {
                $endpoints.Add([PSCustomObject]@{
                    Host           = $conn.LocalAddress
                    Path           = "/ (active connection from $remote)"
                    Method         = "UNKNOWN"
                    Source         = "Netstat"
                    Status         = $null
                    ContentType    = ""
                    SampleRequest  = ""
                    SampleResponse = ""
                })
            }
        }
        $elapsed = [math]::Round(((Get-Date) - $t0).TotalSeconds, 2)
        Write-Log INFO "Netstat: $(@($connections).Count) active connections on port $port in ${elapsed}s."
    } catch {
        Write-Log WARN "netstat query failed: $_"
    }

    return $endpoints
}

# ===========================================================================
# IIS DISCOVERY
# ===========================================================================

# ---------------------------------------------------------------------------
# IIS SOURCE 1: W3SVC access logs
# Default format fields (W3C extended): date time s-ip cs-method cs-uri-stem
#   cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer)
#   sc-status sc-substatus sc-win32-status time-taken
# We look for: cs-method  cs-uri-stem  cs(Host)  sc-status
# ---------------------------------------------------------------------------

function Get-IISLogRoot {
    if ($IISLogPath -and (Test-Path $IISLogPath)) { return $IISLogPath }
    $default = Join-Path $env:SystemDrive "inetpub\logs\LogFiles"
    if (Test-Path $default) { return $default }
    # Try reading from applicationHost.config
    try {
        $cfg = Get-IISAppHostConfig
        if ($cfg) {
            $logNode = $cfg.SelectSingleNode("//*[local-name()='logFile']")
            if ($logNode) {
                $dir = $logNode.GetAttribute("directory") -replace '%SystemDrive%', $env:SystemDrive
                if ($dir -and (Test-Path $dir)) { return $dir }
            }
        }
    } catch {}
    return $null
}

function Get-IISAppHostConfig {
    $path = $IISConfigPath
    if (-not $path) {
        $path = Join-Path $env:windir "System32\inetsrv\config\applicationHost.config"
    }
    if (-not (Test-Path $path)) { return $null }
    $doc    = [System.Xml.XmlDocument]::new()
    $reader = $null
    try {
        $settings = [System.Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver   = $null
        $reader = [System.Xml.XmlReader]::Create($path, $settings)
        $doc.Load($reader)
    } finally {
        if ($reader) { $reader.Close() }
    }
    return $doc
}

function Get-EndpointsFromIISLogs([string[]]$hostnames) {
    Write-Header "IIS Source 1: W3SVC Access Logs"
    $t0 = Get-Date

    $logRoot = Get-IISLogRoot
    if (-not $logRoot) {
        Write-Log WARN "IIS log directory not found." "E6001"
        return @()
    }

    $cutoff   = (Get-Date).AddDays(-$LogDays)
    $logFiles = @(Get-ChildItem $logRoot -Recurse -Filter "u_ex*.log" -ErrorAction SilentlyContinue |
                  Where-Object { $_.LastWriteTime -ge $cutoff })
    # Also catch custom-named logs
    $logFiles += @(Get-ChildItem $logRoot -Recurse -Filter "*.log" -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -notmatch '^u_ex' -and $_.LastWriteTime -ge $cutoff })

    if (-not $logFiles) {
        Write-Log WARN "No IIS log files found in the last $LogDays days under $logRoot." "E6001"
        return @()
    }

    $Script:Telemetry['IISLogFilesScanned'] = @($logFiles).Count
    Write-Log INFO ("Scanning " + @($logFiles).Count + " IIS log file(s)...")

    $results   = [System.Collections.Generic.HashSet[string]]::new()
    $endpoints = [System.Collections.Generic.List[PSCustomObject]]::new()
    $totalLines = 0

    # W3C field positions — read from #Fields directive in each file
    $methodIdx  = -1; $uriIdx = -1; $hostIdx = -1; $statusIdx = -1; $portIdx = -1

    foreach ($file in $logFiles) {
        $fs = $null; $reader = $null
        try {
            $fs     = [System.IO.File]::Open($file.FullName,
                        [System.IO.FileMode]::Open,
                        [System.IO.FileAccess]::Read,
                        [System.IO.FileShare]::ReadWrite)
            $reader = [System.IO.StreamReader]::new($fs)
            # Reset field positions per file
            $methodIdx = -1; $uriIdx = -1; $hostIdx = -1; $statusIdx = -1; $portIdx = -1

            while (-not $reader.EndOfStream) {
                $line = $reader.ReadLine()
                $totalLines++
                if ($totalLines -gt $MaxLogLines) {
                    Write-Log WARN ("IIS logs: reached " + $MaxLogLines + " line cap.") "E6002"
                    $Script:Telemetry['LogLineCapped'] = $true
                    break
                }

                # Parse #Fields directive to get column positions
                if ($line.StartsWith('#Fields:')) {
                    $fields    = ($line.Substring(8).Trim()) -split '\s+'
                    $methodIdx = [array]::IndexOf($fields, 'cs-method')
                    $uriIdx    = [array]::IndexOf($fields, 'cs-uri-stem')
                    $hostIdx   = [array]::IndexOf($fields, 'cs(Host)')
                    $statusIdx = [array]::IndexOf($fields, 'sc-status')
                    $portIdx   = [array]::IndexOf($fields, 's-port')
                    continue
                }
                if ($line.StartsWith('#')) { continue }
                if ($methodIdx -lt 0 -or $uriIdx -lt 0) { continue }

                $cols = $line -split '\s+'
                if ($cols.Count -le [Math]::Max($methodIdx, $uriIdx)) { continue }

                $method = $cols[$methodIdx].ToUpper()
                if ($method -notmatch '^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)$') { continue }

                $path = $cols[$uriIdx]
                if (-not (Test-ApiPath $path)) { continue }

                $logHost = 'localhost'
                if ($hostIdx -ge 0 -and $cols.Count -gt $hostIdx -and $cols[$hostIdx] -ne '-') {
                    $candidate = ($cols[$hostIdx] -split ':')[0].ToLower()
                    if ($candidate -match '^[a-z0-9][a-z0-9._-]*$') { $logHost = $candidate }
                } elseif ($portIdx -ge 0 -and $cols.Count -gt $portIdx) {
                    # No host header — use first matching hostname for this port
                    $sitePort = $cols[$portIdx]
                    $match    = $hostnames | Where-Object { $_ -ne 'localhost' } | Select-Object -First 1
                    if ($match) { $logHost = $match }
                }

                $status = $null
                if ($statusIdx -ge 0 -and $cols.Count -gt $statusIdx) {
                    $sv = $cols[$statusIdx]
                    if ($sv -match '^\d{3}$') { $status = [int]$sv }
                }

                $key = "$method|$logHost|$path"
                if ($results.Add($key)) {
                    $endpoints.Add([PSCustomObject]@{
                        Host           = $logHost
                        Path           = $path
                        Method         = $method
                        Source         = "IIS:AccessLog"
                        Status         = $status
                        ContentType    = ""
                        SampleRequest  = ""
                        SampleResponse = ""
                    })
                }
            }
        } catch {
            Write-Log WARN ("Could not read IIS log " + $file.Name + ": " + $_) "E6002"
        } finally {
            if ($reader) { $reader.Close() }
            if ($fs)     { $fs.Close() }
        }
    }

    $elapsed = [math]::Round(((Get-Date) - $t0).TotalSeconds, 2)
    Write-Log INFO ("IIS logs: " + $endpoints.Count + " unique endpoints from " + $totalLines + " lines in " + $elapsed + "s.")
    return $endpoints
}

# ---------------------------------------------------------------------------
# IIS SOURCE 2: Hostnames from applicationHost.config site bindings
# ---------------------------------------------------------------------------

function Get-HostnamesFromIIS {
    $names = [System.Collections.Generic.List[string]]::new()
    try {
        $cfg = Get-IISAppHostConfig
        if (-not $cfg) {
            Write-Log WARN "applicationHost.config not found." "E6003"
            return @()
        }
        # <binding protocol="http" bindingInformation="*:80:mysite.example.com" />
        $bindings = $cfg.SelectNodes("//*[local-name()='binding']")
        foreach ($b in $bindings) {
            $info = $b.GetAttribute("bindingInformation")
            if (-not $info) { continue }
            $parts = $info -split ':'
            # format: ip:port:hostname
            if ($parts.Count -ge 3 -and $parts[2]) {
                $n = $parts[2].Trim().ToLower()
                if ($n -match '^[a-z0-9][a-z0-9._-]*$') { $names.Add($n) }
            }
        }
    } catch {
        Write-Log WARN ("Could not parse applicationHost.config: " + $_) "E6003"
    }
    Write-Log INFO ("IIS hostnames from applicationHost.config: " + ($names -join ', '))
    return $names.ToArray()
}

# ---------------------------------------------------------------------------
# IIS SOURCE 3: web.config HTTP handlers and route tables
# Looks for: <add verb="GET,POST" path="/api/*" ...>
#            ASP.NET route config comments and attribute routes
# ---------------------------------------------------------------------------

function Get-EndpointsFromIISWebConfig([string[]]$hostnames) {
    Write-Header "IIS Source 2: web.config Handlers / Routes"
    $t0 = Get-Date

    $searchRoots = @(
        (Join-Path $env:SystemDrive "inetpub\wwwroot"),
        (Join-Path $env:SystemDrive "inetpub\sites")
    )
    # Also scan any sites declared in applicationHost.config
    try {
        $cfg = Get-IISAppHostConfig
        if ($cfg) {
            $physPaths = $cfg.SelectNodes("//*[local-name()='virtualDirectory']")
            foreach ($vd in $physPaths) {
                $phys = $vd.GetAttribute("physicalPath") -replace '%SystemDrive%', $env:SystemDrive
                if ($phys -and (Test-Path $phys)) { $searchRoots += $phys }
            }
        }
    } catch {}

    $endpoints  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $seen       = [System.Collections.Generic.HashSet[string]]::new()
    $parseErrors = 0

    $webConfigs = foreach ($root in ($searchRoots | Select-Object -Unique)) {
        if (Test-Path $root) {
            Get-ChildItem $root -Recurse -Filter "web.config" -ErrorAction SilentlyContinue
        }
    }

    foreach ($wcf in @($webConfigs)) {
        Write-Verbose ("  Parsing " + $wcf.FullName)
        try {
            $doc    = [System.Xml.XmlDocument]::new()
            $reader = $null
            try {
                $settings = [System.Xml.XmlReaderSettings]::new()
                $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
                $settings.XmlResolver   = $null
                $reader = [System.Xml.XmlReader]::Create($wcf.FullName, $settings)
                $doc.Load($reader)
            } finally {
                if ($reader) { $reader.Close() }
            }

            # <handlers> <add verb="GET,POST" path="/api/v1/*" ...>
            $handlers = $doc.SelectNodes("//*[local-name()='handlers']/*[local-name()='add']")
            foreach ($h in $handlers) {
                $verbs = $h.GetAttribute("verb")
                $path  = $h.GetAttribute("path")
                if (-not $path -or $path -eq '*') { continue }
                if (-not (Test-ApiPath $path)) { continue }

                $methods = if ($verbs -and $verbs -ne '*') {
                    $verbs -split ',' | ForEach-Object { $_.Trim().ToUpper() } |
                        Where-Object { $_ -match '^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)$' }
                } else {
                    @("GET","POST","PUT","DELETE","PATCH")
                }

                foreach ($hn in $hostnames) {
                    foreach ($method in $methods) {
                        $key = "$method|$hn|$path"
                        if ($seen.Add($key)) {
                            $endpoints.Add([PSCustomObject]@{
                                Host           = $hn
                                Path           = $path
                                Method         = $method
                                Source         = ("IIS:web.config:" + $wcf.FullName)
                                Status         = $null
                                ContentType    = ""
                                SampleRequest  = ""
                                SampleResponse = ""
                            })
                        }
                    }
                }
            }
        } catch {
            Write-Log WARN ("Could not parse " + $wcf.FullName + ": " + $_) "E6004"
            $parseErrors++
        }
    }

    $elapsed = [math]::Round(((Get-Date) - $t0).TotalSeconds, 2)
    Write-Log INFO ("IIS web.config: " + $endpoints.Count + " endpoints from " + @($webConfigs).Count + " file(s) in " + $elapsed + "s" + $(if ($parseErrors) { " [$parseErrors errors]" }) + ".")
    return $endpoints
}

# ===========================================================================
# NODE.JS DISCOVERY
# ===========================================================================

# ---------------------------------------------------------------------------
# Node SOURCE 1: PM2 / node process logs
# Looks for Express-style: "GET /api/v1/users 200" or route registration lines
# ---------------------------------------------------------------------------

function Get-EndpointsFromNodeLogs([string[]]$hostnames) {
    Write-Header "Node.js Source 1: Process Logs"
    $t0 = Get-Date

    $logRoots = @()
    if ($NodeLogPath -and (Test-Path $NodeLogPath)) {
        $logRoots += $NodeLogPath
    } else {
        # PM2 default locations
        $pm2Home = Join-Path $env:USERPROFILE ".pm2\logs"
        if (Test-Path $pm2Home) { $logRoots += $pm2Home }
        $pm2Global = "C:\Users\Public\.pm2\logs"
        if (Test-Path $pm2Global) { $logRoots += $pm2Global }
    }

    if (-not $logRoots) {
        Write-Log INFO "No Node.js log directories found - skipping."
        return @()
    }

    $endpoints = [System.Collections.Generic.List[PSCustomObject]]::new()
    $results   = [System.Collections.Generic.HashSet[string]]::new()
    # Express access log pattern: "METHOD /path HTTP/1.x" status or "METHOD /path status"
    $exprPattern = [string]'(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(/[^\s"]*)\s+(?:HTTP/\S+\s+)?(\d{3})'

    foreach ($root in $logRoots) {
        $files = @(Get-ChildItem $root -Recurse -Filter "*.log" -ErrorAction SilentlyContinue |
                   Where-Object { $_.LastWriteTime -ge (Get-Date).AddDays(-$LogDays) })
        foreach ($file in $files) {
            $fs = $null; $reader = $null
            try {
                $fs     = [System.IO.File]::Open($file.FullName,
                            [System.IO.FileMode]::Open,
                            [System.IO.FileAccess]::Read,
                            [System.IO.FileShare]::ReadWrite)
                $reader = [System.IO.StreamReader]::new($fs)
                while (-not $reader.EndOfStream) {
                    $line = $reader.ReadLine()
                    $m    = [regex]::Match($line, $exprPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                    if (-not $m.Success) { continue }
                    $method = $m.Groups[1].Value.ToUpper()
                    $path   = $m.Groups[2].Value -replace '\?.*',''
                    if (-not (Test-ApiPath $path)) { continue }
                    $status = if ($m.Groups[3].Value) { [int]$m.Groups[3].Value } else { $null }
                    foreach ($hn in $hostnames) {
                        $key = "$method|$hn|$path"
                        if ($results.Add($key)) {
                            $endpoints.Add([PSCustomObject]@{
                                Host = $hn; Path = $path; Method = $method
                                Source = "Node:Log"; Status = $status
                                ContentType = ""; SampleRequest = ""; SampleResponse = ""
                            })
                        }
                    }
                }
            } catch {
                Write-Log WARN ("Node log read error " + $file.Name + ": " + $_) "E7002"
            } finally {
                if ($reader) { $reader.Close() }
                if ($fs)     { $fs.Close() }
            }
        }
    }

    $elapsed = [math]::Round(((Get-Date) - $t0).TotalSeconds, 2)
    Write-Log INFO ("Node.js logs: " + $endpoints.Count + " endpoints in " + $elapsed + "s.")
    return $endpoints
}

# ---------------------------------------------------------------------------
# Node SOURCE 2: package.json + source file route scanning
# Scans for Express app.get/post/put/delete/patch('/path', ...) definitions
# ---------------------------------------------------------------------------

function Get-EndpointsFromNodeSource([string[]]$hostnames) {
    Write-Header "Node.js Source 2: Source Route Scan"
    $t0 = Get-Date

    $appRoots = @()
    if ($NodeAppPath -and (Test-Path $NodeAppPath)) {
        $appRoots += $NodeAppPath
    } else {
        # Common locations
        foreach ($candidate in @("C:\apps", "C:\inetpub\nodejs", "C:\srv", "C:\www")) {
            if (Test-Path $candidate) { $appRoots += $candidate }
        }
    }
    if (-not $appRoots) {
        Write-Log INFO "No Node.js app directories found - skipping."
        return @()
    }

    $endpoints  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $seen       = [System.Collections.Generic.HashSet[string]]::new()
    # Match: app.get('/path', ...) router.post('/path', ...) router.all('/path', ...)
    $routePat   = [string]'(?:app|router)\.(get|post|put|delete|patch|all)\s*\(\s*[''"]([^''"]+)[''"]'

    foreach ($root in $appRoots) {
        $jsFiles = @(Get-ChildItem $root -Recurse -Depth 8 -Include "*.js","*.ts","*.mjs" -ErrorAction SilentlyContinue |
                     Where-Object { $_.FullName -notmatch 'node_modules' } |
                     Select-Object -First 500)
        foreach ($jsf in $jsFiles) {
            try {
                $content = [System.IO.File]::ReadAllText($jsf.FullName)
                $matches_ = [regex]::Matches($content, $routePat, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                foreach ($m in $matches_) {
                    $verb = $m.Groups[1].Value.ToLower()
                    $path = $m.Groups[2].Value
                    if (-not $path.StartsWith('/')) { $path = '/' + $path }
                    if (-not (Test-ApiPath $path)) { continue }
                    $methods = if ($verb -eq 'all') { @("GET","POST","PUT","DELETE","PATCH") } else { @($verb.ToUpper()) }
                    foreach ($hn in $hostnames) {
                        foreach ($method in $methods) {
                            $key = "$method|$hn|$path"
                            if ($seen.Add($key)) {
                                $endpoints.Add([PSCustomObject]@{
                                    Host = $hn; Path = $path; Method = $method
                                    Source = ("Node:Source:" + $jsf.Name)
                                    Status = $null; ContentType = ""
                                    SampleRequest = ""; SampleResponse = ""
                                })
                            }
                        }
                    }
                }
            } catch {
                Write-Log WARN ("Node source scan error " + $jsf.Name + ": " + $_) "E7002"
            }
        }
    }

    $elapsed = [math]::Round(((Get-Date) - $t0).TotalSeconds, 2)
    Write-Log INFO ("Node.js source: " + $endpoints.Count + " endpoints in " + $elapsed + "s.")
    return $endpoints
}

# ===========================================================================
# .NET KESTREL / ASP.NET CORE DISCOVERY
# ===========================================================================

function Get-EndpointsFromDotNetLogs([string[]]$hostnames) {
    Write-Header ".NET Source 1: Kestrel / ASP.NET Core Logs"
    $t0 = Get-Date

    $logRoots = @()
    if ($DotNetLogPath -and (Test-Path $DotNetLogPath)) {
        $logRoots += $DotNetLogPath
    } else {
        foreach ($candidate in @(
            "C:\inetpub\logs",
            "C:\apps",
            "C:\srv"
        )) {
            if (Test-Path $candidate) { $logRoots += $candidate }
        }
    }

    $endpoints = [System.Collections.Generic.List[PSCustomObject]]::new()
    $results   = [System.Collections.Generic.HashSet[string]]::new()
    # Kestrel stdout: "info: Microsoft.AspNetCore.Hosting... Request starting HTTP/1.1 GET https://host/path"
    # Also standard combined log format emitted by some ASP.NET middlewares
    $kestrelPat  = [string]'Request starting \S+ (GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+https?://([^/\s]+)(/[^\s]*)'
    $combinedPat = [string]'"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(/[^\s]*)\s+HTTP'

    foreach ($root in $logRoots) {
        $files = @(Get-ChildItem $root -Recurse -Filter "*.log" -ErrorAction SilentlyContinue |
                   Where-Object { $_.LastWriteTime -ge (Get-Date).AddDays(-$LogDays) } |
                   Select-Object -First 50)
        foreach ($file in $files) {
            $fs = $null; $reader = $null
            try {
                $fs     = [System.IO.File]::Open($file.FullName,
                            [System.IO.FileMode]::Open,
                            [System.IO.FileAccess]::Read,
                            [System.IO.FileShare]::ReadWrite)
                $reader = [System.IO.StreamReader]::new($fs)
                while (-not $reader.EndOfStream) {
                    $line = $reader.ReadLine()
                    $m    = [regex]::Match($line, $kestrelPat, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                    if ($m.Success) {
                        $method  = $m.Groups[1].Value.ToUpper()
                        $logHost = $m.Groups[2].Value.ToLower() -replace ':\d+$',''
                        $path    = $m.Groups[3].Value -replace '\?.*',''
                        if (Test-ApiPath $path) {
                            $key = "$method|$logHost|$path"
                            if ($results.Add($key)) {
                                $endpoints.Add([PSCustomObject]@{
                                    Host = $logHost; Path = $path; Method = $method
                                    Source = ".NET:KestrelLog"; Status = $null
                                    ContentType = ""; SampleRequest = ""; SampleResponse = ""
                                })
                            }
                        }
                        continue
                    }
                    $m = [regex]::Match($line, $combinedPat)
                    if ($m.Success) {
                        $method = $m.Groups[1].Value.ToUpper()
                        $path   = $m.Groups[2].Value -replace '\?.*',''
                        if (-not (Test-ApiPath $path)) { continue }
                        foreach ($hn in $hostnames) {
                            $key = "$method|$hn|$path"
                            if ($results.Add($key)) {
                                $endpoints.Add([PSCustomObject]@{
                                    Host = $hn; Path = $path; Method = $method
                                    Source = ".NET:Log"; Status = $null
                                    ContentType = ""; SampleRequest = ""; SampleResponse = ""
                                })
                            }
                        }
                    }
                }
            } catch {
                Write-Log WARN (".NET log read error " + $file.Name + ": " + $_) "E8002"
            } finally {
                if ($reader) { $reader.Close() }
                if ($fs)     { $fs.Close() }
            }
        }
    }

    $elapsed = [math]::Round(((Get-Date) - $t0).TotalSeconds, 2)
    Write-Log INFO (".NET logs: " + $endpoints.Count + " endpoints in " + $elapsed + "s.")
    return $endpoints
}

function Get-EndpointsFromDotNetSource([string[]]$hostnames) {
    Write-Header ".NET Source 2: launchSettings.json / Route Attributes"
    $t0 = Get-Date

    $appRoots = @()
    if ($DotNetAppPath -and (Test-Path $DotNetAppPath)) {
        $appRoots += $DotNetAppPath
    } else {
        foreach ($candidate in @("C:\apps", "C:\inetpub\wwwroot", "C:\srv")) {
            if (Test-Path $candidate) { $appRoots += $candidate }
        }
    }

    $endpoints = [System.Collections.Generic.List[PSCustomObject]]::new()
    $seen      = [System.Collections.Generic.HashSet[string]]::new()
    # [HttpGet("/api/v1/users")]  [Route("api/[controller]")]
    $attrPat   = [string]'\[Http(Get|Post|Put|Delete|Patch)\s*\(\s*"([^"]+)"\s*\)\]'
    $routePat  = [string]'\[Route\s*\(\s*"([^"]+)"\s*\)\]'

    foreach ($root in $appRoots) {
        $csFiles = @(Get-ChildItem $root -Recurse -Depth 8 -Include "*.cs" -ErrorAction SilentlyContinue |
                     Where-Object { $_.FullName -notmatch '\\obj\\|\\bin\\' } |
                     Select-Object -First 500)
        foreach ($csf in $csFiles) {
            try {
                $content  = [System.IO.File]::ReadAllText($csf.FullName)
                $attrMs   = [regex]::Matches($content, $attrPat, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                foreach ($m in $attrMs) {
                    $method = $m.Groups[1].Value.ToUpper()
                    $path   = $m.Groups[2].Value
                    if (-not $path.StartsWith('/')) { $path = '/' + $path }
                    # Normalise [controller] / [action] tokens
                    $path = $path -replace '\[controller\]', '{controller}' -replace '\[action\]', '{action}'
                    if (-not (Test-ApiPath $path)) { continue }
                    foreach ($hn in $hostnames) {
                        $key = "$method|$hn|$path"
                        if ($seen.Add($key)) {
                            $endpoints.Add([PSCustomObject]@{
                                Host = $hn; Path = $path; Method = $method
                                Source = (".NET:Source:" + $csf.Name)
                                Status = $null; ContentType = ""
                                SampleRequest = ""; SampleResponse = ""
                            })
                        }
                    }
                }
            } catch {
                Write-Log WARN (".NET source scan error " + $csf.Name + ": " + $_) "E8002"
            }
        }
    }

    $elapsed = [math]::Round(((Get-Date) - $t0).TotalSeconds, 2)
    Write-Log INFO (".NET source: " + $endpoints.Count + " endpoints in " + $elapsed + "s.")
    return $endpoints
}

# ===========================================================================
# PYTHON (FLASK / FASTAPI / DJANGO) DISCOVERY
# ===========================================================================

function Get-EndpointsFromPythonLogs([string[]]$hostnames) {
    Write-Header "Python Source 1: WSGI/ASGI Logs"
    $t0 = Get-Date

    $logRoots = @()
    if ($PythonLogPath -and (Test-Path $PythonLogPath)) {
        $logRoots += $PythonLogPath
    } else {
        foreach ($candidate in @("C:\apps", "C:\srv", "C:\inetpub\logs")) {
            if (Test-Path $candidate) { $logRoots += $candidate }
        }
    }

    $endpoints = [System.Collections.Generic.List[PSCustomObject]]::new()
    $results   = [System.Collections.Generic.HashSet[string]]::new()
    # Gunicorn/Waitress/uvicorn: "GET /api/v1/users HTTP/1.1" 200
    $accessPat  = [string]'"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(/[^\s"]*)\s+HTTP/[^"]*"\s+(\d{3})'
    # uvicorn info log: INFO:     127.0.0.1:port - "GET /path HTTP/1.1" 200
    $uvicornPat = [string]'"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(/[^\s"]*)\s+HTTP'

    foreach ($root in $logRoots) {
        $files = @(Get-ChildItem $root -Recurse -Filter "*.log" -ErrorAction SilentlyContinue |
                   Where-Object { $_.LastWriteTime -ge (Get-Date).AddDays(-$LogDays) } |
                   Select-Object -First 50)
        foreach ($file in $files) {
            $fs = $null; $reader = $null
            try {
                $fs     = [System.IO.File]::Open($file.FullName,
                            [System.IO.FileMode]::Open,
                            [System.IO.FileAccess]::Read,
                            [System.IO.FileShare]::ReadWrite)
                $reader = [System.IO.StreamReader]::new($fs)
                while (-not $reader.EndOfStream) {
                    $line = $reader.ReadLine()
                    $m    = [regex]::Match($line, $accessPat)
                    if (-not $m.Success) { $m = [regex]::Match($line, $uvicornPat) }
                    if (-not $m.Success) { continue }
                    $method = $m.Groups[1].Value.ToUpper()
                    $path   = $m.Groups[2].Value -replace '\?.*',''
                    if (-not (Test-ApiPath $path)) { continue }
                    $status = if ($m.Groups[3].Success -and $m.Groups[3].Value) { [int]$m.Groups[3].Value } else { $null }
                    foreach ($hn in $hostnames) {
                        $key = "$method|$hn|$path"
                        if ($results.Add($key)) {
                            $endpoints.Add([PSCustomObject]@{
                                Host = $hn; Path = $path; Method = $method
                                Source = "Python:Log"; Status = $status
                                ContentType = ""; SampleRequest = ""; SampleResponse = ""
                            })
                        }
                    }
                }
            } catch {
                Write-Log WARN ("Python log read error " + $file.Name + ": " + $_) "E9002"
            } finally {
                if ($reader) { $reader.Close() }
                if ($fs)     { $fs.Close() }
            }
        }
    }

    $elapsed = [math]::Round(((Get-Date) - $t0).TotalSeconds, 2)
    Write-Log INFO ("Python logs: " + $endpoints.Count + " endpoints in " + $elapsed + "s.")
    return $endpoints
}

function Get-EndpointsFromPythonSource([string[]]$hostnames) {
    Write-Header "Python Source 2: Flask/FastAPI Route Scan"
    $t0 = Get-Date

    $appRoots = @()
    if ($PythonAppPath -and (Test-Path $PythonAppPath)) {
        $appRoots += $PythonAppPath
    } else {
        foreach ($candidate in @("C:\apps", "C:\srv", "C:\inetpub\python")) {
            if (Test-Path $candidate) { $appRoots += $candidate }
        }
    }

    $endpoints = [System.Collections.Generic.List[PSCustomObject]]::new()
    $seen      = [System.Collections.Generic.HashSet[string]]::new()
    # Flask:   @app.route('/path', methods=['GET','POST'])
    # FastAPI: @app.get('/path')  @router.post('/path')
    $flaskPat   = [string]'@\w+\.route\s*\(\s*''([^'']+)''[^)]*methods\s*=\s*\[([^\]]+)\]'
    $fastapiPat = [string]'@(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*''([^'']+)'''

    foreach ($root in $appRoots) {
        $pyFiles = @(Get-ChildItem $root -Recurse -Include "*.py" -ErrorAction SilentlyContinue |
                     Where-Object { $_.FullName -notmatch '\\__pycache__\\|\\venv\\|\\\.venv\\' } |
                     Select-Object -First 500)
        foreach ($pyf in $pyFiles) {
            try {
                $content = [System.IO.File]::ReadAllText($pyf.FullName)

                # Flask routes
                $flaskMs = [regex]::Matches($content, $flaskPat, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                foreach ($m in $flaskMs) {
                    $path    = $m.Groups[1].Value
                    if (-not $path.StartsWith('/')) { $path = '/' + $path }
                    $methods = $m.Groups[2].Value -split ',' |
                               ForEach-Object { $_.Trim().Trim('"').Trim("'").ToUpper() } |
                               Where-Object { $_ -match '^(GET|POST|PUT|DELETE|PATCH)$' }
                    if (-not (Test-ApiPath $path)) { continue }
                    foreach ($hn in $hostnames) {
                        foreach ($method in $methods) {
                            $key = "$method|$hn|$path"
                            if ($seen.Add($key)) {
                                $endpoints.Add([PSCustomObject]@{
                                    Host = $hn; Path = $path; Method = $method
                                    Source = ("Python:Flask:" + $pyf.Name)
                                    Status = $null; ContentType = ""
                                    SampleRequest = ""; SampleResponse = ""
                                })
                            }
                        }
                    }
                }

                # FastAPI routes
                $fastapiMs = [regex]::Matches($content, $fastapiPat, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                foreach ($m in $fastapiMs) {
                    $method = $m.Groups[1].Value.ToUpper()
                    $path   = $m.Groups[2].Value
                    if (-not $path.StartsWith('/')) { $path = '/' + $path }
                    if (-not (Test-ApiPath $path)) { continue }
                    foreach ($hn in $hostnames) {
                        $key = "$method|$hn|$path"
                        if ($seen.Add($key)) {
                            $endpoints.Add([PSCustomObject]@{
                                Host = $hn; Path = $path; Method = $method
                                Source = ("Python:FastAPI:" + $pyf.Name)
                                Status = $null; ContentType = ""
                                SampleRequest = ""; SampleResponse = ""
                            })
                        }
                    }
                }
            } catch {
                Write-Log WARN ("Python source scan error " + $pyf.Name + ": " + $_) "E9002"
            }
        }
    }

    $elapsed = [math]::Round(((Get-Date) - $t0).TotalSeconds, 2)
    Write-Log INFO ("Python source: " + $endpoints.Count + " endpoints in " + $elapsed + "s.")
    return $endpoints
}

# ---------------------------------------------------------------------------
# Deduplication and merge
# ---------------------------------------------------------------------------

function Merge-Endpoints([array]$all) {
    Write-Header "Deduplicating"
    $t0     = Get-Date
    $index  = [System.Collections.Generic.Dictionary[string,int]]::new()
    $unique = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($ep in $all) {
        $normPath = (($ep.Path -replace '\?.*','') -replace '//+', '/').ToLower()
        $key      = "$($ep.Method.ToUpper())|$($ep.Host.ToLower())|$normPath"

        if (-not $index.ContainsKey($key)) {
            $index[$key] = $unique.Count
            $unique.Add([PSCustomObject]@{
                Host           = $ep.Host.ToLower()
                Path           = $normPath
                Method         = $ep.Method.ToUpper()
                Source         = $ep.Source
                Status         = $ep.Status
                ContentType    = $ep.ContentType
                SampleRequest  = $ep.SampleRequest
                SampleResponse = $ep.SampleResponse
            })
        } else {
            $existing = $unique[$index[$key]]
            if (-not $existing.Status         -and $ep.Status)         { $existing.Status         = $ep.Status }
            if (-not $existing.ContentType    -and $ep.ContentType)    { $existing.ContentType    = $ep.ContentType }
            if (-not $existing.SampleRequest  -and $ep.SampleRequest)  { $existing.SampleRequest  = $ep.SampleRequest }
            if (-not $existing.SampleResponse -and $ep.SampleResponse) { $existing.SampleResponse = $ep.SampleResponse }
            if ($ep.Source -eq "AccessLog") { $existing.Source = "AccessLog" }
        }
    }

    $elapsed = [math]::Round(((Get-Date) - $t0).TotalSeconds, 2)
    Write-Log INFO "Dedup: $($all.Count) raw -> $($unique.Count) unique in ${elapsed}s."
    return $unique
}

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

function Export-Inventory([array]$endpoints, [string]$format, [string]$path) {
    switch ($format) {
        "CSV" {
            $endpoints | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
            Write-Log INFO "CSV written to: $path"
        }
        "JSON" {
            $endpoints | ConvertTo-Json -Depth 3 | Set-Content -Path $path -Encoding UTF8
            Write-Log INFO "JSON written to: $path"
        }
        default {
            Write-Header "API Inventory"
            $endpoints | Format-Table Host, Method, Path, Status, ContentType, Source -AutoSize
        }
    }
}

# ---------------------------------------------------------------------------
# Engine POST (bulk synthetic packet pairs)
# ---------------------------------------------------------------------------

function Build-Packet([PSCustomObject]$ep, [long]$ts, [string]$localIp,
                      [int]$sourceType, [int]$sourceIndex, [string]$sourceKey) {
    $ct = if ($ep.ContentType) { $ep.ContentType } else { "application/json" }
    return [ordered]@{
        ip     = [ordered]@{ v = "4"; src = "127.0.0.1"; dst = $localIp }
        tcp    = [ordered]@{ src = 0; dst = $Port }
        http   = [ordered]@{
            v        = "1.1"
            request  = [ordered]@{
                ts      = $ts
                method  = $ep.Method
                url     = $ep.Path
                headers = [ordered]@{ host = $ep.Host }
                body    = ""
            }
            response = [ordered]@{
                ts      = $ts
                status  = if ($ep.Status) { $ep.Status } else { 200 }
                headers = [ordered]@{ "content-type" = $ct }
                body    = ""
            }
        }
        source = [ordered]@{
            type  = $sourceType
            index = $sourceIndex
            key   = $sourceKey
        }
    }
}

function Send-ToEngine([array]$endpoints, [string]$engineUrl,
                       [int]$sourceType, [int]$sourceIndex, [string]$sourceKey,
                       [bool]$skipTls) {

    Write-Header "Posting to Engine: $engineUrl"

    $invokeArgs = @{
        Uri         = $engineUrl
        Method      = 'POST'
        ContentType = 'application/json'
        ErrorAction = 'Stop'
    }
    if ($skipTls) {
        Write-Log WARN "TLS certificate verification disabled. Test environments only."
    }

    Test-EngineConnectivity $engineUrl $skipTls

    $ts      = [long][double]::Parse((Get-Date -UFormat %s))
    $localIp = (Get-NetIPAddress -AddressFamily IPv4 |
                Where-Object { $_.InterfaceAlias -notmatch 'Loopback' } |
                Select-Object -First 1).IPAddress
    if (-not $localIp) { $localIp = "127.0.0.1" }

    $packets = [System.Collections.Generic.List[object]]::new()
    foreach ($ep in $endpoints) {
        if ($ep.Method -eq "UNKNOWN") { continue }
        $packets.Add((Build-Packet $ep $ts $localIp $sourceType $sourceIndex $sourceKey))
    }

    Write-Log INFO "Sending $($packets.Count) packets in batches of $BatchSize..."

    $sent         = 0
    $failed       = 0
    $batchNum     = 0
    $batchFailed  = 0
    $t0           = Get-Date

    for ($i = 0; $i -lt $packets.Count; $i += $BatchSize) {
        $batchNum++
        $batch              = $packets[$i .. [Math]::Min($i + $BatchSize - 1, $packets.Count - 1)]
        $invokeArgs['Body'] = ($batch | ConvertTo-Json -Depth 8 -Compress)

        try {
            $bt0  = Get-Date
            $null = if ($skipTls) { Invoke-RestSkipTls $invokeArgs } else { Invoke-RestMethod @invokeArgs }
            $bms  = [math]::Round(((Get-Date) - $bt0).TotalMilliseconds)
            $sent += $batch.Count
            Write-Verbose "  Batch $batchNum/$([Math]::Ceiling($packets.Count / $BatchSize)): $($batch.Count) packets in ${bms}ms"
        } catch {
            Write-Log WARN "Batch $batchNum failed: $_" "E2002"
            $failed      += $batch.Count
            $batchFailed++
        }
    }

    $elapsed = [math]::Round(((Get-Date) - $t0).TotalSeconds, 2)
    $Script:Telemetry['PacketsSent']    = $sent
    $Script:Telemetry['PacketsFailed']  = $failed
    $Script:Telemetry['BatchesSent']    = $batchNum - $batchFailed
    $Script:Telemetry['BatchesFailed']  = $batchFailed

    $color = if ($failed -eq 0) { "Green" } else { "Yellow" }
    Write-Host "  Sent: $sent  Failed: $failed  Duration: ${elapsed}s" -ForegroundColor $color
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Header "Hostname Discovery"
$catHome = Resolve-CatalinaHome
$Script:Telemetry['CatalinaHome'] = if ($catHome) { $catHome } else { "not found" }

$hostsFileNames = @(Resolve-LocalHostnames)
$serverXmlNames = if ($catHome) { @(Resolve-HostnamesFromServerXml $catHome) } else { @() }
$iisNames       = if (-not $SkipIIS) { @(Get-HostnamesFromIIS) } else { @() }

$seenHn    = [System.Collections.Generic.HashSet[string]]::new()
$hostnames = [System.Collections.Generic.List[string]]::new()
foreach ($n in ($hostsFileNames + $serverXmlNames + $iisNames)) {
    if ($n -and $seenHn.Add($n.ToLower())) { $hostnames.Add($n.ToLower()) }
}
if ($hostnames.Count -eq 0) { $hostnames.Add("localhost") }
Write-Log INFO "Combined hostnames: $($hostnames -join ', ')"

$hostnames = $hostnames.ToArray()
$all       = [System.Collections.Generic.List[PSCustomObject]]::new()

# --- Tomcat ---
if ($catHome) {
    Write-Log INFO "Tomcat home: $catHome"
    foreach ($ep in @(Get-EndpointsFromLogs   $catHome))            { $all.Add($ep) }
    foreach ($ep in @(Get-EndpointsFromWebXml $catHome $hostnames)) { $all.Add($ep) }
    foreach ($ep in @(Get-EndpointsFromWars   $catHome $hostnames)) { $all.Add($ep) }
} else {
    Write-Log WARN "Skipping Tomcat discovery - home not found." "E5002"
}

# --- IIS ---
if (-not $SkipIIS) {
    foreach ($ep in @(Get-EndpointsFromIISLogs      $hostnames)) { $all.Add($ep) }
    foreach ($ep in @(Get-EndpointsFromIISWebConfig $hostnames)) { $all.Add($ep) }
}

# --- Node.js ---
if (-not $SkipNode) {
    foreach ($ep in @(Get-EndpointsFromNodeLogs   $hostnames)) { $all.Add($ep) }
    foreach ($ep in @(Get-EndpointsFromNodeSource $hostnames)) { $all.Add($ep) }
}

# --- .NET Kestrel / ASP.NET Core ---
if (-not $SkipDotNet) {
    foreach ($ep in @(Get-EndpointsFromDotNetLogs   $hostnames)) { $all.Add($ep) }
    foreach ($ep in @(Get-EndpointsFromDotNetSource $hostnames)) { $all.Add($ep) }
}

# --- Python (Flask / FastAPI / Django) ---
if (-not $SkipPython) {
    foreach ($ep in @(Get-EndpointsFromPythonLogs   $hostnames)) { $all.Add($ep) }
    foreach ($ep in @(Get-EndpointsFromPythonSource $hostnames)) { $all.Add($ep) }
}

# --- Netstat (all runtimes) ---
foreach ($ep in @(Get-EndpointsFromNetstat $Port)) { $all.Add($ep) }

$Script:Telemetry['EndpointsRaw'] = $all.Count
$inventory = @(Merge-Endpoints $all.ToArray())
$Script:Telemetry['EndpointsUnique'] = $inventory.Count

if ($inventory.Count -eq 0) {
    Write-Log WARN "No API endpoints discovered." "E5001"
    Exit-Script 0
}

if ($OutputFormat -ne "Console" -and -not $OutputPath) {
    Write-Log ERROR "-OutputPath is required when -OutputFormat is '$OutputFormat'." "E1005"
    Exit-Script 1
}

Export-Inventory $inventory $OutputFormat $OutputPath

if ($DynatraceUrl -and $DynatraceToken) {
    Send-EndpointsToDynatrace $inventory
}

if ($EngineUrl) {
    if (-not $SourceKey) {
        Write-Log ERROR "-SourceKey is required when -EngineUrl is provided." "E1004"
        Exit-Script 1
    }
    Send-ToEngine $inventory $EngineUrl $SourceType $SourceIndex $SourceKey $SkipTlsVerify.IsPresent
}

Exit-Script 0
