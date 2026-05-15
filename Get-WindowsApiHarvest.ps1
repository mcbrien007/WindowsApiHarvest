 <#
.SYNOPSIS
    Discovers API services on the local machine and outputs a normalized endpoint
    inventory as objects (and optionally to CSV).

.DESCRIPTION
    Harvests API endpoints from multiple discovery sources:
      - IIS W3SVC access logs
      - Tomcat access logs + server.xml + web.xml servlet mappings
      - Java / Spring Boot / Jetty / Undertow process inspection
      - Python (Flask, Django, FastAPI, uvicorn, gunicorn, waitress) logs + source routes
      - Node.js (Express, Fastify, Koa, NestJS) logs + source routes
      - .NET Core / Kestrel self-hosted
      - nginx / Apache / other HTTP listeners
      - OpenAPI / Swagger spec files (JSON + YAML)
      - Source-code decorator/route extraction (Python + Node.js)

    Each discovered endpoint is validated (optionally via GET probe), normalized,
    and deduplicated. Results are returned as PSObjects and optionally exported to CSV.

    Designed to be deployed across a fleet via WinRM:
      Invoke-Command -ComputerName (Get-Content servers.txt) `
                     -FilePath .\Harvest-ApiInventory.ps1

.PARAMETER Platforms
    Which runtime platforms to scan. Default: All.

.PARAMETER DebugMode
    Enables verbose console output alongside log file.

.PARAMETER OutputCsv
    Optional file path to export results as CSV. If omitted, results are returned
    as pipeline objects only. When run via Invoke-Command, objects serialize back
    to the caller automatically.

.PARAMETER LogLookbackHours
    Only parse log files modified within this window. Default: 168 (7 days).

.PARAMETER MaxSourceFiles
    Max source code files to scan per discovered service. Default: 50.

.PARAMETER MaxSpecFiles
    Max OpenAPI/Swagger spec files to parse per search root. Default: 10.

.PARAMETER SearchDepth
    Max directory recursion depth when searching for specs/source. Default: 5.

.EXAMPLE
    # Local dry run
    .\Harvest-ApiInventory.ps1 -DebugMode

.EXAMPLE
    # Fleet scan via WinRM, collect into single CSV
    $results = Invoke-Command -ComputerName (Get-Content servers.txt) `
                   -FilePath .\Harvest-ApiInventory.ps1 -Credential $cred -ThrottleLimit 20
    $results | Export-Csv -Path .\fleet_apis.csv -NoTypeInformation

.EXAMPLE
    # Local scan with CSV output
    .\Harvest-ApiInventory.ps1 -OutputCsv C:\Reports\apis.csv -DebugMode

.NOTES
    Author:  Patrick / TDBank IIS AppSec SOC
    Version: 2.1.0
    Requires: PowerShell 5.1+
#>

[CmdletBinding()]
param(
    [ValidateSet("All","IIS","Tomcat","Process","Java","SpringBoot","Jetty","Undertow",
                 "NodeJS",".NET","nginx","Apache","Python","Flask","Django","FastAPI","Other","IISWorker")]
    [string[]]$Platforms = @("All"),

    [switch]$DebugMode,

    [string]$OutputCsv,

    [int]$ProbeTimeoutSec = 5,
    [int]$MaxLogFiles = 100,
    [int]$MaxProbeCount = 50,
    [int]$ProbeDelayMs = 250,
    [int]$MaxBodyChars = 512,
    [int]$LogLookbackHours = 168,
    [int]$MaxSourceFiles = 50,
    [int]$MaxSpecFiles = 10,
    [int]$SearchDepth = 5,
    [switch]$DisableGetValidation,
    [switch]$DisableSourceCodeScan,
    [switch]$DisableSpecScan,
    [switch]$IgnoreCertificateErrors
)

# -------------------------------------------------------------------
# GLOBALS
# -------------------------------------------------------------------
$ErrorActionPreference = "Stop"
$LogFile = Join-Path $env:TEMP ("harvest-api-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".log")
$Global:ProbeCache = @{}
$Global:ProbeCount = 0
$Global:LogCutoff = (Get-Date).AddHours(-$LogLookbackHours)
$script:InstanceMutex = $null
$script:MutexAcquired = $false

# -------------------------------------------------------------------
# LOGGING
# -------------------------------------------------------------------
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    try { Add-Content -Path $LogFile -Value $line -ErrorAction Stop } catch {}

    if ($DebugMode) {
        switch ($Level) {
            "ERROR" { Write-Host $line -ForegroundColor Red }
            "WARN"  { Write-Host $line -ForegroundColor Yellow }
            default { Write-Host $line }
        }
    }
}

# -------------------------------------------------------------------
# PLATFORM FILTER
# -------------------------------------------------------------------
function Test-PlatformEnabled {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (-not $Platforms -or $Platforms.Count -eq 0) { return $false }
    if ($Platforms -contains "All") { return $true }
    return $Platforms -contains $Name
}

# -------------------------------------------------------------------
# SINGLE-INSTANCE MUTEX
# -------------------------------------------------------------------
function Enter-SingleInstance {
    param(
        [string]$Name = "Global\HarvestApiInventoryMutex"
    )
    try {
        $createdNew = $false
        $script:InstanceMutex = New-Object System.Threading.Mutex($true, $Name, [ref]$createdNew)

        if (-not $createdNew) {
            Write-Log "Another instance is already running. Exiting." "WARN"
            return $false
        }
        $script:MutexAcquired = $true
        Write-Log "Single-instance lock acquired: $Name"
        return $true
    }
    catch {
        Write-Log "Failed to acquire single-instance lock: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Exit-SingleInstance {
    try {
        if ($script:InstanceMutex -and $script:MutexAcquired) {
            $script:InstanceMutex.ReleaseMutex()
            $script:MutexAcquired = $false
            Write-Log "Single-instance lock released"
        }
    }
    catch {}
    finally {
        if ($script:InstanceMutex) {
            $script:InstanceMutex.Dispose()
            $script:InstanceMutex = $null
        }
    }
}

# -------------------------------------------------------------------
# TLS + CERTIFICATE HANDLING
# -------------------------------------------------------------------
function Initialize-Tls {
    try {
        if ([Net.ServicePointManager]::SecurityProtocol -band [Net.SecurityProtocolType]::Tls12) {
            Write-Log "TLS 1.2 already enabled"
        }
        else {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            Write-Log "Enabled TLS 1.2 for outbound requests"
        }
    }
    catch {
        Write-Log "Failed to initialize TLS preferences: $($_.Exception.Message)" "WARN"
    }
}

function Initialize-CertificateBypassForLegacyPowerShell {
    if (-not $IgnoreCertificateErrors) { return }
    if ($PSVersionTable.PSVersion.Major -ge 7) { return }

    try {
        Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@ -ErrorAction SilentlyContinue

        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        Write-Log "Enabled legacy certificate bypass for Windows PowerShell"
    }
    catch {
        Write-Log "Failed to enable legacy certificate bypass: $($_.Exception.Message)" "WARN"
    }
}

# -------------------------------------------------------------------
# HTTP COMPAT WRAPPERS (PS5.1 + PS7)
# -------------------------------------------------------------------
function Invoke-WebRequestCompat {
    param(
        [Parameter(Mandatory)] [string]$Uri,
        [Parameter(Mandatory)] [string]$Method,
        [hashtable]$Headers,
        [string]$Body,
        [int]$TimeoutSec = 30,
        [string]$ContentType
    )

    $params = @{
        Uri         = $Uri
        Method      = $Method
        TimeoutSec  = $TimeoutSec
        ErrorAction = "Stop"
    }
    if ($Headers)     { $params["Headers"]     = $Headers }
    if ($Body)        { $params["Body"]        = $Body }
    if ($ContentType) { $params["ContentType"] = $ContentType }

    if ($PSVersionTable.PSVersion.Major -ge 7) {
        if ($IgnoreCertificateErrors) { $params["SkipCertificateCheck"] = $true }
        return Invoke-WebRequest @params
    }
    else {
        $params["UseBasicParsing"] = $true
        return Invoke-WebRequest @params
    }
}

# -------------------------------------------------------------------
# PREFLIGHT
# -------------------------------------------------------------------
function Test-IsAdministrator {
    try {
        $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

function Invoke-PreflightChecks {
    Write-Log "Starting preflight checks"
    Initialize-Tls
    Initialize-CertificateBypassForLegacyPowerShell

    Write-Log ("PowerShellVersion: " + $PSVersionTable.PSVersion.ToString())
    Write-Log ("Edition: " + $PSVersionTable.PSEdition)
    Write-Log ("Is64BitProcess: " + [Environment]::Is64BitProcess)
    Write-Log ("IsAdministrator: " + (Test-IsAdministrator))
    Write-Log ("IgnoreCertificateErrors: " + $IgnoreCertificateErrors)
    Write-Log ("Platforms: " + ($Platforms -join ","))
    Write-Log ("LogLookbackHours: $LogLookbackHours")
    Write-Log ("DisableSourceCodeScan: $DisableSourceCodeScan")
    Write-Log ("DisableSpecScan: $DisableSpecScan")

    if ($PSVersionTable.PSVersion.Major -lt 5) {
        throw "PowerShell 5.1 or later is required."
    }

    if (-not [Environment]::Is64BitProcess) {
        Write-Log "Script is running in 32-bit PowerShell. Some discovery paths may be incomplete." "WARN"
    }
}

# -------------------------------------------------------------------
# PATH NORMALIZATION + CLASSIFICATION
# -------------------------------------------------------------------
function Normalize-UrlPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return "/" }

    $normalized = "/" + ($Path.Trim() -replace '^/+', '')
    $normalized = $normalized -replace '/{2,}', '/'

    # Collapse numeric IDs and GUIDs into parameter placeholders
    $normalized = $normalized -replace '/\d{2,}(/|$)', '/{id}$1'
    $normalized = $normalized -replace '/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(/|$)', '/{uuid}$1'
    # Collapse hex-like tokens (MongoDB ObjectId, etc.)
    $normalized = $normalized -replace '/[0-9a-fA-F]{24}(/|$)', '/{objectid}$1'

    return $normalized
}

function Get-ServerDnsFqdn {
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        if ($cs.DNSHostName -and $cs.Domain) {
            return ("{0}.{1}" -f $cs.DNSHostName, $cs.Domain).ToLowerInvariant()
        }
    } catch {}

    try {
        $ipProps = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        if ($ipProps.HostName -and $ipProps.DomainName) {
            return ("{0}.{1}" -f $ipProps.HostName, $ipProps.DomainName).ToLowerInvariant()
        }
    } catch {}

    try {
        return ([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME)).HostName.ToLowerInvariant()
    } catch {}

    return $env:COMPUTERNAME.ToLowerInvariant()
}

function Get-IISBindingHostCandidates {
    $bindingHosts = @()
    $appCmdPath = Join-Path $env:windir "System32\inetsrv\appcmd.exe"

    if (-not (Test-Path $appCmdPath)) { return @() }

    try {
        $output = & $appCmdPath list site /text:bindings 2>$null
        foreach ($line in $output) {
            foreach ($binding in ($line -split ',')) {
                $trimmedBinding = $binding.Trim()
                if ($trimmedBinding -match ':(\d+):(.*)$') {
                    $candidateHost = $matches[2].Trim()
                    if (-not [string]::IsNullOrWhiteSpace($candidateHost) -and $candidateHost -ne "*") {
                        $bindingHosts += $candidateHost.ToLowerInvariant()
                    }
                }
            }
        }
    } catch {}

    return $bindingHosts | Select-Object -Unique
}

function Get-BestHostname {
    param([string]$ObservedHost)

    if (-not [string]::IsNullOrWhiteSpace($ObservedHost) -and $ObservedHost -ne "-") {
        return $ObservedHost.ToLowerInvariant()
    }

    $bindingHost = Get-IISBindingHostCandidates | Select-Object -First 1
    if ($bindingHost) { return $bindingHost }

    return Get-ServerDnsFqdn
}

function Build-BaseUrl {
    param(
        [string]$Host_,
        [int]$Port
    )
    if ($Port -eq 443 -or $Port -eq 8443) { $scheme = "https" }
    else { $scheme = "http" }

    $baseUrl = "${scheme}://$Host_"
    if (($scheme -eq "http" -and $Port -ne 80) -or ($scheme -eq "https" -and $Port -ne 443)) {
        $baseUrl = "${baseUrl}:$Port"
    }
    return $baseUrl
}

# -------------------------------------------------------------------
# PATH CLASSIFICATION FILTERS
# -------------------------------------------------------------------
function Test-IsKnownApiGetPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -eq "-") { return $false }

    $p = $Path.Trim().ToLowerInvariant()

    return (
        $p -eq "/health" -or
        $p -eq "/healthz" -or
        $p -eq "/ready" -or
        $p -eq "/readiness" -or
        $p -eq "/live" -or
        $p -eq "/liveness" -or
        $p -eq "/status" -or
        $p -eq "/metrics" -or
        $p -eq "/actuator/health" -or
        $p -eq "/actuator/info" -or
        $p -eq "/actuator/metrics" -or
        $p -like "/api/health*" -or
        $p -like "/api/status*" -or
        $p -like "/api/metrics*" -or
        $p -like "/api/*/health*" -or
        $p -like "/api/*/status*" -or
        $p -like "/swagger*" -or
        $p -like "/openapi*" -or
        $p -like "/v3/api-docs*"
    )
}

function Test-IsApiLikePath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -eq "-") { return $false }

    $normalizedPath = $Path.Trim().ToLowerInvariant()

    $excludedExtensions = @(
        ".html", ".htm", ".css", ".js", ".mjs",
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".map", ".txt", ".pdf", ".zip", ".gz", ".tgz", ".rar", ".7z",
        ".mp3", ".wav", ".mp4", ".avi", ".mov", ".webm"
    )

    foreach ($ext in $excludedExtensions) {
        if ($normalizedPath.EndsWith($ext)) { return $false }
    }

    if (Test-IsKnownApiGetPath -Path $normalizedPath) { return $true }

    $apiIndicators = @(
        "/api/", "/rest/", "/graphql", "/grpc", "/odata/", "/services/",
        "/swagger", "/openapi",
        "/v1/", "/v2/", "/v3/", "/v4/",
        "/actuator/"
    )
    foreach ($indicator in $apiIndicators) {
        if ($normalizedPath.Contains($indicator)) { return $true }
    }

    if ($normalizedPath.EndsWith(".json") -or $normalizedPath.EndsWith(".xml")) { return $true }
    if ($normalizedPath -match '^/[a-z0-9\-_]+(/[a-z0-9\-_{}.:]+)+$') { return $true }

    return $false
}

function Test-IsApiLikeMethod {
    param([string]$Method)

    if ([string]::IsNullOrWhiteSpace($Method) -or $Method -eq "-") { return $false }
    return @("GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD") -contains $Method.ToUpperInvariant()
}

# -------------------------------------------------------------------
# GET-PROBE VALIDATION
# -------------------------------------------------------------------
function Get-SafeResponseContentType {
    param([string]$Url)
    try {
        $headResponse = Invoke-WebRequestCompat `
            -Uri $Url -Method HEAD -TimeoutSec $ProbeTimeoutSec `
            -Headers @{ Accept = "application/json, application/xml, text/xml, text/json, */*" }

        if ($headResponse.Headers -and $headResponse.Headers["Content-Type"]) {
            return $headResponse.Headers["Content-Type"].ToString().ToLowerInvariant()
        }
    } catch {}
    return $null
}

function Test-ResponseLooksLikeApi {
    param([Parameter(Mandatory)] [string]$Url)

    if ($DisableGetValidation) { return $true }
    if ($Global:ProbeCache.ContainsKey($Url)) { return $Global:ProbeCache[$Url] }

    if ($Global:ProbeCount -ge $MaxProbeCount) {
        Write-Log "Max probe count reached ($MaxProbeCount). Skipping further GET validation." "WARN"
        $Global:ProbeCache[$Url] = $false
        return $false
    }

    $Global:ProbeCount++
    Start-Sleep -Milliseconds $ProbeDelayMs

    try {
        Write-Log "Probing GET endpoint safely: $Url"

        $contentType = Get-SafeResponseContentType -Url $Url
        if ($contentType -and ($contentType -match 'application/json|text/json|application/.+\+json|application/xml|text/xml|application/.+\+xml')) {
            Write-Log "GET probe accepted by HEAD Content-Type '$contentType': $Url"
            $Global:ProbeCache[$Url] = $true
            return $true
        }

        $response = Invoke-WebRequestCompat `
            -Uri $Url -Method GET -TimeoutSec $ProbeTimeoutSec `
            -Headers @{ Accept = "application/json, application/xml, text/xml, text/json, */*" }

        $body = ""
        if ($null -ne $response.Content) {
            $body = $response.Content.ToString()
            if ($body.Length -gt $MaxBodyChars) { $body = $body.Substring(0, $MaxBodyChars) }
            $body = $body.Trim()
        }

        $isApi = $false
        if ($response.Headers -and $response.Headers["Content-Type"]) {
            $ct = $response.Headers["Content-Type"].ToString().ToLowerInvariant()
            if ($ct -match 'application/json|text/json|application/.+\+json|application/xml|text/xml|application/.+\+xml') {
                $isApi = $true
            }
        }
        if (-not $isApi) {
            if ($body.StartsWith("{") -or $body.StartsWith("[") -or $body.StartsWith("<")) {
                $isApi = $true
            }
        }

        if ($isApi) { Write-Log "GET probe accepted: $Url" }
        else { Write-Log "GET probe rejected: not JSON/XML response for $Url" "WARN" }

        $Global:ProbeCache[$Url] = $isApi
        return $isApi
    }
    catch {
        Write-Log "GET probe failed for $Url : $($_.Exception.Message)" "WARN"
        $Global:ProbeCache[$Url] = $false
        return $false
    }
}

# -------------------------------------------------------------------
# API RECORD BUILDER
# -------------------------------------------------------------------
function New-ApiRecord {
    param(
        [string]$Source,
        [string]$Runtime,
        [string]$Method,
        [string]$ApiHost,
        [string]$Path,
        [string]$FullUrl,
        [int]$Port,
        [string]$Evidence
    )

    [pscustomobject]@{
        Server   = $env:COMPUTERNAME
        Source   = $Source
        Runtime  = $Runtime
        Method   = $Method.ToUpperInvariant()
        Host     = $ApiHost
        Path     = (Normalize-UrlPath -Path $Path)
        FullUrl  = $FullUrl
        Port     = $Port
        Evidence = $Evidence
    }
}

# -------------------------------------------------------------------
# OPENAPI / SWAGGER SPEC PARSER
# -------------------------------------------------------------------
function Get-OpenApiRoutes {
    param(
        [string]$FilePath,
        [string]$Runtime,
        [string]$ServiceLabel,
        [string]$BaseUrl,
        [int]$Port
    )

    $results = @()
    try {
        $content = Get-Content -Path $FilePath -Raw -ErrorAction Stop
        $httpMethods = @('get','post','put','delete','patch','head','options','trace')

        # Try JSON first
        $isJson = $false
        try {
            $spec = $content | ConvertFrom-Json -ErrorAction Stop
            $isJson = $true
        } catch {}

        if ($isJson -and $spec.paths) {
            foreach ($pathProp in $spec.paths.PSObject.Properties) {
                $routePath = $pathProp.Name
                foreach ($methodProp in $pathProp.Value.PSObject.Properties) {
                    if ($httpMethods -contains $methodProp.Name.ToLower()) {
                        $normalizedPath = Normalize-UrlPath -Path $routePath
                        $results += New-ApiRecord `
                            -Source "OpenApiSpec" `
                            -Runtime $Runtime `
                            -Method $methodProp.Name.ToUpper() `
                            -ApiHost $BaseUrl `
                            -Path $normalizedPath `
                            -FullUrl ($BaseUrl + $normalizedPath) `
                            -Port $Port `
                            -Evidence "Spec:$FilePath"
                    }
                }
            }
        }
        else {
            # Lightweight YAML extraction (no YAML parser dependency)
            $inPaths = $false
            $currentPath = $null
            foreach ($yamlLine in ($content -split "`n")) {
                $trimmed = $yamlLine.TrimEnd()
                if ($trimmed -match '^paths\s*:') { $inPaths = $true; continue }
                if ($inPaths) {
                    if ($trimmed -match '^\S' -and $trimmed -notmatch '^paths') { $inPaths = $false; continue }
                    if ($trimmed -match '^\s{2}(/\S+)\s*:') {
                        $currentPath = $Matches[1]
                    }
                    elseif ($currentPath -and $trimmed -match '^\s{4}(get|post|put|delete|patch|head|options|trace)\s*:') {
                        $normalizedPath = Normalize-UrlPath -Path $currentPath
                        $results += New-ApiRecord `
                            -Source "OpenApiSpec" `
                            -Runtime $Runtime `
                            -Method $Matches[1].ToUpper() `
                            -ApiHost $BaseUrl `
                            -Path $normalizedPath `
                            -FullUrl ($BaseUrl + $normalizedPath) `
                            -Port $Port `
                            -Evidence "Spec:$FilePath"
                    }
                }
            }
        }

        if ($results.Count -gt 0) {
            Write-Log "  OpenAPI spec '$FilePath' yielded $($results.Count) routes"
        }
    }
    catch {
        Write-Log "Failed to parse OpenAPI spec '$FilePath': $($_.Exception.Message)" "WARN"
    }

    return $results
}

function Find-SpecFilesUnderPath {
    param(
        [string]$SearchRoot,
        [string]$Runtime,
        [string]$BaseUrl,
        [int]$Port
    )

    if ($DisableSpecScan) { return @() }
    if (-not $SearchRoot -or -not (Test-Path $SearchRoot)) { return @() }

    $results = @()
    $specNames = @('swagger.json','openapi.json','openapi.yaml','swagger.yaml','openapi.yml','swagger.yml')

    try {
        $specFiles = Get-ChildItem -Path $SearchRoot -Recurse -Include $specNames `
            -Depth $SearchDepth -ErrorAction SilentlyContinue |
            Select-Object -First $MaxSpecFiles

        foreach ($sf in $specFiles) {
            $results += Get-OpenApiRoutes -FilePath $sf.FullName -Runtime $Runtime `
                -ServiceLabel $SearchRoot -BaseUrl $BaseUrl -Port $Port
        }
    } catch {}

    return $results
}

# -------------------------------------------------------------------
# WEB.XML SERVLET MAPPING PARSER (Tomcat)
# -------------------------------------------------------------------
function Get-WebXmlRoutes {
    param(
        [string]$FilePath,
        [string]$BaseUrl,
        [int]$Port
    )

    $results = @()
    try {
        [xml]$xml = Get-Content -Path $FilePath -Raw -ErrorAction Stop

        $ns = $xml.DocumentElement.NamespaceURI
        $mappings = $null
        if ($ns) {
            $nsMgr = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
            $nsMgr.AddNamespace('j', $ns)
            $mappings = $xml.SelectNodes('//j:servlet-mapping/j:url-pattern', $nsMgr)
        }
        else {
            $mappings = $xml.SelectNodes('//servlet-mapping/url-pattern')
        }

        foreach ($m in $mappings) {
            $pattern = $m.InnerText
            $normalizedPath = Normalize-UrlPath -Path $pattern
            $results += New-ApiRecord `
                -Source "WebXml" `
                -Runtime "Tomcat" `
                -Method "*" `
                -ApiHost $BaseUrl `
                -Path $normalizedPath `
                -FullUrl ($BaseUrl + $normalizedPath) `
                -Port $Port `
                -Evidence "web.xml:$FilePath"
        }

        if ($results.Count -gt 0) {
            Write-Log "  web.xml '$FilePath' yielded $($results.Count) servlet mappings"
        }
    }
    catch {
        Write-Log "Failed to parse web.xml '$FilePath': $($_.Exception.Message)" "WARN"
    }
    return $results
}

# -------------------------------------------------------------------
# SOURCE CODE ROUTE EXTRACTION
# -------------------------------------------------------------------
function Get-PythonSourceRoutes {
    param(
        [string]$SearchRoot,
        [string]$Runtime,
        [string]$BaseUrl,
        [int]$Port
    )

    if ($DisableSourceCodeScan) { return @() }
    if (-not $SearchRoot -or -not (Test-Path $SearchRoot)) { return @() }

    $results = @()
    try {
        $pyFiles = Get-ChildItem -Path $SearchRoot -Recurse -Include '*.py' `
            -Depth $SearchDepth -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '__pycache__|\.eggs|\.tox|venv|site-packages' } |
            Select-Object -First $MaxSourceFiles

        foreach ($pyf in $pyFiles) {
            try {
                $content = Get-Content -Path $pyf.FullName -Raw -ErrorAction Stop

                # Flask: @app.route('/path', methods=['GET','POST'])
                #        @bp.route('/path')
                $rxFlaskRoute = "@\w+\.route\s*\(\s*['""]([^'""]+)['""]"
                foreach ($m in [regex]::Matches($content, $rxFlaskRoute)) {
                    $routePath = $m.Groups[1].Value
                    $methods = "*"
                    # Look for methods= in the surrounding text
                    $regionStart = [Math]::Max(0, $m.Index)
                    $regionLen = [Math]::Min(300, $content.Length - $regionStart)
                    $region = $content.Substring($regionStart, $regionLen)
                    if ($region -match "methods\s*=\s*\[([^\]]+)\]") {
                        $methods = ($Matches[1] -replace "'|""| ","").ToUpper()
                    }
                    $normalizedPath = Normalize-UrlPath -Path $routePath
                    foreach ($method in ($methods -split ',')) {
                        $results += New-ApiRecord -Source "SourceCode" -Runtime $Runtime `
                            -Method $method.Trim() -ApiHost $BaseUrl -Path $normalizedPath `
                            -FullUrl ($BaseUrl + $normalizedPath) -Port $Port `
                            -Evidence "PySrc:$($pyf.FullName)"
                    }
                }

                # Flask/FastAPI shorthand: @app.get('/path'), @router.post('/path')
                $rxShorthand = "@\w+\.(get|post|put|delete|patch|head|options)\s*\(\s*['""]([^'""]+)['""]"
                foreach ($m in [regex]::Matches($content, $rxShorthand)) {
                    $method = $m.Groups[1].Value.ToUpper()
                    $routePath = $m.Groups[2].Value
                    $normalizedPath = Normalize-UrlPath -Path $routePath
                    $results += New-ApiRecord -Source "SourceCode" -Runtime $Runtime `
                        -Method $method -ApiHost $BaseUrl -Path $normalizedPath `
                        -FullUrl ($BaseUrl + $normalizedPath) -Port $Port `
                        -Evidence "PySrc:$($pyf.FullName)"
                }

                # FastAPI: @app.api_route('/path', methods=[...])
                $rxApiRoute = "@\w+\.api_route\s*\(\s*['""]([^'""]+)['""]"
                foreach ($m in [regex]::Matches($content, $rxApiRoute)) {
                    $routePath = $m.Groups[1].Value
                    $normalizedPath = Normalize-UrlPath -Path $routePath
                    $results += New-ApiRecord -Source "SourceCode" -Runtime $Runtime `
                        -Method "*" -ApiHost $BaseUrl -Path $normalizedPath `
                        -FullUrl ($BaseUrl + $normalizedPath) -Port $Port `
                        -Evidence "PySrc:$($pyf.FullName)"
                }

                # Django: path('api/users/', view), re_path(r'^api/users/')
                $rxDjango = "(?:path|re_path)\s*\(\s*[r]?['""]([^'""]+)['""]"
                foreach ($m in [regex]::Matches($content, $rxDjango)) {
                    $routeRaw = $m.Groups[1].Value -replace '^\^|\\$',''
                    $normalizedPath = Normalize-UrlPath -Path $routeRaw
                    $results += New-ApiRecord -Source "SourceCode" -Runtime $Runtime `
                        -Method "*" -ApiHost $BaseUrl -Path $normalizedPath `
                        -FullUrl ($BaseUrl + $normalizedPath) -Port $Port `
                        -Evidence "PySrc:$($pyf.FullName)"
                }
            } catch {}
        }

        if ($results.Count -gt 0) {
            Write-Log "  Python source scan under '$SearchRoot' yielded $($results.Count) routes"
        }
    } catch {}

    return $results
}

function Get-NodeSourceRoutes {
    param(
        [string]$SearchRoot,
        [string]$BaseUrl,
        [int]$Port
    )

    if ($DisableSourceCodeScan) { return @() }
    if (-not $SearchRoot -or -not (Test-Path $SearchRoot)) { return @() }

    $results = @()
    try {
        $jsFiles = Get-ChildItem -Path $SearchRoot -Recurse -Include '*.js','*.ts','*.mjs' `
            -Depth $SearchDepth -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch 'node_modules|\.next|dist[/\\]|build[/\\]' } |
            Select-Object -First $MaxSourceFiles

        foreach ($jf in $jsFiles) {
            try {
                $content = Get-Content -Path $jf.FullName -Raw -ErrorAction Stop

                # Express/Fastify: app.get('/path', ...), router.post('/path', ...)
                $rxExpress = "\.\s*(get|post|put|delete|patch|all|head|options)\s*\(\s*['""`]([^'""``]+)['""`]"
                foreach ($m in [regex]::Matches($content, $rxExpress)) {
                    $method = $m.Groups[1].Value.ToUpper()
                    if ($method -eq 'ALL') { $method = '*' }
                    $routePath = $m.Groups[2].Value
                    if ($routePath -match '^/') {
                        $normalizedPath = Normalize-UrlPath -Path $routePath
                        $results += New-ApiRecord -Source "SourceCode" -Runtime "NodeJS" `
                            -Method $method -ApiHost $BaseUrl -Path $normalizedPath `
                            -FullUrl ($BaseUrl + $normalizedPath) -Port $Port `
                            -Evidence "JsSrc:$($jf.FullName)"
                    }
                }

                # NestJS: @Get('/path'), @Post('/path')
                $rxNest = "@(Get|Post|Put|Delete|Patch|Head|Options|All)\s*\(\s*['""]([^'""]+)['""]"
                foreach ($m in [regex]::Matches($content, $rxNest)) {
                    $method = $m.Groups[1].Value.ToUpper()
                    if ($method -eq 'ALL') { $method = '*' }
                    $routePath = $m.Groups[2].Value
                    $normalizedPath = Normalize-UrlPath -Path $routePath
                    $results += New-ApiRecord -Source "SourceCode" -Runtime "NodeJS" `
                        -Method $method -ApiHost $BaseUrl -Path $normalizedPath `
                        -FullUrl ($BaseUrl + $normalizedPath) -Port $Port `
                        -Evidence "JsSrc:$($jf.FullName)"
                }
            } catch {}
        }

        if ($results.Count -gt 0) {
            Write-Log "  Node source scan under '$SearchRoot' yielded $($results.Count) routes"
        }
    } catch {}

    return $results
}

# -------------------------------------------------------------------
# GENERIC ACCESS LOG PARSER (Combined/Common format)
# -------------------------------------------------------------------
function Get-AccessLogApis {
    param(
        [string]$LogDir,
        [string]$Runtime,
        [string]$BaseUrl,
        [int]$Port,
        [string]$SourceLabel,
        [string[]]$FilePatterns = @('*.log','access*')
    )

    $results = @()
    if (-not $LogDir -or -not (Test-Path $LogDir)) { return @() }

    try {
        $logFiles = @()
        foreach ($pattern in $FilePatterns) {
            $logFiles += Get-ChildItem -Path $LogDir -Filter $pattern -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $Global:LogCutoff -and $_.Length -gt 0 }
        }
        $logFiles = $logFiles | Sort-Object FullName -Unique |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First $MaxLogFiles

        $rxRequest = '"(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(\S+)\s+HTTP/[0-9.]+"'

        foreach ($file in $logFiles) {
            try {
                $reader = [System.IO.StreamReader]::new($file.FullName)
                while ($null -ne ($line = $reader.ReadLine())) {
                    if ($line -match $rxRequest) {
                        $method = $Matches[1].ToUpperInvariant()
                        $rawPath = $Matches[2]

                        $pathOnly = ($rawPath -split '\?')[0]
                        $query = $null
                        if ($rawPath -match '^([^?]+)\?(.*)$') {
                            $pathOnly = $Matches[1]
                            $query = $Matches[2]
                        }

                        $pathOnly = Normalize-UrlPath -Path $pathOnly
                        if (-not (Test-IsApiLikePath -Path $pathOnly)) { continue }

                        $fullUrl = $BaseUrl + $pathOnly
                        if ($query) { $fullUrl = "$fullUrl`?$query" }

                        if ($method -eq "GET") {
                            if (-not (Test-IsKnownApiGetPath -Path $pathOnly)) {
                                if (-not (Test-ResponseLooksLikeApi -Url $fullUrl)) { continue }
                            }
                        }

                        $results += New-ApiRecord `
                            -Source $SourceLabel `
                            -Runtime $Runtime `
                            -Method $method `
                            -ApiHost $BaseUrl `
                            -Path $pathOnly `
                            -FullUrl $fullUrl `
                            -Port $Port `
                            -Evidence $file.FullName
                    }
                }
                $reader.Close()
            } catch {}
        }
    } catch {}

    return $results
}

# -------------------------------------------------------------------
# 1. IIS DISCOVERY
# -------------------------------------------------------------------
function Get-IISLogDirectory {
    $configPath = Join-Path $env:windir "System32\inetsrv\config\applicationHost.config"
    if (Test-Path $configPath) {
        try {
            [xml]$xml = Get-Content -Path $configPath -Raw -ErrorAction Stop
            $dir = $xml.configuration.'system.applicationHost'.sites.siteDefaults.logFile.directory
            if ($dir) { return [Environment]::ExpandEnvironmentVariables($dir) }
        } catch {}
    }
    return (Join-Path $env:SystemDrive "inetpub\logs\LogFiles")
}

function Get-IISApis {
    $results = @()
    $logDirectory = Get-IISLogDirectory

    if (-not (Test-Path $logDirectory)) {
        Write-Log "No IIS logs found at $logDirectory" "WARN"
        return @()
    }

    # --- W3SVC log parsing (existing logic) ---
    $logFiles = Get-ChildItem -Path $logDirectory -Recurse -Filter *.log -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $Global:LogCutoff } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First $MaxLogFiles

    foreach ($file in $logFiles) {
        $fields = @()

        foreach ($line in Get-Content -Path $file.FullName -ErrorAction SilentlyContinue) {
            if ($line -like "#Fields*") {
                $fields = ($line -replace "#Fields:\s*", "") -split ' '
                continue
            }
            if ($line -like "#*") { continue }
            if (-not $fields -or $fields.Count -eq 0) { continue }

            $parts = $line -split ' '
            if ($parts.Count -lt $fields.Count) { continue }

            $row = @{}
            for ($i = 0; $i -lt $fields.Count; $i++) {
                $row[$fields[$i]] = $parts[$i]
            }

            $method       = $row["cs-method"]
            $path         = $row["cs-uri-stem"]
            $query        = $row["cs-uri-query"]
            $observedHost = $row["cs-host"]
            $port         = $row["s-port"]

            if (-not (Test-IsApiLikeMethod -Method $method)) { continue }
            if (-not (Test-IsApiLikePath -Path $path)) { continue }

            $bestHost = Get-BestHostname -ObservedHost $observedHost

            if ([string]::IsNullOrWhiteSpace($port) -or $port -eq "-") { $port = "80" }
            $baseUrl = Build-BaseUrl -Host_ $bestHost -Port ([int]$port)

            $normalizedPath = Normalize-UrlPath -Path $path
            $fullUrl = $baseUrl + $normalizedPath
            if (-not [string]::IsNullOrWhiteSpace($query) -and $query -ne "-") {
                $fullUrl = "$fullUrl`?$query"
            }

            $upperMethod = $method.ToUpperInvariant()
            if ($upperMethod -eq "GET") {
                if (-not (Test-IsKnownApiGetPath -Path $normalizedPath)) {
                    if (-not (Test-ResponseLooksLikeApi -Url $fullUrl)) { continue }
                }
            }

            $results += New-ApiRecord `
                -Source "IISLog" -Runtime "IIS" -Method $upperMethod `
                -ApiHost $baseUrl -Path $normalizedPath -FullUrl $fullUrl `
                -Port ([int]$port) -Evidence $file.FullName
        }
    }

    # --- OpenAPI specs under IIS site physical paths ---
    if (-not $DisableSpecScan) {
        try {
            $appCmdPath = Join-Path $env:windir "System32\inetsrv\appcmd.exe"
            if (Test-Path $appCmdPath) {
                $siteOutput = & $appCmdPath list site /text:* 2>$null
                $physPaths = @()
                foreach ($ln in $siteOutput) {
                    if ($ln -match 'physicalPath:"?([^"]+)"?') {
                        $pp = [Environment]::ExpandEnvironmentVariables($Matches[1].Trim())
                        if ($pp -and (Test-Path $pp)) { $physPaths += $pp }
                    }
                }

                # Also try WebAdministration if available
                try {
                    Import-Module WebAdministration -ErrorAction Stop
                    $sites = Get-ChildItem IIS:\Sites -ErrorAction SilentlyContinue
                    foreach ($site in $sites) {
                        if ($site.PhysicalPath -and (Test-Path $site.PhysicalPath)) {
                            $physPaths += $site.PhysicalPath
                        }
                    }
                } catch {}

                $physPaths = $physPaths | Select-Object -Unique
                foreach ($pp in $physPaths) {
                    $results += Find-SpecFilesUnderPath -SearchRoot $pp -Runtime "IIS" `
                        -BaseUrl (Build-BaseUrl -Host_ (Get-ServerDnsFqdn) -Port 80) -Port 80
                }
            }
        } catch {}
    }

    return $results
}

# -------------------------------------------------------------------
# 2. TOMCAT DISCOVERY
# -------------------------------------------------------------------
function Get-TomcatInstallPaths {
    $roots = @("C:\Program Files", "C:\Program Files (x86)", "C:\")
    $results = @()

    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        try {
            $dirs = Get-ChildItem -Path $root -Directory -Recurse -Depth 3 -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.FullName -match 'tomcat' -or
                    (Test-Path (Join-Path $_.FullName "conf\server.xml"))
                }
            foreach ($d in $dirs) { $results += $d.FullName }
        } catch {}
    }

    # Also detect from running java processes
    try {
        $javaProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -match 'catalina\.base|catalina\.home' }
        foreach ($jp in $javaProcs) {
            if ($jp.CommandLine -match '-Dcatalina\.base[= ]"?([^"\s]+)') {
                $cb = $Matches[1]
                if (Test-Path $cb) { $results += $cb }
            }
            if ($jp.CommandLine -match '-Dcatalina\.home[= ]"?([^"\s]+)') {
                $ch = $Matches[1]
                if (Test-Path $ch) { $results += $ch }
            }
        }
    } catch {}

    return $results | Select-Object -Unique
}

function Get-TomcatPorts {
    $ports = @()
    $paths = Get-TomcatInstallPaths

    foreach ($base in $paths) {
        $serverXml = Join-Path $base "conf\server.xml"
        if (-not (Test-Path $serverXml)) { continue }
        try {
            [xml]$xml = Get-Content -Path $serverXml -Raw -ErrorAction Stop
            $connectors = $xml.Server.Service.Connector
            foreach ($connector in $connectors) {
                if ($connector.port) { $ports += [int]$connector.port }
            }
        } catch {}
    }

    return $ports | Select-Object -Unique
}

function Get-TomcatApis {
    $results = @()
    $tomcatPaths = Get-TomcatInstallPaths
    $tomcatPorts = Get-TomcatPorts
    $bestHost = Get-ServerDnsFqdn

    foreach ($base in $tomcatPaths) {
        $port = 8080
        if ($tomcatPorts -and $tomcatPorts.Count -gt 0) {
            $port = [int]($tomcatPorts | Select-Object -First 1)
        }
        $baseUrl = Build-BaseUrl -Host_ $bestHost -Port $port

        # Access logs
        $logDir = Join-Path $base "logs"
        $results += Get-AccessLogApis -LogDir $logDir -Runtime "Tomcat" `
            -BaseUrl $baseUrl -Port $port -SourceLabel "TomcatLog" `
            -FilePatterns @('*access*','localhost*')

        # web.xml servlet mappings
        $webappsDir = Join-Path $base "webapps"
        if (Test-Path $webappsDir) {
            try {
                $webXmls = Get-ChildItem -Path $webappsDir -Recurse -Filter 'web.xml' `
                    -Depth $SearchDepth -ErrorAction SilentlyContinue |
                    Select-Object -First 20
                foreach ($wx in $webXmls) {
                    $results += Get-WebXmlRoutes -FilePath $wx.FullName -BaseUrl $baseUrl -Port $port
                }
            } catch {}
        }

        # OpenAPI specs in webapps
        $results += Find-SpecFilesUnderPath -SearchRoot $webappsDir `
            -Runtime "Tomcat" -BaseUrl $baseUrl -Port $port
    }

    return $results
}

# -------------------------------------------------------------------
# 3. PYTHON API DISCOVERY
# -------------------------------------------------------------------
function Get-PythonApis {
    $results = @()
    $bestHost = Get-ServerDnsFqdn

    try {
        $pyProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -match 'python' -or
                ($_.CommandLine -and $_.CommandLine -match 'flask|django|fastapi|uvicorn|gunicorn|waitress|hypercorn|daphne')
            }

        $tcpConns = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue

        foreach ($pp in $pyProcs) {
            $cmdLine = $pp.CommandLine
            $pid_ = $pp.ProcessId
            if (-not $cmdLine) { continue }

            $framework = "Python"
            if ($cmdLine -match 'flask')    { $framework = "Flask" }
            if ($cmdLine -match 'django')   { $framework = "Django" }
            if ($cmdLine -match 'fastapi')  { $framework = "FastAPI" }
            if ($cmdLine -match 'uvicorn')  { $framework = "FastAPI" }
            if ($cmdLine -match 'gunicorn') { $framework = "Python" }

            if (-not (Test-PlatformEnabled -Name "Python") -and -not (Test-PlatformEnabled -Name $framework)) {
                continue
            }

            # Determine listening port
            $pyPort = ($tcpConns | Where-Object { $_.OwningProcess -eq $pid_ } |
                       Select-Object -First 1).LocalPort
            if (-not $pyPort) {
                # Try to extract from cmdline
                if ($cmdLine -match '(?:--port|--bind|:)(\d{2,5})') { $pyPort = [int]$Matches[1] }
                else { $pyPort = 8000 }
            }

            $baseUrl = Build-BaseUrl -Host_ $bestHost -Port $pyPort

            # Determine working directory
            $workDir = $null
            try {
                $procObj = Get-Process -Id $pid_ -ErrorAction SilentlyContinue
                if ($procObj -and $procObj.Path) {
                    $workDir = Split-Path $procObj.Path -Parent
                }
            } catch {}

            if ($cmdLine -match '(?:--chdir|--directory)\s+"?([^"\s]+)') {
                $workDir = $Matches[1]
            }
            if ($cmdLine -match '(\S+[/\\])(?:app|main|wsgi|asgi|manage)\.py') {
                $candidate = $Matches[1] -replace '"',''
                if (Test-Path $candidate) { $workDir = $candidate }
            }

            Write-Log "  Python process PID=$pid_ framework=$framework port=$pyPort workDir=$workDir"

            # Access logs
            if ($workDir -and (Test-Path $workDir)) {
                foreach ($logCandidate in @((Join-Path $workDir 'logs'), (Join-Path $workDir 'log'), $workDir)) {
                    $results += Get-AccessLogApis -LogDir $logCandidate -Runtime $framework `
                        -BaseUrl $baseUrl -Port $pyPort -SourceLabel "${framework}Log"
                }

                # Source code routes
                $results += Get-PythonSourceRoutes -SearchRoot $workDir `
                    -Runtime $framework -BaseUrl $baseUrl -Port $pyPort

                # OpenAPI specs
                $results += Find-SpecFilesUnderPath -SearchRoot $workDir `
                    -Runtime $framework -BaseUrl $baseUrl -Port $pyPort
            }
        }
    }
    catch {
        Write-Log "Python discovery failed: $($_.Exception.Message)" "WARN"
    }

    return $results
}

# -------------------------------------------------------------------
# 4. PROCESS-BASED DISCOVERY (Java, Node, .NET, nginx, Apache, etc.)
# -------------------------------------------------------------------
function Get-WebListeningProcesses {
    $results = @()
    try {
        $connections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalPort -in @(80,443,8080,8443,8000,8008,8081,5000,5001,7001,7002,9000,3000,4200,9090,9443) }

        foreach ($conn in $connections) {
            $proc = Get-CimInstance Win32_Process -Filter "ProcessId = $($conn.OwningProcess)" -ErrorAction SilentlyContinue
            if ($proc) {
                $results += [pscustomobject]@{
                    ProcessId    = $proc.ProcessId
                    Name         = $proc.Name
                    CommandLine  = $proc.CommandLine
                    LocalAddress = $conn.LocalAddress
                    LocalPort    = $conn.LocalPort
                }
            }
        }
    }
    catch {
        Write-Log "Listening process discovery failed: $($_.Exception.Message)" "WARN"
    }
    return $results | Sort-Object ProcessId, LocalPort -Unique
}

function Get-JavaApiCandidates {
    $results = @()
    try {
        $javaProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -match '^java(w)?\.exe$' -or
                ($_.CommandLine -and $_.CommandLine -match 'spring|tomcat|jetty|undertow|server\.port|catalina')
            }

        foreach ($proc in $javaProcs) {
            $runtime = "Java"
            if ($proc.CommandLine -match 'tomcat|catalina') { $runtime = "Tomcat" }
            elseif ($proc.CommandLine -match 'spring')      { $runtime = "SpringBoot" }
            elseif ($proc.CommandLine -match 'jetty')       { $runtime = "Jetty" }
            elseif ($proc.CommandLine -match 'undertow')    { $runtime = "Undertow" }

            $port = $null
            if ($proc.CommandLine -match '(--server\.port=|-Dserver\.port=)(\d+)') {
                $port = [int]$matches[2]
            }

            $results += [pscustomobject]@{
                ProcessId   = $proc.ProcessId
                Name        = $proc.Name
                RuntimeType = $runtime
                CommandLine = $proc.CommandLine
                PortHint    = $port
            }
        }
    }
    catch {
        Write-Log "Java process discovery failed: $($_.Exception.Message)" "WARN"
    }
    return $results
}

function Get-OtherApiHostProcesses {
    $results = @()
    try {
        $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -match 'node\.exe|dotnet\.exe|nginx\.exe|httpd\.exe' -or
                ($_.CommandLine -and $_.CommandLine -match 'express|nestjs|fastify|koa|aspnetcore|kestrel')
            }

        foreach ($proc in $procs) {
            $runtime = "Other"
            if ($proc.Name -match 'node\.exe')   { $runtime = "NodeJS" }
            elseif ($proc.Name -match 'dotnet\.exe') { $runtime = ".NET" }
            elseif ($proc.Name -match 'nginx\.exe')  { $runtime = "nginx" }
            elseif ($proc.Name -match 'httpd\.exe')  { $runtime = "Apache" }

            $results += [pscustomobject]@{
                ProcessId   = $proc.ProcessId
                Name        = $proc.Name
                RuntimeType = $runtime
                CommandLine = $proc.CommandLine
            }
        }
    }
    catch {
        Write-Log "Other process discovery failed: $($_.Exception.Message)" "WARN"
    }
    return $results
}

function Get-ProcessDerivedApis {
    $results = @()
    $bestHost = Get-ServerDnsFqdn
    $listening = Get-WebListeningProcesses
    $java = Get-JavaApiCandidates
    $other = Get-OtherApiHostProcesses
    $tcpConns = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue

    $knownPathsByRuntime = @{
        "SpringBoot" = @("/actuator/health","/actuator/info","/actuator/metrics","/v3/api-docs","/swagger-ui","/swagger-ui/index.html")
        "Tomcat"     = @("/health","/status","/swagger","/swagger-ui","/openapi.json")
        "Jetty"      = @("/health","/status","/swagger","/openapi.json")
        "Undertow"   = @("/health","/status","/swagger","/openapi.json")
        "NodeJS"     = @("/health","/status","/api/health","/swagger","/openapi.json")
        ".NET"       = @("/health","/healthz","/swagger","/swagger/index.html","/openapi/v1.json")
        "nginx"      = @("/api/health","/health","/status")
        "Apache"     = @("/api/health","/health","/status")
        "Java"       = @("/health","/status","/swagger","/openapi.json")
        "Other"      = @("/health","/status","/api/health")
        "IISWorker"  = @("/api/health","/health","/status","/swagger","/openapi.json")
        "Python"     = @("/health","/docs","/redoc","/openapi.json","/swagger","/api/health")
        "Flask"      = @("/health","/api/health","/swagger","/openapi.json")
        "Django"     = @("/health","/api/health","/swagger","/openapi.json","/admin/")
        "FastAPI"    = @("/health","/docs","/redoc","/openapi.json","/api/health")
    }

    foreach ($listener in $listening) {
        $runtime = "Other"

        $javaMatch = $java | Where-Object { $_.ProcessId -eq $listener.ProcessId } | Select-Object -First 1
        $otherMatch = $other | Where-Object { $_.ProcessId -eq $listener.ProcessId } | Select-Object -First 1

        if ($javaMatch) { $runtime = $javaMatch.RuntimeType }
        elseif ($otherMatch) { $runtime = $otherMatch.RuntimeType }
        else {
            if ($listener.Name -match 'w3wp\.exe') { $runtime = "IISWorker" }
            elseif ($listener.Name -match 'python') { $runtime = "Python" }
        }

        if (-not (Test-PlatformEnabled -Name "Process")) {
            if (-not (Test-PlatformEnabled -Name $runtime)) { continue }
        }

        $port = [int]$listener.LocalPort
        $baseUrl = Build-BaseUrl -Host_ $bestHost -Port $port

        # Probe known paths
        $candidatePaths = $knownPathsByRuntime[$runtime]
        if (-not $candidatePaths) { $candidatePaths = $knownPathsByRuntime["Other"] }

        foreach ($candidatePath in $candidatePaths) {
            $normalizedPath = Normalize-UrlPath -Path $candidatePath
            $fullUrl = $baseUrl + $normalizedPath

            if ($DisableGetValidation -or (Test-ResponseLooksLikeApi -Url $fullUrl) -or (Test-IsKnownApiGetPath -Path $normalizedPath)) {
                $results += New-ApiRecord `
                    -Source "ProcessDiscovery" -Runtime $runtime -Method "GET" `
                    -ApiHost $baseUrl -Path $normalizedPath -FullUrl $fullUrl `
                    -Port $port -Evidence ("PID=" + $listener.ProcessId + "; Name=" + $listener.Name)
            }
        }

        # --- Source code + spec scanning for process working directories ---
        $workDir = $null
        $cmdLine = $listener.CommandLine
        if ($cmdLine) {
            # Node.js app directory
            if ($runtime -eq "NodeJS" -and $cmdLine -match '"?(\S+[/\\](?:app|server|index|main)\.(?:js|ts|mjs))') {
                $workDir = Split-Path $Matches[1] -Parent -ErrorAction SilentlyContinue
            }
            # .NET dll directory
            elseif ($runtime -eq ".NET" -and $cmdLine -match '"?(\S+\.dll)') {
                $workDir = Split-Path $Matches[1] -Parent -ErrorAction SilentlyContinue
            }
            # Spring Boot jar directory
            elseif ($runtime -in @("SpringBoot","Java") -and $cmdLine -match '(?:^|\s)"?(\S+\.jar)') {
                $jarPath = $Matches[1] -replace '"',''
                $workDir = Split-Path $jarPath -Parent -ErrorAction SilentlyContinue
            }
        }

        if ($workDir -and (Test-Path $workDir)) {
            # Access logs near the app
            foreach ($logCandidate in @((Join-Path $workDir 'logs'), (Join-Path $workDir 'log'), $workDir)) {
                $results += Get-AccessLogApis -LogDir $logCandidate -Runtime $runtime `
                    -BaseUrl $baseUrl -Port $port -SourceLabel "${runtime}Log"
            }

            # Node source routes
            if ($runtime -eq "NodeJS") {
                $results += Get-NodeSourceRoutes -SearchRoot $workDir -BaseUrl $baseUrl -Port $port
            }

            # OpenAPI specs
            $results += Find-SpecFilesUnderPath -SearchRoot $workDir `
                -Runtime $runtime -BaseUrl $baseUrl -Port $port
        }
    }

    return $results
}

# -------------------------------------------------------------------
# NORMALIZATION + DEDUP
# -------------------------------------------------------------------
function Normalize-ApiResults {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Apis
    )

    $normalized = foreach ($api in $Apis) {
        if (-not $api) { continue }

        $apiHostValue = ""
        if ($api.Host) { $apiHostValue = $api.Host.ToString().Trim().ToLowerInvariant() }

        $path = Normalize-UrlPath -Path $api.Path
        $method = $api.Method.ToString().Trim().ToUpperInvariant()

        $fullUrl = $api.FullUrl
        if (-not $fullUrl -or [string]::IsNullOrWhiteSpace($fullUrl.ToString())) {
            $fullUrl = $apiHostValue.TrimEnd("/") + $path
        }

        [pscustomobject]@{
            Server   = $api.Server
            Source   = $api.Source
            Runtime  = $api.Runtime
            Method   = $method
            Host     = $apiHostValue
            Path     = $path
            FullUrl  = $fullUrl
            Port     = $api.Port
            Evidence = $api.Evidence
        }
    }

    return $normalized | Sort-Object Method, FullUrl -Unique
}

# -------------------------------------------------------------------
# MAIN EXECUTION
# -------------------------------------------------------------------
try {
    Invoke-PreflightChecks

    if (-not (Enter-SingleInstance)) {
        exit 0
    }

    Write-Log "Starting harvest v2.1.0"
    Write-Log "Safety controls: MaxLogFiles=$MaxLogFiles MaxProbeCount=$MaxProbeCount ProbeDelayMs=$ProbeDelayMs ProbeTimeoutSec=$ProbeTimeoutSec MaxBodyChars=$MaxBodyChars LogLookbackHours=$LogLookbackHours MaxSourceFiles=$MaxSourceFiles MaxSpecFiles=$MaxSpecFiles SearchDepth=$SearchDepth DisableGetValidation=$DisableGetValidation DisableSourceCodeScan=$DisableSourceCodeScan DisableSpecScan=$DisableSpecScan IgnoreCertificateErrors=$IgnoreCertificateErrors Platforms=$($Platforms -join ',')"

    $allApis = @()

    # --- IIS ---
    if (Test-PlatformEnabled -Name "IIS") {
        Write-Log "Running IIS discovery"
        $iisApis = Get-IISApis
        $allApis += $iisApis
        Write-Log "IIS APIs found: $($iisApis.Count)"
    }

    # --- Tomcat ---
    if (Test-PlatformEnabled -Name "Tomcat") {
        Write-Log "Running Tomcat discovery"
        $tomcatApis = Get-TomcatApis
        $allApis += $tomcatApis
        Write-Log "Tomcat APIs found: $($tomcatApis.Count)"
    }

    # --- Python ---
    if (
        (Test-PlatformEnabled -Name "Python") -or
        (Test-PlatformEnabled -Name "Flask") -or
        (Test-PlatformEnabled -Name "Django") -or
        (Test-PlatformEnabled -Name "FastAPI")
    ) {
        Write-Log "Running Python discovery"
        $pythonApis = Get-PythonApis
        $allApis += $pythonApis
        Write-Log "Python APIs found: $($pythonApis.Count)"
    }

    # --- Process-based (Java, Node, .NET, nginx, Apache, etc.) ---
    if (
        (Test-PlatformEnabled -Name "Process") -or
        (Test-PlatformEnabled -Name "Java") -or
        (Test-PlatformEnabled -Name "SpringBoot") -or
        (Test-PlatformEnabled -Name "Jetty") -or
        (Test-PlatformEnabled -Name "Undertow") -or
        (Test-PlatformEnabled -Name "NodeJS") -or
        (Test-PlatformEnabled -Name ".NET") -or
        (Test-PlatformEnabled -Name "nginx") -or
        (Test-PlatformEnabled -Name "Apache") -or
        (Test-PlatformEnabled -Name "Other") -or
        (Test-PlatformEnabled -Name "IISWorker")
    ) {
        Write-Log "Running process-based discovery"
        $processApis = Get-ProcessDerivedApis
        $allApis += $processApis
        Write-Log "Process-derived APIs found: $($processApis.Count)"
    }

    # --- Normalize + Dedup ---
    $apis = Normalize-ApiResults -Apis $allApis
    Write-Log "Total APIs found after normalization: $($apis.Count)"

    if ($DebugMode) {
        Write-Host ""
        Write-Host "===== DISCOVERED APIs =====" -ForegroundColor Cyan
        $apis | Format-Table Server, Source, Runtime, Method, Path, FullUrl -AutoSize
        Write-Host ""

        # Summary by source
        Write-Host "--- By Source ---" -ForegroundColor Gray
        $apis | Group-Object Source | Sort-Object Count -Descending | ForEach-Object {
            Write-Host ("  {0}: {1}" -f $_.Name, $_.Count)
        }
        Write-Host ""

        # Summary by runtime
        Write-Host "--- By Runtime ---" -ForegroundColor Gray
        $apis | Group-Object Runtime | Sort-Object Count -Descending | ForEach-Object {
            Write-Host ("  {0}: {1}" -f $_.Name, $_.Count)
        }
        Write-Host ""
        Write-Host ("Log file: " + $LogFile)
    }

    # --- Output ---
    if ($OutputCsv) {
        $outputDir = Split-Path $OutputCsv -Parent
        if ($outputDir -and -not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }
        $apis | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
        Write-Log "CSV exported to: $OutputCsv"
    }

    Write-Log "Done. Total=$($apis.Count)"

    # Return objects to pipeline (serializes back to caller via Invoke-Command)
    return $apis
}
finally {
    Exit-SingleInstance
}
 
