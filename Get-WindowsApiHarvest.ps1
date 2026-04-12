param(
    [ValidateSet("install","uninstall","activate","status","preflight","repair","none")]
    [string]$Action = "none",

    [string]$InstallDir,
    [string]$LogDir,
    [string]$StateDir,

    [switch]$DryRun,
    [switch]$Force,

    [string]$NonameSourceType = "26",
    [string]$NonameSourceIndex = "19",
    [string]$NonameSourceKey = "d52875f0-03cc-437e-8679-597fb37aa069",
    [string]$NonameEngineUrl = "https://cs-internal-envTEST.nonamesec.com/engine",
    [string]$NonameSourceVersion = "4.1.1",

    [string]$LogFileName = "noname.log",
    [switch]$UseHostBasedLogName,

    [string]$LogForwardUrl,
    [switch]$LogForwardOnInstall,
    [switch]$LogForwardOnUninstall,
    [switch]$LogForwardOnActivate,

    # --- Dynatrace ---
    # DynatraceApiUrl  : Your environment events endpoint, e.g.
    #   https://<env>.live.dynatrace.com/api/v2/events/ingest
    # DynatraceApiToken: A token with events.ingest scope.
    # When DynatraceApiUrl is empty, all Dynatrace calls are silently skipped.
    [string]$DynatraceApiUrl,
    [string]$DynatraceApiToken,
    [int]$DynatraceTimeoutSec = 10,

    [string]$PackageSourceDir,
    [switch]$EnableAzureMetadata,
    [int]$AzureMetadataTimeoutSec = 2,
    [int]$LogForwardTimeoutSec = 10,
    [int]$EngineConnectivityTimeoutSec = 10,
    [string]$RuntimeInstallArgs = "/quiet",
    [switch]$EnableLogDirFallback,
    [string[]]$LogDirFallbackPaths,
    [switch]$FailOnWarnings,
    [ValidateSet("Machine","User","Process")]
    [string]$EnvironmentVariableScope = "Machine"
)

#region ------ PowerShell version guard -------------------------------------------------------
if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1) {
    $detected = "{0} {1}" -f $PSVersionTable.PSEdition, $PSVersionTable.PSVersion
    Write-Error (("Unsupported PowerShell version: {0}.`n" +
                  "This script requires Windows PowerShell 5.1 (Desktop edition).`n" +
                  "Run: powershell.exe -Version 5 -File `"$PSCommandPath`"") -f $detected)
    exit 1
}
#endregion ------------------------------------------------------------------------------------

$script:DryRun = [bool]$DryRun
$script:Force  = [bool]$Force

$env:SystemDirectory = [Environment]::SystemDirectory
$appCmd = Join-Path $env:SystemDirectory "inetsrv\appcmd.exe"
$dir = "NONAME_MODULE_INSTALL_DIR"

$module64 = @{
    moduleName     = "NonameNativeModule64"
    dllName        = "NonameNativeModule64.dll"
    runtimeLibrary = "VC_redist.x64.exe"
    preCondition   = "bitness64"
}

$module32 = @{
    moduleName     = "NonameNativeModule32"
    dllName        = "NonameNativeModule32.dll"
    runtimeLibrary = "VC_redist.x86.exe"
    preCondition   = "bitness32"
}

$modules = @($module64, $module32)

foreach ($module in $modules) {
    if ($module.runtimeLibrary -match 'debug') {
        throw "Configured runtimeLibrary must not be a debug package: $($module.runtimeLibrary)"
    }
}

$sourceParams = @{
    NONAME_SOURCE_TYPE    = $NonameSourceType
    NONAME_SOURCE_INDEX   = $NonameSourceIndex
    NONAME_SOURCE_KEY     = $NonameSourceKey
    NONAME_ENGINE_URL     = $NonameEngineUrl
    NONAME_SOURCE_VERSION = $NonameSourceVersion
}

# ===========================================================================
#region Dynatrace
# Send a custom event to the Dynatrace Events API v2.
# https://docs.dynatrace.com/docs/dynatrace-api/environment-api/events-v2/post-event
#
# eventType must be one of:
#   CUSTOM_INFO | CUSTOM_DEPLOYMENT | CUSTOM_ANNOTATION | CUSTOM_CONFIGURATION | ERROR_EVENT
#
# All calls are best-effort: failures are logged as warnings, never fatal.
# ===========================================================================

function Test-DynatraceEnabled {
    return (-not [string]::IsNullOrWhiteSpace($DynatraceApiUrl) -and
            -not [string]::IsNullOrWhiteSpace($DynatraceApiToken))
}

function Send-DynatraceEvent {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("CUSTOM_INFO","CUSTOM_DEPLOYMENT","CUSTOM_ANNOTATION","CUSTOM_CONFIGURATION","ERROR_EVENT")]
        [string]$EventType,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [string]$Description = "",

        [hashtable]$Properties = @{}
    )

    if (-not (Test-DynatraceEnabled)) { return }

    # Standard properties always included for correlation in the Dynatrace UI.
    $mergedProps = @{
        "noname.action"     = $Action
        "noname.computer"   = $env:COMPUTERNAME
        "noname.version"    = $NonameSourceVersion
        "noname.engine_url" = $NonameEngineUrl
        "noname.dry_run"    = ([string]$script:DryRun)
        "noname.force"      = ([string]$script:Force)
    }
    foreach ($k in $Properties.Keys) { $mergedProps[$k] = [string]$Properties[$k] }

    $body = @{
        eventType  = $EventType
        title      = $Title
        properties = $mergedProps
    }
    if (-not [string]::IsNullOrWhiteSpace($Description)) {
        $body["description"] = $Description
    }

    $bodyJson = $body | ConvertTo-Json -Depth 6 -Compress

    if ($script:DryRun) {
        Write-DryRun "Would POST Dynatrace event '$EventType / $Title' to '$DynatraceApiUrl'."
        return
    }

    try {
        $headers = @{
            "Authorization" = "Api-Token $DynatraceApiToken"
            "Content-Type"  = "application/json"
        }
        Invoke-WebRequest -Uri $DynatraceApiUrl `
                          -Method Post `
                          -Headers $headers `
                          -Body $bodyJson `
                          -TimeoutSec $DynatraceTimeoutSec `
                          -UseBasicParsing `
                          -ErrorAction Stop | Out-Null
        Write-Host -ForegroundColor Cyan "Dynatrace event sent: $EventType / $Title"
    }
    catch {
        Write-Host -ForegroundColor Yellow "Warning: Failed sending Dynatrace event '$Title'. $($_.Exception.Message)"
    }
}

#endregion Dynatrace

function Write-DryRun {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host -ForegroundColor Magenta "[DRY-RUN] $Message"
}

function Import-RequiredModules {
    $requiredModules = @("WebAdministration", "IISAdministration")
    foreach ($m in $requiredModules) {
        try {
            if (-not (Get-Module -ListAvailable -Name $m)) {
                Write-Host -ForegroundColor Yellow "Warning: PowerShell module '$m' not found. IIS features or management tools may not be installed."
                continue
            }
            Import-Module $m -ErrorAction Stop -Force
            Write-Host -ForegroundColor Cyan "Loaded PowerShell module '$m'."
        }
        catch {
            Write-Host -ForegroundColor Yellow "Warning: Failed to load PowerShell module '$m'. $($_.Exception.Message)"
        }
    }
}

function Test-IISAvailable {
    try {
        if (Get-Command Get-WebConfiguration -ErrorAction SilentlyContinue) { return $true }
        if (Test-Path -LiteralPath $appCmd) { return $true }
        return $false
    }
    catch {
        return $false
    }
}

function Get-IISVersion {
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\InetStp"
        $props = Get-ItemProperty -Path $regPath -ErrorAction Stop
        $major = $props.MajorVersion
        $minor = $props.MinorVersion
        return [PSCustomObject]@{
            Detected = $true
            Major    = $major
            Minor    = $minor
            Version  = "$major.$minor"
        }
    }
    catch {
        return [PSCustomObject]@{
            Detected = $false
            Major    = $null
            Minor    = $null
            Version  = $null
        }
    }
}

function Test-IsAdministrator {
    try {
        $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Get-EnvironmentVariableTarget {
    switch ($EnvironmentVariableScope) {
        "Machine" { return [System.EnvironmentVariableTarget]::Machine }
        "User"    { return [System.EnvironmentVariableTarget]::User }
        "Process" { return [System.EnvironmentVariableTarget]::Process }
        default   { return [System.EnvironmentVariableTarget]::Machine }
    }
}

function Get-Preferred-LogFileName {
    if ($UseHostBasedLogName) { return ("noname-{0}.log" -f $env:COMPUTERNAME) }
    if ([string]::IsNullOrWhiteSpace($LogFileName)) { return "noname.log" }
    return $LogFileName
}

function Resolve-FullPathSafe {
    param(
        [Parameter(Mandatory = $true)][string]$PathValue,
        [Parameter(Mandatory = $true)][string]$ParamName
    )
    try {
        return [System.IO.Path]::GetFullPath($PathValue)
    }
    catch {
        throw "Invalid $ParamName provided '$PathValue'"
    }
}

function Get-Package-Source-Dir {
    if ([string]::IsNullOrWhiteSpace($PackageSourceDir)) { return (Get-Location).Path }
    try {
        return [System.IO.Path]::GetFullPath($PackageSourceDir)
    }
    catch {
        throw "Invalid PackageSourceDir provided '$PackageSourceDir'"
    }
}

function Test-DirectoryWritable {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$NoCreate
    )
    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            if ($NoCreate -or $script:DryRun) { return $false }
            New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null
        }
        if ($script:DryRun) { return $true }
        $probe = Join-Path $Path ("write-test-{0}.tmp" -f [guid]::NewGuid().ToString())
        [System.IO.File]::WriteAllText($probe, "test")
        Remove-Item -LiteralPath $probe -Force -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Test-PathWritable {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$NoCreate
    )
    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            if ($NoCreate -or $script:DryRun) { return $false }
            New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null
        }
        if ($script:DryRun) { return $true }
        $probe = Join-Path $Path ("preflight-{0}.tmp" -f ([guid]::NewGuid().ToString()))
        [System.IO.File]::WriteAllText($probe, "test")
        Remove-Item -LiteralPath $probe -Force -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Resolve-LogDirWithFallback {
    $candidates = New-Object System.Collections.Generic.List[string]

    if (-not [string]::IsNullOrWhiteSpace($LogDir)) {
        $candidates.Add((Resolve-FullPathSafe -PathValue $LogDir -ParamName "LogDir"))
    }

    if ($EnableLogDirFallback) {
        if ($LogDirFallbackPaths -and $LogDirFallbackPaths.Count -gt 0) {
            foreach ($fallbackPath in $LogDirFallbackPaths) {
                try {
                    $resolvedFallback = [System.IO.Path]::GetFullPath($fallbackPath)
                    if (-not $candidates.Contains($resolvedFallback)) {
                        $candidates.Add($resolvedFallback)
                    }
                }
                catch {
                    Write-Host -ForegroundColor Yellow "Warning: Invalid fallback log path '$fallbackPath'."
                }
            }
        }
        else {
            $defaultProgramDataLogDir = Join-Path $env:ProgramData "Noname\Logs"
            $tempRoot = [System.IO.Path]::GetTempPath()
            $tempLogDir = Join-Path $tempRoot "Noname\Logs"
            if (-not $candidates.Contains($defaultProgramDataLogDir)) { $candidates.Add($defaultProgramDataLogDir) }
            if (-not $candidates.Contains($tempLogDir)) { $candidates.Add($tempLogDir) }
        }
    }

    if ($candidates.Count -eq 0) {
        $candidates.Add((Join-Path $env:ProgramData "Noname\Logs"))
    }

    foreach ($candidate in $candidates) {
        if ($script:DryRun) {
            Write-DryRun "Would evaluate log directory candidate '$candidate'."
            if (Test-Path -LiteralPath $candidate) { return $candidate }
            continue
        }
        if (Test-DirectoryWritable -Path $candidate) { return $candidate }
        Write-Host -ForegroundColor Yellow "Warning: Log directory candidate not writable '$candidate'."
    }

    if ($script:DryRun -and $candidates.Count -gt 0) {
        Write-Host -ForegroundColor Yellow "Warning: Dry-run could not prove any log directory candidate already exists. Returning first candidate only for simulation."
        return $candidates[0]
    }

    throw "Unable to resolve a writable log directory from the configured candidates."
}

function Validate-InstallParameters {
    $validationErrors = New-Object System.Collections.Generic.List[string]

    if ([string]::IsNullOrWhiteSpace($NonameSourceType))   { $validationErrors.Add("NonameSourceType cannot be empty.") }
    if ([string]::IsNullOrWhiteSpace($NonameSourceIndex))  { $validationErrors.Add("NonameSourceIndex cannot be empty.") }
    if ([string]::IsNullOrWhiteSpace($NonameSourceKey))    { $validationErrors.Add("NonameSourceKey cannot be empty.") }

    if ([string]::IsNullOrWhiteSpace($NonameEngineUrl)) {
        $validationErrors.Add("NonameEngineUrl cannot be empty.")
    }
    else {
        $uri = $null
        if (-not [System.Uri]::TryCreate($NonameEngineUrl, [System.UriKind]::Absolute, [ref]$uri)) {
            $validationErrors.Add("NonameEngineUrl must be a valid absolute URL.")
        }
        elseif ($uri.Scheme -ne [System.Uri]::UriSchemeHttps) {
            $validationErrors.Add("NonameEngineUrl must use HTTPS.")
        }
    }

    if ([string]::IsNullOrWhiteSpace($NonameSourceVersion)) { $validationErrors.Add("NonameSourceVersion cannot be empty.") }

    if (-not [string]::IsNullOrWhiteSpace($LogDir)) {
        try { [System.IO.Path]::GetFullPath($LogDir) | Out-Null } catch { $validationErrors.Add("LogDir is not a valid path.") }
    }
    if (-not [string]::IsNullOrWhiteSpace($StateDir)) {
        try { [System.IO.Path]::GetFullPath($StateDir) | Out-Null } catch { $validationErrors.Add("StateDir is not a valid path.") }
    }

    if ([string]::IsNullOrWhiteSpace($LogFileName)) {
        $validationErrors.Add("LogFileName cannot be empty.")
    }
    else {
        foreach ($invalidChar in [System.IO.Path]::GetInvalidFileNameChars()) {
            if ($LogFileName.Contains([string]$invalidChar)) {
                $validationErrors.Add("LogFileName contains invalid filename characters.")
                break
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($LogForwardUrl)) {
        $forwardUri = $null
        if (-not [System.Uri]::TryCreate($LogForwardUrl, [System.UriKind]::Absolute, [ref]$forwardUri)) {
            $validationErrors.Add("LogForwardUrl must be a valid absolute URL.")
        }
        elseif ($forwardUri.Scheme -ne [System.Uri]::UriSchemeHttps) {
            $validationErrors.Add("LogForwardUrl must use HTTPS.")
        }
    }

    # Dynatrace param validation
    if (-not [string]::IsNullOrWhiteSpace($DynatraceApiUrl)) {
        $dtUri = $null
        if (-not [System.Uri]::TryCreate($DynatraceApiUrl, [System.UriKind]::Absolute, [ref]$dtUri)) {
            $validationErrors.Add("DynatraceApiUrl must be a valid absolute URL.")
        }
        elseif ($dtUri.Scheme -ne [System.Uri]::UriSchemeHttps) {
            $validationErrors.Add("DynatraceApiUrl must use HTTPS.")
        }
        if ([string]::IsNullOrWhiteSpace($DynatraceApiToken)) {
            $validationErrors.Add("DynatraceApiToken is required when DynatraceApiUrl is specified.")
        }
    }
    if ($DynatraceTimeoutSec -lt 1) { $validationErrors.Add("DynatraceTimeoutSec must be greater than 0.") }

    if (-not [string]::IsNullOrWhiteSpace($PackageSourceDir)) {
        try { [System.IO.Path]::GetFullPath($PackageSourceDir) | Out-Null } catch { $validationErrors.Add("PackageSourceDir is not a valid path.") }
    }

    if ($AzureMetadataTimeoutSec -lt 1)        { $validationErrors.Add("AzureMetadataTimeoutSec must be greater than 0.") }
    if ($LogForwardTimeoutSec -lt 1)           { $validationErrors.Add("LogForwardTimeoutSec must be greater than 0.") }
    if ($EngineConnectivityTimeoutSec -lt 1)   { $validationErrors.Add("EngineConnectivityTimeoutSec must be greater than 0.") }
    if ([string]::IsNullOrWhiteSpace($RuntimeInstallArgs)) { $validationErrors.Add("RuntimeInstallArgs cannot be empty.") }

    if ($LogDirFallbackPaths) {
        foreach ($fallbackPath in $LogDirFallbackPaths) {
            try { [System.IO.Path]::GetFullPath($fallbackPath) | Out-Null }
            catch { $validationErrors.Add("LogDirFallbackPaths contains an invalid path: $fallbackPath") }
        }
    }

    if ($Action -in @("install","repair") -and $EnvironmentVariableScope -ne "Machine") {
        $validationErrors.Add("EnvironmentVariableScope must be 'Machine' for install/repair because IIS worker processes need persistent machine-level variables.")
    }

    if ($validationErrors.Count -gt 0) {
        throw ("Install parameter validation failed:`n - " + ($validationErrors -join "`n - "))
    }
}

function Add-PreflightResult {
    param(
        [Parameter(Mandatory = $true)]$Results,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet("PASS","WARN","FAIL")][string]$Status,
        [Parameter(Mandatory = $true)][string]$Details,
        # Pass the caught $_ ErrorRecord to capture full exception detail on failures.
        $ErrorRecord = $null
    )

    $errorDetail = $null
    if ($null -ne $ErrorRecord) {
        $ex = $ErrorRecord.Exception
        $errorDetail = [ordered]@{
            ExceptionType    = $ex.GetType().FullName
            ExceptionMessage = $ex.Message
            InnerException   = if ($null -ne $ex.InnerException) { $ex.InnerException.Message } else { $null }
            ScriptStackTrace = $ErrorRecord.ScriptStackTrace
            PositionMessage  = if ($null -ne $ErrorRecord.InvocationInfo) { $ErrorRecord.InvocationInfo.PositionMessage } else { $null }
        }
    }

    $Results.Add([PSCustomObject]@{
        Check       = $Name
        Status      = $Status
        Details     = $Details
        ErrorDetail = $errorDetail
    }) | Out-Null
}

function Get-Default-Paths {
    $resolvedLogDir = Resolve-LogDirWithFallback

    $resolvedStateDir = if ([string]::IsNullOrWhiteSpace($StateDir)) {
        Join-Path $env:ProgramData "Noname\State"
    }
    else {
        Resolve-FullPathSafe -PathValue $StateDir -ParamName "StateDir"
    }

    $resolvedInstallDir = if ([string]::IsNullOrWhiteSpace($InstallDir)) {
        Join-Path $env:ProgramFiles "Noname Module"
    }
    else {
        Resolve-FullPathSafe -PathValue $InstallDir -ParamName "InstallDir"
    }

    $resolvedLogFileName = Get-Preferred-LogFileName

    [PSCustomObject]@{
        InstallDir             = $resolvedInstallDir
        LogDir                 = $resolvedLogDir
        LogFileName            = $resolvedLogFileName
        LogFilePath            = Join-Path $resolvedLogDir $resolvedLogFileName
        StateDir               = $resolvedStateDir
        PendingInstallMarker   = Join-Path $resolvedStateDir "pending-install-activation.json"
        PendingUninstallMarker = Join-Path $resolvedStateDir "pending-uninstall-activation.json"
        PreflightStateFile     = Join-Path $resolvedStateDir "last-preflight.json"
        IISConfigPath          = Join-Path $env:windir "System32\inetsrv\config\applicationHost.config"
        AppCmdPath             = Join-Path $env:windir "System32\inetsrv\appcmd.exe"
    }
}

# ===========================================================================
#region Preflight state persistence
# ===========================================================================

function Write-PreflightState {
    param(
        [Parameter(Mandatory = $true)]$PreflightResult
    )

    $paths = Get-Default-Paths
    New-NonameDirectory -Path $paths.StateDir

    $markerPath = $paths.PreflightStateFile

    # Build the Results array carrying full ErrorDetail for every check so that
    # failed/warned checks include exception type, message, inner exception,
    # and script stack trace — not just the human-readable Details string.
    $resultRows = @($PreflightResult.Results | ForEach-Object {
        $row = [ordered]@{
            Check   = $_.Check
            Status  = $_.Status
            Details = $_.Details
        }
        if ($null -ne $_.ErrorDetail) {
            $row['ErrorDetail'] = $_.ErrorDetail
        }
        $row
    })

    $payload = [ordered]@{
        SchemaVersion    = "1.1"
        TimestampUtc     = (Get-Date).ToUniversalTime().ToString("o")
        ComputerName     = $env:COMPUTERNAME
        NonameVersion    = $NonameSourceVersion
        EngineUrl        = $NonameEngineUrl
        Summary          = [ordered]@{
            Pass              = $PreflightResult.Summary.Pass
            Warn              = $PreflightResult.Summary.Warn
            Fail              = $PreflightResult.Summary.Fail
            ExitCode          = $PreflightResult.Summary.ExitCode
            EngineCheckStatus = $PreflightResult.Summary.EngineCheckStatus
            FailedChecks      = @($PreflightResult.Results | Where-Object { $_.Status -eq 'FAIL' } | ForEach-Object { $_.Check })
            WarnedChecks      = @($PreflightResult.Results | Where-Object { $_.Status -eq 'WARN' } | ForEach-Object { $_.Check })
        }
        Results          = $resultRows
    } | ConvertTo-Json -Depth 8

    if ($script:DryRun) {
        Write-DryRun "Would write preflight state to '$markerPath'."
        return
    }

    Set-Content -LiteralPath $markerPath -Value $payload -Encoding UTF8
    Write-Host -ForegroundColor Cyan "Preflight state written to '$markerPath'."
}

function Read-PreflightState {
    $paths = Get-Default-Paths
    $markerPath = $paths.PreflightStateFile

    if (-not (Test-Path -LiteralPath $markerPath)) { return $null }

    try {
        $raw = Get-Content -LiteralPath $markerPath -Raw -Encoding UTF8
        return $raw | ConvertFrom-Json
    }
    catch {
        Write-Host -ForegroundColor Yellow "Warning: Could not read preflight state file '$markerPath'. $($_.Exception.Message)"
        return $null
    }
}

#endregion Preflight state persistence

function Test-EngineReachable {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [int]$TimeoutSec = 10
    )

    $uri = $null
    try { $uri = [Uri]$Url }
    catch {
        return @{ Reachable = $false; Details = "Invalid URL."; HttpReachable = $false; TcpReachable = $false; EngineOk = $false; StatusCode = $null; Body = $null }
    }

    try {
        $response = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop

        $statusOk    = ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300)
        $bodyText    = if ($null -ne $response.Content) { [string]$response.Content } else { "" }
        $trimmedBody = $bodyText.Trim()
        $bodyLooksOk = ($trimmedBody -eq "OK")

        if ($statusOk -and $bodyLooksOk) {
            return @{ Reachable = $true;  Details = "Engine returned HTTP $($response.StatusCode) and body 'OK'."; HttpReachable = $true; TcpReachable = $true; EngineOk = $true;  StatusCode = $response.StatusCode; Body = $trimmedBody }
        }
        if ($statusOk) {
            return @{ Reachable = $false; Details = "Engine returned HTTP $($response.StatusCode) but body was not exactly 'OK'. Body: '$trimmedBody'"; HttpReachable = $true; TcpReachable = $true; EngineOk = $false; StatusCode = $response.StatusCode; Body = $trimmedBody }
        }
        return @{ Reachable = $false; Details = "Engine returned unexpected HTTP status $($response.StatusCode)."; HttpReachable = $true; TcpReachable = $true; EngineOk = $false; StatusCode = $response.StatusCode; Body = $trimmedBody }
    }
    catch {
        $httpError = $_.Exception.Message
        $port = if ($uri.Port -gt 0) { $uri.Port } elseif ($uri.Scheme -eq "https") { 443 } else { 80 }

        $tcpOk = $false
        if (Get-Command Test-NetConnection -ErrorAction SilentlyContinue) {
            try {
                $tcp = Test-NetConnection -ComputerName $uri.Host -Port $port -WarningAction SilentlyContinue
                $tcpOk = [bool]$tcp.TcpTestSucceeded
            }
            catch { $tcpOk = $false }
        }

        if ($tcpOk) {
            return @{ Reachable = $false; Details = "TCP connectivity to $($uri.Host):$port succeeded, but HTTP GET failed: $httpError"; HttpReachable = $false; TcpReachable = $true; EngineOk = $false; StatusCode = $null; Body = $null }
        }
        return @{ Reachable = $false; Details = "HTTP GET failed and TCP connectivity could not be confirmed. Error: $httpError"; HttpReachable = $false; TcpReachable = $false; EngineOk = $false; StatusCode = $null; Body = $null }
    }
}

function Test-Preflight {
    $results = New-Object System.Collections.Generic.List[object]

    $paths = $null
    try {
        $paths = Get-Default-Paths
        Add-PreflightResult -Results $results -Name "Path resolution" -Status "PASS" -Details "Resolved install/log/state paths successfully."
    }
    catch {
        Add-PreflightResult -Results $results -Name "Path resolution" -Status "FAIL" -Details $_.Exception.Message -ErrorRecord $_
    }

    try {
        $osCaption = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption
        Add-PreflightResult -Results $results -Name "Operating system" -Status "PASS" -Details $osCaption
    }
    catch {
        Add-PreflightResult -Results $results -Name "Operating system" -Status "FAIL" -Details "Unable to confirm Windows operating system." -ErrorRecord $_
    }

    Add-PreflightResult -Results $results -Name "PowerShell version" -Status "PASS" `
        -Details ("Windows PowerShell {0}" -f $PSVersionTable.PSVersion)

    if (Test-IsAdministrator) {
        Add-PreflightResult -Results $results -Name "Administrator rights" -Status "PASS" -Details "Running elevated."
    }
    else {
        Add-PreflightResult -Results $results -Name "Administrator rights" -Status "FAIL" -Details "Script must be run as Administrator."
    }

    if (Get-Module -ListAvailable -Name WebAdministration) {
        Add-PreflightResult -Results $results -Name "WebAdministration module" -Status "PASS" -Details "Module is available."
    }
    else {
        Add-PreflightResult -Results $results -Name "WebAdministration module" -Status "WARN" -Details "Module not available. appcmd fallback may still work."
    }

    if (Get-Module -ListAvailable -Name IISAdministration) {
        Add-PreflightResult -Results $results -Name "IISAdministration module" -Status "PASS" -Details "Module is available."
    }
    else {
        Add-PreflightResult -Results $results -Name "IISAdministration module" -Status "WARN" -Details "Module not available."
    }

    if (Test-IISAvailable) {
        Add-PreflightResult -Results $results -Name "IIS availability" -Status "PASS" -Details "IIS management commands or appcmd are available."
    }
    else {
        Add-PreflightResult -Results $results -Name "IIS availability" -Status "FAIL" -Details "IIS management commands are not available."
    }

    $iisVersion = Get-IISVersion
    if (-not $iisVersion.Detected) {
        Add-PreflightResult -Results $results -Name "IIS version" -Status "FAIL" -Details "Unable to determine IIS version."
    }
    elseif ($iisVersion.Major -eq 10) {
        Add-PreflightResult -Results $results -Name "IIS version" -Status "PASS" -Details "IIS $($iisVersion.Version) detected."
    }
    else {
        Add-PreflightResult -Results $results -Name "IIS version" -Status "FAIL" -Details "Unsupported IIS version: $($iisVersion.Version). IIS 10 is required."
    }

    $pathsForIIS = $null
    try { $pathsForIIS = Get-Default-Paths } catch {}

    if ($pathsForIIS -and (Test-Path -LiteralPath $pathsForIIS.AppCmdPath)) {
        Add-PreflightResult -Results $results -Name "appcmd.exe" -Status "PASS" -Details $pathsForIIS.AppCmdPath
    }
    else {
        Add-PreflightResult -Results $results -Name "appcmd.exe" -Status "FAIL" -Details "appcmd.exe not found. IIS management tools may not be installed."
    }

    try {
        $packageDir = Get-Package-Source-Dir
        Add-PreflightResult -Results $results -Name "PackageSourceDir" -Status "PASS" -Details $packageDir
    }
    catch {
        Add-PreflightResult -Results $results -Name "PackageSourceDir" -Status "FAIL" -Details $_.Exception.Message -ErrorRecord $_
    }

    Add-PreflightResult -Results $results -Name "Environment variable scope"  -Status "PASS" -Details $EnvironmentVariableScope
    Add-PreflightResult -Results $results -Name "Azure metadata enabled"       -Status "PASS" -Details ([string]$EnableAzureMetadata)
    Add-PreflightResult -Results $results -Name "Azure metadata timeout"       -Status "PASS" -Details ([string]$AzureMetadataTimeoutSec)
    Add-PreflightResult -Results $results -Name "Log forwarding timeout"       -Status "PASS" -Details ([string]$LogForwardTimeoutSec)
    Add-PreflightResult -Results $results -Name "Engine connectivity timeout"  -Status "PASS" -Details ([string]$EngineConnectivityTimeoutSec)
    Add-PreflightResult -Results $results -Name "Runtime install args"         -Status "PASS" -Details $RuntimeInstallArgs
    Add-PreflightResult -Results $results -Name "Log dir fallback enabled"     -Status "PASS" -Details ([string]$EnableLogDirFallback)
    Add-PreflightResult -Results $results -Name "Fail on warnings"             -Status "PASS" -Details ([string]$FailOnWarnings)
    Add-PreflightResult -Results $results -Name "Force mode"                   -Status "PASS" -Details ([string]$script:Force)

    # Dynatrace configuration check
    if (-not [string]::IsNullOrWhiteSpace($DynatraceApiUrl)) {
        if (-not [string]::IsNullOrWhiteSpace($DynatraceApiToken)) {
            Add-PreflightResult -Results $results -Name "Dynatrace integration" -Status "PASS" -Details "Dynatrace URL and token configured."
        }
        else {
            Add-PreflightResult -Results $results -Name "Dynatrace integration" -Status "WARN" -Details "DynatraceApiUrl is set but DynatraceApiToken is missing. Events will be skipped."
        }
    }
    else {
        Add-PreflightResult -Results $results -Name "Dynatrace integration" -Status "PASS" -Details "Dynatrace not configured (optional)."
    }

    foreach ($module in $modules) {
        $dllPath = Join-Path (Get-Package-Source-Dir) $module.dllName
        if (Test-Path -LiteralPath $dllPath) {
            Add-PreflightResult -Results $results -Name ("Source DLL: " + $module.dllName) -Status "PASS" -Details $dllPath
        }
        else {
            Add-PreflightResult -Results $results -Name ("Source DLL: " + $module.dllName) -Status "FAIL" -Details ("Missing file: {0}" -f $dllPath)
        }

        $runtimePath = Join-Path (Get-Package-Source-Dir) $module.runtimeLibrary
        if (Test-Path -LiteralPath $runtimePath) {
            Add-PreflightResult -Results $results -Name ("Runtime installer: " + $module.runtimeLibrary) -Status "PASS" -Details $runtimePath
        }
        else {
            Add-PreflightResult -Results $results -Name ("Runtime installer: " + $module.runtimeLibrary) -Status "WARN" -Details ("Missing file: {0}" -f $runtimePath)
        }
    }

    try {
        Validate-InstallParameters
        Add-PreflightResult -Results $results -Name "Install parameter validation" -Status "PASS" -Details "Source and logging parameters validated."
    }
    catch {
        Add-PreflightResult -Results $results -Name "Install parameter validation" -Status "FAIL" -Details $_.Exception.Message -ErrorRecord $_
    }

    # VC++ runtime check
    try {
        $runtimeLibs = @($modules | ForEach-Object { $_.runtimeLibrary }) | Select-Object -Unique
        $vcCheck = Check-Runtime-Libraries -runtimeLibraries $runtimeLibs
        $minVer = $vcCheck.MinimumVersion

        foreach ($arch in @('x64', 'x86')) {
            $required = ($modules | Where-Object { $_.runtimeLibrary -match $arch }) -ne $null
            if (-not $required) { continue }

            if ($vcCheck.Detected.$arch) {
                $matched = ($vcCheck.MatchedPackages | Where-Object { $_ -match "\b$arch\b" }) -join '; '
                Add-PreflightResult -Results $results -Name "VC++ runtime ($arch)" -Status "PASS" `
                    -Details "Sufficient package found (>= $minVer): $matched"
            }
            else {
                Add-PreflightResult -Results $results -Name "VC++ runtime ($arch)" -Status "WARN" `
                    -Details "No VC++ package >= $minVer found for $arch. Install will attempt to install it from the package source."
            }
        }
    }
    catch {
        Add-PreflightResult -Results $results -Name "VC++ runtime check" -Status "WARN" `
            -Details "Unable to enumerate VC++ packages: $($_.Exception.Message)" -ErrorRecord $_
    }

    if ($paths) {
        if ((Test-Path -LiteralPath $paths.InstallDir) -and (Test-PathWritable -Path $paths.InstallDir -NoCreate)) {
            Add-PreflightResult -Results $results -Name "InstallDir writable" -Status "PASS" -Details $paths.InstallDir
        }
        else {
            Add-PreflightResult -Results $results -Name "InstallDir writable" -Status "WARN" -Details ("Path does not yet exist or is not writable without creating it: {0}" -f $paths.InstallDir)
        }

        if ((Test-Path -LiteralPath $paths.LogDir) -and (Test-PathWritable -Path $paths.LogDir -NoCreate)) {
            Add-PreflightResult -Results $results -Name "LogDir writable" -Status "PASS" -Details $paths.LogDir
        }
        else {
            Add-PreflightResult -Results $results -Name "LogDir writable" -Status "WARN" -Details ("Path does not yet exist or is not writable without creating it: {0}" -f $paths.LogDir)
        }

        if ((Test-Path -LiteralPath $paths.StateDir) -and (Test-PathWritable -Path $paths.StateDir -NoCreate)) {
            Add-PreflightResult -Results $results -Name "StateDir writable" -Status "PASS" -Details $paths.StateDir
        }
        else {
            Add-PreflightResult -Results $results -Name "StateDir writable" -Status "WARN" -Details ("Path does not yet exist or is not writable without creating it: {0}" -f $paths.StateDir)
        }

        Add-PreflightResult -Results $results -Name "Resolved log file" -Status "PASS" -Details $paths.LogFilePath
    }

    # Engine connectivity — always at least WARN when unreachable.
    # EngineCheckStatus is surfaced on Summary so Install-Agent can gate on it
    # independently from the aggregate ExitCode.
    $engineCheckStatus = $null
    if (-not [string]::IsNullOrWhiteSpace($NonameEngineUrl)) {
        try {
            $uri = [Uri]$NonameEngineUrl
            Add-PreflightResult -Results $results -Name "Engine URL format" -Status "PASS" -Details $uri.AbsoluteUri

            $engineCheck = Test-EngineReachable -Url $NonameEngineUrl -TimeoutSec $EngineConnectivityTimeoutSec
            if ($engineCheck.Reachable) {
                $engineCheckStatus = "PASS"
                Add-PreflightResult -Results $results -Name "Engine connectivity" -Status "PASS" -Details $engineCheck.Details
            }
            else {
                $engineCheckStatus = "WARN"
                $engineDetails = $engineCheck.Details
                if ($FailOnWarnings -and -not $script:Force) {
                    $engineCheckStatus = "FAIL"
                    $engineDetails = "$($engineCheck.Details) FailOnWarnings is enabled, so engine connectivity is treated as FAIL."
                }
                Add-PreflightResult -Results $results -Name "Engine connectivity" -Status $engineCheckStatus -Details $engineDetails
            }
        }
        catch {
            $engineCheckStatus = "FAIL"
            Add-PreflightResult -Results $results -Name "Engine URL format"   -Status "FAIL" -Details "Engine URL is invalid." -ErrorRecord $_
            Add-PreflightResult -Results $results -Name "Engine connectivity" -Status "FAIL" -Details "Skipped because engine URL is invalid."
        }
    }

    $passCount = ($results | Where-Object Status -eq "PASS").Count
    $warnCount = ($results | Where-Object Status -eq "WARN").Count
    $failCount = ($results | Where-Object Status -eq "FAIL").Count

    $exitCode = 0
    if ($failCount -gt 0) { $exitCode = 1 }
    elseif ($FailOnWarnings -and $warnCount -gt 0) { $exitCode = 1 }

    [PSCustomObject]@{
        Summary = [PSCustomObject]@{
            Pass              = $passCount
            Warn              = $warnCount
            Fail              = $failCount
            ExitCode          = $exitCode
            EngineCheckStatus = $engineCheckStatus
        }
        Results = $results
    }
}

function New-NonameDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (Test-Path -LiteralPath $Path) { return }
    if ($script:DryRun) { Write-DryRun "Would create directory '$Path'."; return }
    New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null
}

function Get-Install-Dir-Path {
    param([string]$InstallDir)
    if ([string]::IsNullOrWhiteSpace($InstallDir)) {
        return (Join-Path $env:ProgramFiles "Noname Module")
    }
    try {
        return [System.IO.Path]::GetFullPath($InstallDir)
    }
    catch {
        throw "Invalid install directory provided '$InstallDir'"
    }
}

function Get-Environment-Variable {
    param([string]$envName)
    [System.Environment]::GetEnvironmentVariable($envName, (Get-EnvironmentVariableTarget))
}

function Set-Environment-Variable {
    param([string]$envName, [string]$envValue)
    if ($script:DryRun) {
        Write-DryRun "Would set $EnvironmentVariableScope environment variable '$envName' to '$envValue'."
        return
    }
    [System.Environment]::SetEnvironmentVariable($envName, $envValue, (Get-EnvironmentVariableTarget))
}

function Remove-Environment-Variable {
    param([Parameter(Mandatory = $true)][string]$envName)
    try {
        if ($script:DryRun) { Write-DryRun "Would clear $EnvironmentVariableScope environment variable '$envName'."; return }
        [System.Environment]::SetEnvironmentVariable($envName, $null, (Get-EnvironmentVariableTarget))
        Write-Host -ForegroundColor Cyan "Environment variable '$envName' cleared."
    }
    catch {
        Write-Host -ForegroundColor Yellow "Warning: Failed to clear environment variable '$envName'. $($_.Exception.Message)"
    }
}

function Remove-Item-IfExists {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$Recurse
    )
    try {
        if (Test-Path -LiteralPath $Path) {
            if ($script:DryRun) {
                $suffix = if ($Recurse) { " recursively" } else { "" }
                Write-DryRun "Would remove '$Path'$suffix."
                return
            }
            if ($Recurse) { Remove-Item -LiteralPath $Path -Force -Recurse -ErrorAction Stop }
            else          { Remove-Item -LiteralPath $Path -Force -ErrorAction Stop }
            Write-Host -ForegroundColor Cyan "Removed '$Path'."
        }
        else {
            Write-Host -ForegroundColor Yellow "Warning: Path does not exist, skipping '$Path'."
        }
    }
    catch {
        Write-Host -ForegroundColor Yellow "Warning: Failed removing '$Path'. $($_.Exception.Message)"
    }
}

function Get-Paths { return (Get-Default-Paths) }

function Get-PendingMarkerPath {
    param([ValidateSet("Install","Uninstall")] [string]$Type)
    $paths = Get-Paths
    switch ($Type) {
        "Install"   { return $paths.PendingInstallMarker }
        "Uninstall" { return $paths.PendingUninstallMarker }
    }
}

function Write-PendingState {
    param(
        [ValidateSet("Install","Uninstall")] [string]$Type,
        [string]$Reason
    )
    $paths = Get-Paths
    New-NonameDirectory -Path $paths.StateDir

    $markerPath = Get-PendingMarkerPath -Type $Type
    $payload = @{
        Type         = $Type
        ComputerName = $env:COMPUTERNAME
        TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
        Reason       = $Reason
    } | ConvertTo-Json -Depth 4

    if ($script:DryRun) { Write-DryRun "Would write pending state '$Type' to '$markerPath'."; return }
    Set-Content -LiteralPath $markerPath -Value $payload -Encoding UTF8
}

function Clear-PendingState {
    param([ValidateSet("Install","Uninstall","All")] [string]$Type)
    $paths = Get-Paths
    switch ($Type) {
        "Install"   { Remove-Item-IfExists -Path $paths.PendingInstallMarker }
        "Uninstall" { Remove-Item-IfExists -Path $paths.PendingUninstallMarker }
        "All" {
            Remove-Item-IfExists -Path $paths.PendingInstallMarker
            Remove-Item-IfExists -Path $paths.PendingUninstallMarker
        }
    }
}

function Get-PendingActivationStatus {
    $paths = Get-Paths
    [PSCustomObject]@{
        PendingInstall   = Test-Path -LiteralPath $paths.PendingInstallMarker
        PendingUninstall = Test-Path -LiteralPath $paths.PendingUninstallMarker
        InstallMarker    = $paths.PendingInstallMarker
        UninstallMarker  = $paths.PendingUninstallMarker
    }
}

function Create-Noname-Log {
    $paths = Get-Paths
    New-NonameDirectory -Path $paths.LogDir

    if ($script:DryRun) {
        Write-DryRun "Would ensure log file exists at '$($paths.LogFilePath)'."
    }
    else {
        if (-not (Test-Path -LiteralPath $paths.LogFilePath)) {
            New-Item -ItemType File -Path $paths.LogFilePath -Force -ErrorAction Stop | Out-Null
        }
    }

    Set-Environment-Variable -envName "NONAME_LOG_FILE_LOCATION" -envValue $paths.LogFilePath
    Write-Host -ForegroundColor Cyan "NONAME_LOG_FILE_LOCATION set to '$($paths.LogFilePath)'"
}

function Clear-Noname-Log-State {
    Remove-Environment-Variable -envName "NONAME_LOG_FILE_LOCATION"
}

function Set-Source-Parameters {
    foreach ($key in $sourceParams.Keys) {
        Set-Environment-Variable -envName $key -envValue $sourceParams[$key]
    }
}

function Clear-Noname-Source-Parameters {
    foreach ($key in $sourceParams.Keys) {
        Remove-Environment-Variable -envName $key
    }
    Remove-Environment-Variable -envName $dir
    Remove-Environment-Variable -envName "AZURE_INSTANCE_METADATA"
}

function Set-Azure-Metadata {
    if (-not $EnableAzureMetadata) { return }

    $metadataValue = $null
    try {
        $headers = @{ Metadata = "true" }
        $uri = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
        $response = Invoke-WebRequest -Uri $uri -Method Get -Headers $headers -TimeoutSec $AzureMetadataTimeoutSec -UseBasicParsing -ErrorAction Stop
        if ($response.Content) { $metadataValue = [string]$response.Content }
    }
    catch {
        Write-Host -ForegroundColor Yellow "Warning: Failed retrieving Azure metadata. $($_.Exception.Message)"
    }

    if (-not [string]::IsNullOrWhiteSpace($metadataValue)) {
        Set-Environment-Variable -envName "AZURE_INSTANCE_METADATA" -envValue $metadataValue
    }
}

function Copy-Noname-Module-To-Dir {
    param([Parameter(Mandatory = $true)][string]$moduleDir)

    New-NonameDirectory -Path $moduleDir

    foreach ($module in $modules) {
        $dllName = $module.dllName
        $sourceDllPath = Join-Path (Get-Package-Source-Dir) $dllName
        $modulePath = Join-Path $moduleDir $dllName

        if (-not (Test-Path -LiteralPath $sourceDllPath)) {
            throw "Required module file not found: $sourceDllPath"
        }

        if ((-not $script:Force) -and (Test-Path -LiteralPath $modulePath)) {
            Write-Host -ForegroundColor Cyan "'$dllName' already exists at '$modulePath'. Skipping copy."
            continue
        }

        if ($script:DryRun) {
            Write-DryRun "Would copy '$sourceDllPath' to '$modulePath'. Force=$script:Force"
        }
        else {
            Copy-Item -Path $sourceDllPath -Destination $modulePath -Force -ErrorAction Stop
            Write-Host -ForegroundColor Cyan "'$dllName' was copied to '$modulePath'."
        }
    }

    Set-Environment-Variable -envName $dir -envValue $moduleDir
}

function Remove-Noname-Module-From-Dir {
    param([string]$moduleDir)

    if (-not $moduleDir -or -not (Test-Path -LiteralPath $moduleDir)) {
        Write-Host -ForegroundColor Yellow "Warning: Module directory does not exist. '$moduleDir'"
        return
    }

    foreach ($module in $modules) {
        $dllName = $module.dllName
        $modulePath = Join-Path $moduleDir $dllName
        try {
            if (Test-Path -LiteralPath $modulePath) {
                if ($script:DryRun) { Write-DryRun "Would remove '$modulePath'." }
                else {
                    Remove-Item -LiteralPath $modulePath -Force -ErrorAction Stop
                    Write-Host -ForegroundColor Cyan "'$dllName' was removed from '$modulePath'."
                }
            }
            else {
                Write-Host -ForegroundColor Yellow "Warning: '$dllName' not found at '$modulePath'."
            }
        }
        catch {
            Write-Host -ForegroundColor Yellow "Warning: Failed removing '$modulePath'. $($_.Exception.Message)"
        }
    }
}

function Get-VcRedistEntries {
    $entries = [System.Collections.Generic.List[object]]::new()
    $hives   = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WoW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($hive in $hives) {
        try {
            Get-ChildItem $hive -ErrorAction SilentlyContinue | ForEach-Object {
                $n = $_.GetValue('DisplayName')
                $v = $_.GetValue('DisplayVersion')
                if (-not [string]::IsNullOrWhiteSpace($n) -and $n -match 'Microsoft Visual C\+\+.*Redistributable') {
                    $entries.Add([PSCustomObject]@{ DisplayName = $n; DisplayVersion = $v; RegistryKey = $_.PSPath }) | Out-Null
                }
            }
        }
        catch { Write-Host -ForegroundColor Yellow "Warning: Could not enumerate registry hive '$hive'. $($_.Exception.Message)" }
    }
    return $entries
}

function Get-VcRedistMinimumVersion { return [Version]'14.16.0.0' }

function Test-VcRedistVersionSufficient {
    param([Parameter(Mandatory=$true)][string]$DisplayVersion, [Parameter(Mandatory=$true)][Version]$MinimumVersion)
    try { return ([Version]$DisplayVersion -ge $MinimumVersion) } catch { return $false }
}

function Check-Runtime-Libraries {
    param([string[]]$runtimeLibraries)

    Write-Host -ForegroundColor Cyan "`nChecking for Visual C++ Redistributable packages"

    $requiredArchitectures = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($lib in $runtimeLibraries) {
        if ($lib -match 'x64') { [void]$requiredArchitectures.Add('x64') }
        elseif ($lib -match 'x86') { [void]$requiredArchitectures.Add('x86') }
    }

    $minimumVersion = Get-VcRedistMinimumVersion
    $detected = @{ x86 = $false; x64 = $false }
    $matchedPackages = [System.Collections.Generic.List[string]]::new()

    foreach ($entry in (Get-VcRedistEntries)) {
        $displayName    = $entry.DisplayName
        $displayVersion = $entry.DisplayVersion

        if ($displayName -match '\bDebug\b') { Write-Host -ForegroundColor Yellow "Ignoring debug VC++ package: $displayName"; continue }

        $arch = $null
        if    ($displayName -match '\bARM64\b') { $arch = 'ARM64' }
        elseif ($displayName -match '\bx64\b')  { $arch = 'x64' }
        elseif ($displayName -match '\bx86\b')  { $arch = 'x86' }

        if ($null -eq $arch) { Write-Host -ForegroundColor Yellow "Warning: VC++ package with unrecognized architecture, skipping: $displayName"; continue }
        if ($arch -eq 'ARM64') { Write-Host -ForegroundColor Yellow "Skipping ARM64 VC++ package (not supported by IIS native module): $displayName"; continue }
        if ([string]::IsNullOrWhiteSpace($displayVersion)) { Write-Host -ForegroundColor Yellow "Warning: VC++ package has no DisplayVersion, skipping: $displayName"; continue }
        if (-not (Test-VcRedistVersionSufficient -DisplayVersion $displayVersion -MinimumVersion $minimumVersion)) {
            Write-Host -ForegroundColor Yellow ("Warning: VC++ package version $displayVersion is below minimum $minimumVersion - too old: $displayName")
            continue
        }

        $detected[$arch] = $true
        $matchedPackages.Add("$displayName ($displayVersion)")
        Write-Host -ForegroundColor Cyan "Detected sufficient VC++ Redistributable for ${arch}: $displayName ($displayVersion)"
    }

    $missing = [System.Collections.Generic.List[string]]::new()
    foreach ($arch in $requiredArchitectures) {
        if (-not $detected[$arch]) { $missing.Add($arch) }
    }

    [PSCustomObject]@{
        AllPresent           = ($missing.Count -eq 0)
        MissingArchitectures = $missing
        MinimumVersion       = $minimumVersion.ToString()
        Detected             = [PSCustomObject]$detected
        MatchedPackages      = $matchedPackages
    }
}

function Install-Runtime-Libraries {
    $runtimeLibraries = [System.Collections.Generic.List[string]]::new()
    foreach ($module in $modules) {
        if (-not [string]::IsNullOrWhiteSpace($module.runtimeLibrary)) {
            if (-not $runtimeLibraries.Contains($module.runtimeLibrary)) {
                $runtimeLibraries.Add($module.runtimeLibrary)
            }
        }
    }

    $runtimeCheck = Check-Runtime-Libraries -runtimeLibraries $runtimeLibraries
    $minimumVersion = $runtimeCheck.MinimumVersion

    foreach ($runtimeLibrary in $runtimeLibraries) {
        if ($runtimeLibrary -match 'debug') { throw "Debug VC++ runtime installer is not allowed: $runtimeLibrary" }

        $targetArch = if ($runtimeLibrary -match 'x64') { 'x64' } elseif ($runtimeLibrary -match 'x86') { 'x86' } else { $null }
        if ($null -eq $targetArch) {
            Write-Host -ForegroundColor Yellow "Warning: Unable to determine runtime architecture from '$runtimeLibrary'. Skipping."
            continue
        }

        $shouldInstall = $script:Force -or (-not $runtimeCheck.Detected.$targetArch)
        if (-not $shouldInstall) {
            Write-Host -ForegroundColor Cyan "Skipping runtime '$runtimeLibrary' - sufficient $targetArch package (>= $minimumVersion) already installed."
            continue
        }

        $runtimePath = Join-Path (Get-Package-Source-Dir) $runtimeLibrary
        if (-not (Test-Path -LiteralPath $runtimePath)) { throw "Runtime installer not found: $runtimePath" }

        if ($script:DryRun) {
            Write-DryRun "Would install runtime library '$runtimeLibrary' from '$runtimePath' with '$RuntimeInstallArgs'. Force=$script:Force"
        }
        else {
            Write-Host -ForegroundColor Cyan "Installing runtime library '$runtimeLibrary'. Force=$script:Force"
            $proc = Start-Process -FilePath $runtimePath -ArgumentList $RuntimeInstallArgs -Wait -PassThru
            if ($proc.ExitCode -notin @(0, 3010, 1638)) { throw "Runtime installer '$runtimeLibrary' failed with exit code $($proc.ExitCode)." }
            if ($proc.ExitCode -eq 3010) { Write-Host -ForegroundColor Yellow "Warning: Runtime '$runtimeLibrary' requires a reboot to complete." }
        }
    }

    if (-not $script:Force -and $runtimeCheck.AllPresent) {
        Write-Host -ForegroundColor Green "Success: All required Visual C++ Redistributables (>= $minimumVersion) were found."
    }
}

function Get-IISModuleRegistered {
    param([string]$ModuleName)
    try {
        if (Get-Command Get-WebConfigurationProperty -ErrorAction SilentlyContinue) {
            $result = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/globalModules/add[@name='$ModuleName']" -Name "." -ErrorAction SilentlyContinue
            return ($null -ne $result)
        }
        elseif (Test-Path -LiteralPath $appCmd) {
            $output = & $appCmd list config -section:system.webServer/globalModules 2>$null
            return ($output -match [regex]::Escape($ModuleName))
        }
        return $false
    }
    catch { return $false }
}

function Install-Global-IIS-Modules {
    param([Parameter(Mandatory = $true)][string]$ModuleDir)

    foreach ($module in $modules) {
        $dllPath = Join-Path $ModuleDir $module.dllName
        if (-not (Test-Path -LiteralPath $dllPath) -and -not $script:DryRun) {
            throw "Cannot register IIS module because DLL is missing: $dllPath"
        }

        $registered = Get-IISModuleRegistered -ModuleName $module.moduleName
        if ($registered -and -not $script:Force) {
            Write-Host -ForegroundColor Cyan "IIS global module '$($module.moduleName)' already registered. Skipping."
            continue
        }

        if ($script:DryRun) {
            Write-DryRun "Would register IIS global module '$($module.moduleName)' with image '$dllPath' and preCondition '$($module.preCondition)'. Force=$script:Force"
            continue
        }

        if (Test-Path -LiteralPath $appCmd) {
            if ($registered -and $script:Force) {
                & $appCmd delete module /module.name:"$($module.moduleName)" /commit:apphost | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "appcmd failed to delete module '$($module.moduleName)' (exit code $LASTEXITCODE)." }
            }
            & $appCmd install module /name:"$($module.moduleName)" /image:"$dllPath" /preCondition:"$($module.preCondition)" /commit:apphost | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "appcmd failed to install module '$($module.moduleName)' (exit code $LASTEXITCODE)." }
            Write-Host -ForegroundColor Cyan "Registered IIS global module '$($module.moduleName)'."
        }
        else {
            throw "appcmd.exe not found. Cannot register IIS modules."
        }
    }
}

function Unregister-Module {
    foreach ($module in $modules) {
        try {
            if ($script:DryRun) { Write-DryRun "Would unregister IIS global module '$($module.moduleName)'."; continue }
            if (Test-Path -LiteralPath $appCmd) {
                & $appCmd delete module /module.name:"$($module.moduleName)" /commit:apphost 2>$null | Out-Null
                Write-Host -ForegroundColor Cyan "Unregistered IIS global module '$($module.moduleName)'."
            }
        }
        catch { Write-Host -ForegroundColor Yellow "Warning: Failed unregistering module '$($module.moduleName)'. $($_.Exception.Message)" }
    }
}

function Configure-Module-Server-Level {
    foreach ($module in $modules) {
        try {
            if ($script:DryRun) { Write-DryRun "Would ensure server-level module reference exists for '$($module.moduleName)'."; continue }
            if (Test-Path -LiteralPath $appCmd) {
                $output = & $appCmd list config -section:system.webServer/modules 2>$null
                $alreadyPresent = ($output -match [regex]::Escape($module.moduleName))

                if ($alreadyPresent -and -not $script:Force) { continue }

                if ($alreadyPresent -and $script:Force) {
                    & $appCmd set config /section:system.webServer/modules "/-[name='$($module.moduleName)']" /commit:apphost | Out-Null
                    if ($LASTEXITCODE -ne 0) { throw "appcmd failed to remove server-level module '$($module.moduleName)' before re-add (exit code $LASTEXITCODE)." }
                }

                & $appCmd set config /section:system.webServer/modules "/+[`"name='$($module.moduleName)'`"]" /commit:apphost | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "appcmd failed to add server-level module '$($module.moduleName)' (exit code $LASTEXITCODE)." }
                Write-Host -ForegroundColor Cyan "Configured server-level module '$($module.moduleName)'."
            }
        }
        catch { Write-Host -ForegroundColor Yellow "Warning: Failed configuring server-level module '$($module.moduleName)'. $($_.Exception.Message)" }
    }
}

function Clear-Module-Server-Level {
    foreach ($module in $modules) {
        try {
            if ($script:DryRun) { Write-DryRun "Would remove server-level module reference '$($module.moduleName)'."; continue }
            if (Test-Path -LiteralPath $appCmd) {
                & $appCmd set config /section:system.webServer/modules "/-[name='$($module.moduleName)']" /commit:apphost 2>$null | Out-Null
                Write-Host -ForegroundColor Cyan "Removed server-level module '$($module.moduleName)'."
            }
        }
        catch { Write-Host -ForegroundColor Yellow "Warning: Failed removing server-level module '$($module.moduleName)'. $($_.Exception.Message)" }
    }
}

function Add-Global-Noname-Module {
    param([string]$ModuleDir)
    Install-Global-IIS-Modules -ModuleDir $ModuleDir
    Configure-Module-Server-Level
}

function Remove-Global-Noname-Module {
    Clear-Module-Server-Level
    Unregister-Module
}

function Verify-InstallState {
    param([string]$ModuleDir)

    $state = [ordered]@{
        ComputerName         = $env:COMPUTERNAME
        TimestampUtc         = (Get-Date).ToUniversalTime().ToString("o")
        ModuleDir            = $ModuleDir
        ModuleDirExists      = $false
        Dlls                 = [System.Collections.Generic.List[object]]::new()
        GlobalModulesPresent = [System.Collections.Generic.List[object]]::new()
        ServerModulesPresent = [System.Collections.Generic.List[object]]::new()
        EnvVars              = @{}
        PendingActivation    = $null
        LastPreflight        = $null
    }

    if (-not [string]::IsNullOrWhiteSpace($ModuleDir)) {
        $state.ModuleDirExists = (Test-Path -LiteralPath $ModuleDir)
        foreach ($module in $modules) {
            $dllPath = Join-Path $ModuleDir $module.dllName
            $state.Dlls.Add([PSCustomObject]@{
                Name   = $module.dllName
                Exists = (Test-Path -LiteralPath $dllPath)
                Path   = $dllPath
            }) | Out-Null
        }
    }

    foreach ($module in $modules) {
        $state.GlobalModulesPresent.Add([PSCustomObject]@{
            Name    = $module.moduleName
            Present = (Get-IISModuleRegistered -ModuleName $module.moduleName)
        }) | Out-Null
        $state.ServerModulesPresent.Add([PSCustomObject]@{
            Name    = $module.moduleName
            Present = $false
        }) | Out-Null
    }

    foreach ($key in (@($sourceParams.Keys) + @($dir, "NONAME_LOG_FILE_LOCATION", "AZURE_INSTANCE_METADATA") | Select-Object -Unique)) {
        $state.EnvVars[$key] = Get-Environment-Variable -envName $key
    }

    $state.PendingActivation = Get-PendingActivationStatus
    $state.LastPreflight     = Read-PreflightState

    [PSCustomObject]$state
}

function Should-ForwardEvent {
    param([ValidateSet("Install","Uninstall","Activate")] [string]$EventType)
    if ([string]::IsNullOrWhiteSpace($LogForwardUrl)) { return $false }
    switch ($EventType) {
        "Install"   { return [bool]$LogForwardOnInstall }
        "Uninstall" { return [bool]$LogForwardOnUninstall }
        "Activate"  { return [bool]$LogForwardOnActivate }
        default     { return $false }
    }
}

function Send-LogForwardEvent {
    param(
        [ValidateSet("Install","Uninstall","Activate")] [string]$EventType,
        [ValidateSet("Started","Completed","Failed")] [string]$Status,
        [string]$Message
    )
    if (-not (Should-ForwardEvent -EventType $EventType)) { return }

    $payload = @{
        eventType = $EventType
        status    = $Status
        message   = $Message
        computer  = $env:COMPUTERNAME
        timestamp = (Get-Date).ToUniversalTime().ToString("o")
        action    = $Action
    } | ConvertTo-Json -Depth 5

    if ($script:DryRun) { Write-DryRun "Would POST log-forward event to '$LogForwardUrl': $payload"; return }

    try {
        Invoke-WebRequest -Uri $LogForwardUrl -Method Post -ContentType "application/json" -Body $payload -TimeoutSec $LogForwardTimeoutSec -UseBasicParsing -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Host -ForegroundColor Yellow "Warning: Failed forwarding event '$EventType/$Status'. $($_.Exception.Message)"
    }
}

function Invoke-IISReset {
    if ($script:DryRun) { Write-DryRun "Would perform 'iisreset.exe /restart'."; return }
    Write-Host -ForegroundColor Cyan "Performing IIS restart."
    $proc = Start-Process "iisreset.exe" -ArgumentList "/restart" -NoNewWindow -Wait -PassThru
    if ($proc.ExitCode -ne 0) { throw "iisreset.exe failed with exit code $($proc.ExitCode)." }
}

function Invoke-NonameActivation {
    try {
        $ErrorActionPreference = "Stop"
        if ($script:Force) { Write-Host -ForegroundColor Yellow "[FORCE MODE ENABLED]" }

        if (Should-ForwardEvent -EventType "Activate") { Send-LogForwardEvent -EventType "Activate" -Status "Started" -Message "Activation started." }
        Send-DynatraceEvent -EventType "CUSTOM_DEPLOYMENT" -Title "Noname Activation Started" `
            -Description "Activation initiated on $env:COMPUTERNAME." -Properties @{ "noname.phase" = "activate" }

        Write-Host -ForegroundColor Cyan "Writing source parameters to machine environment before activation."
        Set-Source-Parameters
        Set-Azure-Metadata
        Write-Host -ForegroundColor Cyan "Source parameters committed. Performing IIS restart."
        Invoke-IISReset
        Clear-PendingState -Type "All"

        if (Should-ForwardEvent -EventType "Activate") { Send-LogForwardEvent -EventType "Activate" -Status "Completed" -Message "Activation completed successfully." }
        Send-DynatraceEvent -EventType "CUSTOM_DEPLOYMENT" -Title "Noname Activation Completed" `
            -Description "Activation completed successfully on $env:COMPUTERNAME." -Properties @{ "noname.phase" = "activate"; "noname.result" = "success" }

        Write-Host -ForegroundColor Green "Activation completed successfully."
    }
    catch {
        if (Should-ForwardEvent -EventType "Activate") { Send-LogForwardEvent -EventType "Activate" -Status "Failed" -Message $_.Exception.Message }
        Send-DynatraceEvent -EventType "ERROR_EVENT" -Title "Noname Activation Failed" `
            -Description $_.Exception.Message -Properties @{ "noname.phase" = "activate"; "noname.result" = "failure" }
        Write-Error "[ERROR] Activation failed.`n $($_.Exception.Message)"
        throw
    }
}

function Get-Agent-Status {
    param([string]$InstallDir)

    $moduleDir = if (-not [string]::IsNullOrWhiteSpace($InstallDir)) {
        Get-Install-Dir-Path -InstallDir $InstallDir
    }
    else {
        $existing = Get-Environment-Variable -envName $dir
        if ([string]::IsNullOrWhiteSpace($existing)) { (Get-Default-Paths).InstallDir } else { $existing }
    }

    [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        Action       = "status"
        TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
        InstallDir   = $moduleDir
        State        = Verify-InstallState -ModuleDir $moduleDir
    }
}

function Install-Agent {
    param([string]$InstallDir)

    $moduleDir   = $null
    $originalEap = $ErrorActionPreference
    $logCreated  = $false
    $iisTouched  = $false

    try {
        $ErrorActionPreference = "Stop"
        Validate-InstallParameters

        # -------------------------------------------------------------------
        # Preflight gate
        # Rule 1: Any FAIL              -> always block (-Force has no effect)
        # Rule 2: Engine WARN           -> block unless -Force
        # Rule 3: Other WARNs           -> block only when -FailOnWarnings set
        #
        # Preflight state is persisted and Dynatrace notified BEFORE any
        # blocking decision so the outcome is always recorded.
        # -------------------------------------------------------------------
        Write-Host -ForegroundColor Cyan "Running preflight checks before install..."
        $preflight = Test-Preflight
        $preflight.Results | Format-Table -AutoSize

        Write-PreflightState -PreflightResult $preflight

        Send-DynatraceEvent -EventType "CUSTOM_INFO" -Title "Noname Preflight Completed" `
            -Description ("Preflight: $($preflight.Summary.Pass) PASS / $($preflight.Summary.Warn) WARN / $($preflight.Summary.Fail) FAIL") `
            -Properties @{
                "noname.phase"               = "preflight"
                "noname.preflight.pass"      = ([string]$preflight.Summary.Pass)
                "noname.preflight.warn"      = ([string]$preflight.Summary.Warn)
                "noname.preflight.fail"      = ([string]$preflight.Summary.Fail)
                "noname.preflight.exit_code" = ([string]$preflight.Summary.ExitCode)
                "noname.preflight.engine"    = ([string]$preflight.Summary.EngineCheckStatus)
            }

        # Rule 1
        if ($preflight.Summary.Fail -gt 0) {
            throw ("Preflight failed with $($preflight.Summary.Fail) failure(s). Resolve the issues above before installing.")
        }

        # Rule 2
        if ($preflight.Summary.EngineCheckStatus -eq "WARN") {
            if (-not $script:Force) {
                throw ("Preflight: engine connectivity check returned WARN. " +
                       "The Noname engine at '$NonameEngineUrl' could not be reached. " +
                       "Resolve connectivity or re-run with -Force to override this check.")
            }
            Write-Host -ForegroundColor Yellow "Warning: Engine connectivity WARN overridden by -Force. Proceeding."
        }

        # Rule 3
        if ($preflight.Summary.ExitCode -ne 0) {
            throw ("Preflight did not pass ($($preflight.Summary.Warn) warning(s) with -FailOnWarnings enabled). Resolve the issues above before installing.")
        }

        Write-Host -ForegroundColor Green "Preflight passed ($($preflight.Summary.Pass) checks). Proceeding with install."

        if ($script:DryRun) { Write-DryRun "Starting install simulation." }
        if ($script:Force)  { Write-Host -ForegroundColor Yellow "[FORCE MODE ENABLED]" }

        if (Should-ForwardEvent -EventType "Install") { Send-LogForwardEvent -EventType "Install" -Status "Started" -Message "Install started." }
        Send-DynatraceEvent -EventType "CUSTOM_DEPLOYMENT" -Title "Noname Install Started" `
            -Description "Install initiated on $env:COMPUTERNAME." -Properties @{ "noname.phase" = "install" }

        $moduleDir = Get-Install-Dir-Path -InstallDir $InstallDir
        Copy-Noname-Module-To-Dir -moduleDir $moduleDir
        Install-Runtime-Libraries

        Create-Noname-Log
        $logCreated = $true

        if (-not (Test-IISAvailable)) {
            Write-Host -ForegroundColor Yellow "Warning: IIS not detected. Skipping module registration."
        }
        else {
            Install-Global-IIS-Modules -ModuleDir $moduleDir
            Configure-Module-Server-Level
            $iisTouched = $true
        }

        $verification = Verify-InstallState -ModuleDir $moduleDir
        $verification | Format-List | Out-String | Write-Host

        Clear-PendingState -Type "Uninstall"
        Clear-PendingState -Type "Install"
        Write-PendingState -Type "Install" -Reason "Module installed and registered. Run activate to write source parameters and recycle workers."

        if (Should-ForwardEvent -EventType "Install") { Send-LogForwardEvent -EventType "Install" -Status "Completed" -Message "Install completed successfully." }
        Send-DynatraceEvent -EventType "CUSTOM_DEPLOYMENT" -Title "Noname Install Completed" `
            -Description "Install completed successfully on $env:COMPUTERNAME." -Properties @{ "noname.phase" = "install"; "noname.result" = "success" }

        Write-Host -ForegroundColor Green "Install Agent completed successfully."
        Write-Host -ForegroundColor Yellow "Source parameters not yet written. Run activate to commit env vars and recycle app pools."
    }
    catch {
        if ($script:DryRun) {
            Write-Host -ForegroundColor Yellow "Warning: Dry-run failed. No rollback required — no changes were made."
        }
        else {
            Write-Host -ForegroundColor Yellow "Warning: Install failed. Attempting rollback."
            try { if ($iisTouched -and (Test-IISAvailable)) { Clear-Module-Server-Level } } catch {}
            try { if ($iisTouched -and (Test-IISAvailable)) { Unregister-Module } }         catch {}
            try { if ($moduleDir) { Remove-Noname-Module-From-Dir -moduleDir $moduleDir } }  catch {}
            try { if ($logCreated) { Clear-Noname-Log-State } }                              catch {}
            try { Clear-PendingState -Type "All" }                                           catch {}
        }

        if (Should-ForwardEvent -EventType "Install") { Send-LogForwardEvent -EventType "Install" -Status "Failed" -Message $_.Exception.Message }
        Send-DynatraceEvent -EventType "ERROR_EVENT" -Title "Noname Install Failed" `
            -Description $_.Exception.Message -Properties @{ "noname.phase" = "install"; "noname.result" = "failure" }

        Write-Error "[ERROR] An error occurred.`n $($_.Exception.Message)"
        throw
    }
    finally {
        $ErrorActionPreference = $originalEap
    }
}

function Repair-Agent {
    param([string]$InstallDir)

    $originalEap = $ErrorActionPreference

    try {
        $ErrorActionPreference = "Stop"
        Validate-InstallParameters

        if ($script:DryRun) { Write-DryRun "Starting repair simulation." }
        if ($script:Force)  { Write-Host -ForegroundColor Yellow "[FORCE MODE ENABLED]" }

        Send-DynatraceEvent -EventType "CUSTOM_DEPLOYMENT" -Title "Noname Repair Started" `
            -Description "Repair initiated on $env:COMPUTERNAME." -Properties @{ "noname.phase" = "repair" }

        $moduleDir = Get-Install-Dir-Path -InstallDir $InstallDir
        New-NonameDirectory -Path $moduleDir

        $needsCopy = $script:Force
        if (-not $needsCopy) {
            foreach ($module in $modules) {
                $dllPath = Join-Path $moduleDir $module.dllName
                if (-not (Test-Path -LiteralPath $dllPath)) { $needsCopy = $true }
            }
        }

        if ($needsCopy) { Copy-Noname-Module-To-Dir -moduleDir $moduleDir }
        else            { Set-Environment-Variable -envName $dir -envValue $moduleDir }

        Create-Noname-Log
        Install-Runtime-Libraries

        if (Test-IISAvailable) {
            Install-Global-IIS-Modules -ModuleDir $moduleDir
            Configure-Module-Server-Level
        }

        Clear-PendingState -Type "All"
        Write-PendingState -Type "Install" -Reason "Repair completed. Run activate to commit source parameters and recycle workers."

        $state = Verify-InstallState -ModuleDir $moduleDir
        $state | Format-List | Out-String | Write-Host

        Send-DynatraceEvent -EventType "CUSTOM_DEPLOYMENT" -Title "Noname Repair Completed" `
            -Description "Repair completed successfully on $env:COMPUTERNAME." -Properties @{ "noname.phase" = "repair"; "noname.result" = "success" }

        Write-Host -ForegroundColor Green "Repair-Agent completed successfully."
        Write-Host -ForegroundColor Yellow "Source parameters not yet written. Run activate to commit env vars and recycle app pools."
    }
    catch {
        Send-DynatraceEvent -EventType "ERROR_EVENT" -Title "Noname Repair Failed" `
            -Description $_.Exception.Message -Properties @{ "noname.phase" = "repair"; "noname.result" = "failure" }
        Write-Error "[ERROR] Repair failed.`n $($_.Exception.Message)"
        throw
    }
    finally {
        $ErrorActionPreference = $originalEap
    }
}

function Uninstall-Agent {
    param([string]$InstallDir)

    $originalEap = $ErrorActionPreference

    try {
        $ErrorActionPreference = "Stop"

        if ($script:DryRun) { Write-DryRun "Starting uninstall simulation." }
        if ($script:Force)  { Write-Host -ForegroundColor Yellow "[FORCE MODE ENABLED]" }

        if (Should-ForwardEvent -EventType "Uninstall") { Send-LogForwardEvent -EventType "Uninstall" -Status "Started" -Message "Uninstall started." }
        Send-DynatraceEvent -EventType "CUSTOM_DEPLOYMENT" -Title "Noname Uninstall Started" `
            -Description "Uninstall initiated on $env:COMPUTERNAME." -Properties @{ "noname.phase" = "uninstall" }

        $moduleDir = if (-not [string]::IsNullOrWhiteSpace($InstallDir)) {
            Get-Install-Dir-Path -InstallDir $InstallDir
        }
        else {
            $existing = Get-Environment-Variable -envName $dir
            if ([string]::IsNullOrWhiteSpace($existing)) { (Get-Default-Paths).InstallDir } else { $existing }
        }

        if (Test-IISAvailable) {
            Clear-Module-Server-Level
            Unregister-Module
        }

        Write-Host -ForegroundColor Cyan "Restarting IIS to unload module before clearing environment variables."
        Invoke-IISReset

        Clear-Noname-Source-Parameters
        Clear-Noname-Log-State
        Remove-Noname-Module-From-Dir -moduleDir $moduleDir

        Clear-PendingState -Type "Install"
        Write-PendingState -Type "Uninstall" -Reason "Module uninstalled and workers recycled. Environment variables cleared."

        if (Should-ForwardEvent -EventType "Uninstall") { Send-LogForwardEvent -EventType "Uninstall" -Status "Completed" -Message "Uninstall completed successfully." }
        Send-DynatraceEvent -EventType "CUSTOM_DEPLOYMENT" -Title "Noname Uninstall Completed" `
            -Description "Uninstall completed successfully on $env:COMPUTERNAME." -Properties @{ "noname.phase" = "uninstall"; "noname.result" = "success" }

        Write-Host -ForegroundColor Green "Uninstall Agent completed successfully."
    }
    catch {
        if (Should-ForwardEvent -EventType "Uninstall") { Send-LogForwardEvent -EventType "Uninstall" -Status "Failed" -Message $_.Exception.Message }
        Send-DynatraceEvent -EventType "ERROR_EVENT" -Title "Noname Uninstall Failed" `
            -Description $_.Exception.Message -Properties @{ "noname.phase" = "uninstall"; "noname.result" = "failure" }
        Write-Error "[ERROR] Uninstall failed.`n $($_.Exception.Message)"
        throw
    }
    finally {
        $ErrorActionPreference = $originalEap
    }
}

Import-RequiredModules

if ($ExecutionContext.SessionState.Module) {
    Export-ModuleMember -Function Install-Agent               -ErrorAction SilentlyContinue
    Export-ModuleMember -Function Uninstall-Agent             -ErrorAction SilentlyContinue
    Export-ModuleMember -Function Invoke-NonameActivation     -ErrorAction SilentlyContinue
    Export-ModuleMember -Function Get-PendingActivationStatus -ErrorAction SilentlyContinue
    Export-ModuleMember -Function Add-Global-Noname-Module    -ErrorAction SilentlyContinue
    Export-ModuleMember -Function Remove-Global-Noname-Module -ErrorAction SilentlyContinue
    Export-ModuleMember -Function Repair-Agent                -ErrorAction SilentlyContinue
    Export-ModuleMember -Function Get-Agent-Status            -ErrorAction SilentlyContinue
    Export-ModuleMember -Function Read-PreflightState         -ErrorAction SilentlyContinue
    Export-ModuleMember -Function Write-PreflightState        -ErrorAction SilentlyContinue
    Export-ModuleMember -Function Send-DynatraceEvent         -ErrorAction SilentlyContinue
}

switch ($Action) {
    "install"   { Install-Agent -InstallDir $InstallDir }
    "uninstall" { Uninstall-Agent -InstallDir $InstallDir }
    "activate"  { Invoke-NonameActivation }
    "status"    { Get-Agent-Status -InstallDir $InstallDir | Format-List }

    "preflight" {
        $preflight = Test-Preflight
        $preflight.Summary | Format-List
        ""
        $preflight.Results | Format-Table -AutoSize

        Write-PreflightState -PreflightResult $preflight

        Send-DynatraceEvent -EventType "CUSTOM_INFO" -Title "Noname Preflight Completed (standalone)" `
            -Description ("Preflight: $($preflight.Summary.Pass) PASS / $($preflight.Summary.Warn) WARN / $($preflight.Summary.Fail) FAIL") `
            -Properties @{
                "noname.phase"               = "preflight"
                "noname.preflight.pass"      = ([string]$preflight.Summary.Pass)
                "noname.preflight.warn"      = ([string]$preflight.Summary.Warn)
                "noname.preflight.fail"      = ([string]$preflight.Summary.Fail)
                "noname.preflight.exit_code" = ([string]$preflight.Summary.ExitCode)
                "noname.preflight.engine"    = ([string]$preflight.Summary.EngineCheckStatus)
            }

        if ($preflight.Summary.ExitCode -ne 0) { exit 1 } else { exit 0 }
    }

    "repair" { Repair-Agent -InstallDir $InstallDir }
    "none"   { }
}
