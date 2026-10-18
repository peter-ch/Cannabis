# Portable, per-user setup. No administrator access or execution-policy changes.
param([switch]$PrepareOnly, [switch]$CheckActivity)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$sourceRoot = Split-Path -Parent $PSScriptRoot
$toolRoot = Join-Path $env:LOCALAPPDATA 'CannabisParticipant\tools'
$previousDirectory = Get-Location
try {
    $nativeArchitecture = $env:PROCESSOR_ARCHITEW6432
    if (!$nativeArchitecture) { $nativeArchitecture = $env:PROCESSOR_ARCHITECTURE }
    $architecture = switch ($nativeArchitecture.ToUpperInvariant()) { 'AMD64' { 'x64' }; 'ARM64' { 'arm64' }; default { throw 'Windows x64 or ARM64 is required' } }
    $manifest = Get-Content -LiteralPath (Join-Path $sourceRoot 'config\windows-tools.json') -Raw | ConvertFrom-Json
    $selected = $manifest.$architecture
    New-Item -ItemType Directory -Path $toolRoot -Force | Out-Null
    $accountSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    & icacls.exe $toolRoot '/inheritance:r' '/grant:r' ('*' + $accountSid + ':(OI)(CI)(F)') '*S-1-5-18:(OI)(CI)(F)' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not protect the tools directory' }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    foreach ($name in @('node', 'age')) {
        $spec = $selected.$name
        $uri = [Uri]$spec.url
        if ($uri.Scheme -ne 'https' -or $uri.Host -notin @('nodejs.org', 'github.com') -or $spec.sha256 -notmatch '^[0-9a-f]{64}$') { throw 'Invalid tool pin' }
        $archive = Join-Path $toolRoot ($spec.sha256 + '.zip')
        if (!(Test-Path -LiteralPath $archive)) {
            Write-Host ('Downloading verified ' + $name + ' archive...')
            $download = $archive + '.download-' + [Guid]::NewGuid().ToString('N')
            Invoke-WebRequest -UseBasicParsing -Uri $uri -OutFile $download -TimeoutSec 180
            if ((Get-Item -LiteralPath $download).Length -gt 100MB -or (Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash.ToLowerInvariant() -ne $spec.sha256) { throw 'Tool download checksum mismatch; refusing execution' }
            Move-Item -LiteralPath $download -Destination $archive
        }
        if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $spec.sha256) { throw 'Cached tool checksum mismatch; refusing execution' }
        $destination = Join-Path $toolRoot ($name + '-' + $architecture + '-' + $spec.sha256.Substring(0, 12))
        # Re-extract checked archives so stale or modified installed files are replaced.
        Expand-Archive -LiteralPath $archive -DestinationPath $destination -Force
        $toolDirectory = Join-Path $destination $spec.folder
        if ($name -eq 'node') { $nodeDirectory = $toolDirectory } else { $ageDirectory = $toolDirectory }
    }
    $node = Join-Path $nodeDirectory 'node.exe'
    $age = Join-Path $ageDirectory 'age.exe'
    $nodeVersion = & $node --version
    $ageVersion = & $age --version
    if ($nodeVersion.Trim() -ne ('v' + $manifest.nodeVersion) -or $ageVersion.Trim().TrimStart('v') -ne $manifest.ageVersion) { throw 'Installed tool version mismatch' }
    $env:PATH = $nodeDirectory + ';' + $env:PATH
    $env:CANNABIS_AGE = $age
    Set-Location -LiteralPath $sourceRoot
    Write-Host 'Installing locked application dependencies without package lifecycle scripts...'
    & $node (Join-Path $nodeDirectory 'node_modules\npm\bin\npm-cli.js') ci --ignore-scripts --no-fund --no-audit
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
    if ($PrepareOnly) { Write-Host 'Cannabis prerequisites are ready.'; exit 0 }
    if ($CheckActivity) { & $node (Join-Path $PSScriptRoot 'exercise-activity.mjs') }
    else { & $node (Join-Path $PSScriptRoot 'participant.mjs') }
    if ($LASTEXITCODE -ne 0) { throw 'Participant guide did not complete' }
} catch {
    Write-Host 'Cannabis setup stopped before opening the guide. Check connectivity, storage, trusted source files and local execution policy.' -ForegroundColor Yellow
    Write-Host 'No administrator rights, security-policy changes or payment details are required.'
    exit 1
} finally { Set-Location -LiteralPath $previousDirectory.Path }
