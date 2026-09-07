[CmdletBinding()]
param(
    [ValidateSet("bootstrap", "up", "down", "status", "health-only", "activate", "seed", "readiness")]
    [string]$Action = "status",
    [switch]$ConfigureDaily,
    [string]$DailyDomain = "demo-compass.daily.co",
    [string]$DailyWebhookId = "",
    [string]$DailyWebhookUrl = "",
    [string]$SystemIdentity = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$envPath = Join-Path $repoRoot "deploy\local-staging.env"
$envExamplePath = Join-Path $repoRoot "deploy\local-staging.env.example"
$composeFiles = @("-f", (Join-Path $repoRoot "compose.local-staging.yaml"))
$projectArgs = @("compose", "--project-name", "compass-local-staging", "--env-file", $envPath) + $composeFiles

function New-RandomToken([int]$Bytes = 32) {
    $buffer = New-Object byte[] $Bytes
    [Security.Cryptography.RandomNumberGenerator]::Fill($buffer)
    return [Convert]::ToHexString($buffer).ToLowerInvariant()
}

function New-FernetKey {
    $buffer = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Fill($buffer)
    return [Convert]::ToBase64String($buffer).Replace("+", "-").Replace("/", "_")
}

function New-Base64Secret([int]$Bytes = 32) {
    $buffer = New-Object byte[] $Bytes
    [Security.Cryptography.RandomNumberGenerator]::Fill($buffer)
    return [Convert]::ToBase64String($buffer)
}

function Read-HiddenValue([string]$Prompt) {
    $secure = Read-Host $Prompt -AsSecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Assert-SafeEnvValue([string]$Name, [string]$Value) {
    if ($Value.Contains("`r") -or $Value.Contains("`n")) {
        throw "$Name contains an invalid line break."
    }
}

function Get-SecretNames {
    @(& podman secret ls --format "{{.Name}}")
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to inspect the local Podman secret store."
    }
}

function Add-PodmanSecret([string]$Name, [string]$Value, [string[]]$Existing) {
    if ($Existing -contains $Name) {
        return
    }
    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "Refusing to create an empty Podman secret: $Name"
    }
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = "podman"
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @("secret", "create", $Name, "-")) {
        [void]$startInfo.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    [void]$process.Start()
    $process.StandardInput.Write($Value)
    $process.StandardInput.Close()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw "Podman secret creation failed for $Name. $stderr"
    }
}

function Set-EnvEntry([string]$Name, [string]$Value) {
    if ($Name -notmatch "^[A-Z][A-Z0-9_]*$") {
        throw "Invalid environment setting name."
    }
    Assert-SafeEnvValue $Name $Value
    $content = Get-Content -LiteralPath $envPath
    $replacement = "$Name=$Value"
    $matched = $false
    $updated = foreach ($line in $content) {
        if ($line -match "^$([Regex]::Escape($Name))=") {
            $matched = $true
            $replacement
        }
        else {
            $line
        }
    }
    if (-not $matched) {
        $updated += $replacement
    }
    Set-Content -LiteralPath $envPath -Value $updated -Encoding utf8NoBOM
}

function Invoke-Compose([string[]]$Arguments) {
    & podman @projectArgs @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Local staging Compose operation failed."
    }
}

if ($Action -eq "bootstrap") {
    if (Test-Path -LiteralPath $envPath) {
        throw "deploy/local-staging.env already exists; refusing to overwrite it."
    }
    $existing = Get-SecretNames
    $localSecretNames = @($existing | Where-Object { $_ -like "compass-local-staging-*" })
    if ($localSecretNames.Count -gt 0) {
        throw "Local staging secrets already exist; refusing to rotate credentials implicitly. Restore deploy/local-staging.env or remove the isolated stack explicitly."
    }

    Copy-Item -LiteralPath $envExamplePath -Destination $envPath
    $stamp = Get-Date -Format "yyyyMMddHHmmss"
    Set-EnvEntry "COMPASS_RELEASE_VERSION" "local-staging-$stamp"
    Set-EnvEntry "COMPASS_BUILD_ID" "local-staging-$stamp"

    $dailyApiKey = "disabled-local-staging-$((New-RandomToken 16))"
    $dailyWebhookSecret = New-Base64Secret
    if ($ConfigureDaily) {
        $dailyApiKey = Read-HiddenValue "Daily API key"
        if ([string]::IsNullOrWhiteSpace($dailyApiKey)) {
            throw "Daily API key cannot be empty."
        }
        if ($DailyDomain -notmatch "^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$" -or $DailyDomain.Contains("..")) {
            throw "DailyDomain must be a canonical host without a scheme, path, or port."
        }
        if (-not [string]::IsNullOrWhiteSpace($DailyWebhookId) -and $DailyWebhookId -notmatch "^[A-Za-z0-9-]{1,128}$") {
            throw "DailyWebhookId contains invalid characters."
        }
        if (-not [string]::IsNullOrWhiteSpace($DailyWebhookUrl)) {
            $parsedWebhookUrl = $null
            if (-not [Uri]::TryCreate($DailyWebhookUrl, [UriKind]::Absolute, [ref]$parsedWebhookUrl) -or $parsedWebhookUrl.Scheme -ne "https") {
                throw "DailyWebhookUrl must be an absolute HTTPS URL."
            }
        }
        $providedWebhookSecret = Read-HiddenValue "Daily webhook HMAC secret (leave blank to generate a base64 rehearsal secret)"
        if (-not [string]::IsNullOrWhiteSpace($providedWebhookSecret)) {
            try {
                $decodedWebhookSecret = [Convert]::FromBase64String($providedWebhookSecret)
            }
            catch {
                throw "Daily webhook HMAC secret must be valid base64."
            }
            if ($decodedWebhookSecret.Length -lt 32) {
                throw "Daily webhook HMAC secret must decode to at least 32 bytes."
            }
            $dailyWebhookSecret = $providedWebhookSecret
        }
    }

    $postgresPassword = New-RandomToken 24
    $protectedAccessKey = "compasslocal$((New-RandomToken 8))"
    $protectedSecretKey = New-RandomToken 24
    $backupAccessKey = "compassbackup$((New-RandomToken 8))"
    $backupSecretKey = New-RandomToken 24
    $secrets = [ordered]@{
        "compass-local-staging-postgres-password" = $postgresPassword
        "compass-local-staging-secret-key" = New-RandomToken 48
        "compass-local-staging-audit-hash-secret" = New-RandomToken 48
        "compass-local-staging-account-security-hash-secret" = New-RandomToken 48
        "compass-local-staging-account-activation-token-secret" = New-RandomToken 48
        "compass-local-staging-database-url" = "postgresql://compass:$postgresPassword@db:5432/compass_local_staging"
        "compass-local-staging-protected-storage-s3-access-key" = $protectedAccessKey
        "compass-local-staging-protected-storage-s3-secret-key" = $protectedSecretKey
        "compass-local-staging-backup-storage-s3-access-key" = $backupAccessKey
        "compass-local-staging-backup-storage-s3-secret-key" = $backupSecretKey
        "compass-local-staging-field-encryption-key" = New-FernetKey
        "compass-local-staging-account-security-turnstile-secret" = "1x0000000000000000000000000000000AA"
        "compass-local-staging-email-host-password" = New-RandomToken 24
        "compass-local-staging-ecounseling-daily-api-key" = $dailyApiKey
        "compass-local-staging-ecounseling-daily-webhook-secret" = $dailyWebhookSecret
        "compass-local-staging-ecounseling-room-salt" = New-RandomToken 48
    }
    foreach ($entry in $secrets.GetEnumerator()) {
        Add-PodmanSecret $entry.Key $entry.Value $existing
    }

    if ($ConfigureDaily) {
        Set-EnvEntry "COMPASS_LOCAL_STAGING_DAILY_ENABLED" "True"
        Set-EnvEntry "ECOUNSELING_DAILY_DOMAIN" $DailyDomain
        Set-EnvEntry "ECOUNSELING_DAILY_WEBHOOK_ID" $DailyWebhookId
        Set-EnvEntry "ECOUNSELING_DAILY_WEBHOOK_URL" $DailyWebhookUrl
        if (
            -not [string]::IsNullOrWhiteSpace($DailyWebhookId) -and
            -not [string]::IsNullOrWhiteSpace($DailyWebhookUrl)
        ) {
            Set-EnvEntry "ECOUNSELING_PROVIDER" "DAILY"
        }
        else {
            Set-EnvEntry "ECOUNSELING_PROVIDER" "disabled"
            Write-Warning "Daily credentials were imported, but the provider remains disabled until a matching public HTTPS webhook URL and webhook id are configured."
        }
    }
    Write-Host "Local staging configuration created. Secret values were written only to the local Podman secret store."
    exit 0
}

if (-not (Test-Path -LiteralPath $envPath)) {
    throw "Run .\scripts\local-staging.ps1 bootstrap first."
}

switch ($Action) {
    "up" { Invoke-Compose @("up", "-d", "--build") }
    "down" { Invoke-Compose @("down") }
    "status" { Invoke-Compose @("ps") }
    "health-only" {
        Set-EnvEntry "COMPASS_ACCESS_MODE" "health_only"
        Invoke-Compose @("up", "-d")
    }
    "activate" {
        Set-EnvEntry "COMPASS_ACCESS_MODE" "active"
        Invoke-Compose @("up", "-d")
    }
    "seed" {
        Invoke-Compose @(
            "exec",
            "web",
            "/usr/local/bin/compass-secret-env",
            "python",
            "manage.py",
            "seed_operating_demo"
        )
    }
    "readiness" {
        $arguments = @(
            "exec",
            "web",
            "/usr/local/bin/compass-secret-env",
            "python",
            "manage.py",
            "verify_health",
            "--strict",
            "--probe-external",
            "--format",
            "json"
        )
        if (-not [string]::IsNullOrWhiteSpace($SystemIdentity)) {
            $arguments += @("--system-identity", $SystemIdentity)
        }
        Invoke-Compose $arguments
    }
}
