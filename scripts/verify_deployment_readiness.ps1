[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ReadinessArgs
)

$scriptPath = Join-Path $PSScriptRoot "compass_runtime.py"
$python = Get-Command python -ErrorAction SilentlyContinue
if ($null -ne $python) {
    & $python.Source $scriptPath readiness @ReadinessArgs
    exit $LASTEXITCODE
}

$py = Get-Command py -ErrorAction SilentlyContinue
if ($null -ne $py) {
    & $py.Source -3 $scriptPath readiness @ReadinessArgs
    exit $LASTEXITCODE
}

Write-Error "Python 3 is required to run COMPASS deployment readiness checks."
exit 1
