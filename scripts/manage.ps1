[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ManagementArgs
)

$scriptPath = Join-Path $PSScriptRoot "compass_runtime.py"
$python = Get-Command python -ErrorAction SilentlyContinue
if ($null -ne $python) {
    & $python.Source $scriptPath manage @ManagementArgs
    exit $LASTEXITCODE
}

$py = Get-Command py -ErrorAction SilentlyContinue
if ($null -ne $py) {
    & $py.Source -3 $scriptPath manage @ManagementArgs
    exit $LASTEXITCODE
}

Write-Error "Python 3 is required to run COMPASS container-aware commands."
exit 1
