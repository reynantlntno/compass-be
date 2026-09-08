[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$python = Get-Command python -ErrorAction SilentlyContinue
if ($null -ne $python) {
    & $python.Source (Join-Path $repoRoot "scripts\core\repo_checks.py") crawler
    exit $LASTEXITCODE
}

$py = Get-Command py -ErrorAction SilentlyContinue
if ($null -ne $py) {
    & $py.Source -3 (Join-Path $repoRoot "scripts\core\repo_checks.py") crawler
    exit $LASTEXITCODE
}

Write-Error "Python 3 is required. Install Python and make python or py available on PATH."
exit 1
