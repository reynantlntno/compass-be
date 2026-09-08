[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $RemainingArguments
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$python = Get-Command python -ErrorAction SilentlyContinue
if ($null -ne $python) {
    & $python.Source (Join-Path $repoRoot "scripts\core\release.py") build @RemainingArguments
    exit $LASTEXITCODE
}

$py = Get-Command py -ErrorAction SilentlyContinue
if ($null -ne $py) {
    & $py.Source -3 (Join-Path $repoRoot "scripts\core\release.py") build @RemainingArguments
    exit $LASTEXITCODE
}

Write-Error "Python 3 is required. Install Python and make python or py available on PATH."
exit 1
