param(
    [Parameter(Mandatory = $true)]
    [string]$SourceDir,
    [Parameter(Mandatory = $true)]
    [string]$DataDir
)

$ErrorActionPreference = 'Stop'
$env:PYTHONUTF8 = '1'
$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $projectDir '.venv\Scripts\python.exe'

if (-not (Test-Path -LiteralPath $python)) {
    py -3 -m venv (Join-Path $projectDir '.venv')
    & $python -m pip install --disable-pip-version-check -r (Join-Path $projectDir 'requirements.txt')
}

New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
$log = Join-Path $DataDir 'collection.log'
"[$(Get-Date -Format o)] started" | Out-File -LiteralPath $log -Append -Encoding utf8
& $python (Join-Path $projectDir 'collector.py') --source-dir $SourceDir --data-dir $DataDir 2>&1 |
    Out-File -LiteralPath $log -Append -Encoding utf8
$result = $LASTEXITCODE
"[$(Get-Date -Format o)] exit=$result" | Out-File -LiteralPath $log -Append -Encoding utf8
exit $result

