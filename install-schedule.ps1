param(
    [Parameter(Mandatory = $true)]
    [string]$SourceDir,
    [Parameter(Mandatory = $true)]
    [string]$DataDir,
    [int]$IntervalMinutes = 15
)

$ErrorActionPreference = 'Stop'
$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$collect = Join-Path $projectDir 'collect.ps1'
$arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$collect`" -SourceDir `"$SourceDir`" -DataDir `"$DataDir`""
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
    -RepetitionDuration (New-TimeSpan -Days 3650)
$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName 'WeComAgentReadOnlyCollect' -Action $action -Trigger $trigger `
    -Principal $principal -Description 'Read-only local WeCom message index refresh' -Force | Out-Null
Get-ScheduledTask -TaskName 'WeComAgentReadOnlyCollect' | Select-Object TaskName, State

