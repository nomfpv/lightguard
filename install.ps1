#Requires -RunAsAdministrator
# copies lightguard.exe to Program Files and adds a start menu entry
$ErrorActionPreference = 'Stop'
$exe = Join-Path $PSScriptRoot 'lightguard.exe'
if (-not (Test-Path $exe)) { throw 'lightguard.exe not found, run build.bat first' }

$dir = Join-Path $env:ProgramFiles 'lightguard'
New-Item -ItemType Directory -Force $dir | Out-Null
Copy-Item $exe $dir -Force

$link = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\lightguard.lnk'
$s = (New-Object -ComObject WScript.Shell).CreateShortcut($link)
$s.TargetPath = Join-Path $dir 'lightguard.exe'
$s.WorkingDirectory = $dir
$s.Description = 'wireguard config tool'
$s.Save()
Write-Host 'installed. search "lightguard" in the start menu.'
