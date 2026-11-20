#Requires -RunAsAdministrator
# removes the program and the start menu entry; tunnels and configs are left alone
Remove-Item (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\lightguard.lnk') -ErrorAction SilentlyContinue
Remove-Item (Join-Path $env:ProgramFiles 'lightguard') -Recurse -Force -ErrorAction SilentlyContinue
Write-Host 'removed. your tunnels and configs in %ProgramData%\lightguard are untouched.'
