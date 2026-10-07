# sendkeys.ps1 — drive the game toward gameplay: coin + confirms + arrows
param([int]$pidnum)
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName Microsoft.VisualBasic
$p = Get-Process -Id $pidnum -ErrorAction SilentlyContinue
if (-not $p) { Write-Host "no process"; exit 1 }
[Microsoft.VisualBasic.Interaction]::AppActivate($p.Id) | Out-Null
Start-Sleep -Milliseconds 500
$seq = @('{F1}','{F1}','{ENTER}','1','2','{ENTER}','{DOWN}','{ENTER}','{RIGHT}','{ENTER}','{LEFT}','{ENTER}','{UP}','{ENTER}','{ENTER}','{F1}','{ENTER}','{DOWN}','{DOWN}','{ENTER}','{RIGHT}','{ENTER}')
foreach ($k in $seq) {
    [System.Windows.Forms.SendKeys]::SendWait($k)
    Start-Sleep -Milliseconds 700
}
