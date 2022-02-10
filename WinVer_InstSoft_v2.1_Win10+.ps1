"`0 Please wait..." | Write-Host -foregroundcolor Cyan
$dir = (dir).Name
if($dir -like "test"){
Remove-item -Recurse -Force -Path $PSScriptRoot"\test\" | Out-Null }
New-Item -Path $PSScriptRoot"\test\" -ItemType Directory | Out-Null

Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion"  | Select-Object ProductName, DisplayVersion, CurrentBuild, ReleaseId | Format-List > $PSScriptRoot\test\WindowsVersion.csv

Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -notlike "*False*"} | Select-Object DisplayName, DisplayVersion | Sort-Object -Property "DisplayName" | Format-Table -HideTableHeaders -AutoSize -Wrap > $PSScriptRoot\test\x86.csv
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -notlike "*False*"}  | Select-Object DisplayName, DisplayVersion | Sort-Object -Property "DisplayName" | Format-Table -HideTableHeaders -AutoSize -Wrap > $PSScriptRoot\test\x64.csv
Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -notlike "*False*"}  | Select-Object DisplayName, DisplayVersion | Sort-Object -Property "DisplayName" | Format-Table -HideTableHeaders -AutoSize -Wrap > $PSScriptRoot\test\other_soft.csv
# InstallDate
Get-ChildItem $PSScriptRoot\test\x86.csv | ForEach-Object {
    (Get-Content $_.FullName) | Where { $_.Replace(",","").trim() -ne "" } |
    Out-File $_.FullName
}
Get-ChildItem $PSScriptRoot\test\x64.csv | ForEach-Object {
    (Get-Content $_.FullName) | Where { $_.Replace(",","").trim() -ne "" } |
    Out-File $_.FullName
}
if ((get-item $PSScriptRoot\test\other_soft.csv).Length -eq 0)
{}
else
{
 Get-ChildItem $PSScriptRoot\test\other_soft.csv | ForEach-Object {
    (Get-Content $_.FullName) | Where { $_.Replace(",","").trim() -ne "" } |
    Out-File $_.FullName
}
}

Compare-Object -referenceobject (Get-Content -Path $PSScriptRoot"\test\x86.csv") -differenceobject (Get-Content -Path $PSScriptRoot"\test\x64.csv") -IncludeEqual | Select-Object InputObject | Format-Table -HideTableHeaders > $PSScriptRoot"\test\ALL_Installed_Soft.csv"
if ((get-item $PSScriptRoot\test\other_soft.csv).Length -eq 0)
{}
else
{
Compare-Object -referenceobject (Get-Content -Path $PSScriptRoot"\test\ALL_Installed_Soft.csv") -differenceobject (Get-Content -Path $PSScriptRoot"\test\other_soft.csv") -IncludeEqual | Select-Object InputObject | Format-Table -HideTableHeaders > $PSScriptRoot"\test\ALL_Installed_Soft.csv"
}

"`n "
Get-Content $PSScriptRoot\test\WindowsVersion.csv
"`n `n "
"Installed soft:" | Write-Host -foregroundcolor Cyan
"`n "
"`n x86:" | Write-Host -foregroundcolor Cyan
Get-Content  $PSScriptRoot\test\x86.csv
"`n x64:" | Write-Host -foregroundcolor Cyan
Get-Content  $PSScriptRoot\test\x64.csv
"`n other_soft:" | Write-Host -foregroundcolor Cyan
Get-Content  $PSScriptRoot\test\other_soft.csv
$sum = (Get-Content $PSScriptRoot'\test\x86.csv').Length + (Get-Content $PSScriptRoot'\test\x64.csv').Length + (Get-Content $PSScriptRoot'\test\other_soft.csv').Length
"`n In sum = " + $sum + " programs" | Write-Host -foregroundcolor Green
"`0 `n All data saved in \Windows_InstalledPrograms\test\" | Write-Host -foregroundcolor Green
"`n Script finished - press [ENTER] to exit"
Read-Host 
