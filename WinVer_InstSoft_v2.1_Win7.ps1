$ErrorActionPreference= 'silentlycontinue'
"`0 Please wait..." | Write-Host -foregroundcolor Cyan
Remove-item -Recurse -Force -Path 'C:\Windows_InstalledPrograms' | Out-Null 
New-Item -Path 'C:\Windows_InstalledPrograms' -ItemType Directory | Out-Null
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -notlike "*False*"} | Select-Object DisplayName, DisplayVersion | Format-Table -HideTableHeaders -AutoSize -Wrap > C:\Windows_InstalledPrograms\x86.csv
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -notlike "*False*"}  | Select-Object DisplayName, DisplayVersion | Format-Table -HideTableHeaders -AutoSize -Wrap > C:\Windows_InstalledPrograms\x64.csv
Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -notlike "*False*"}  | Select-Object DisplayName, DisplayVersion | Format-Table -HideTableHeaders -AutoSize -Wrap > C:\Windows_InstalledPrograms\other_soft.csv

Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion"  | Select-Object ProductName, CSDVersion, CurrentBuild | Format-List > C:\Windows_InstalledPrograms\WindowsVersion.csv

Get-ChildItem "C:\Windows_InstalledPrograms\x86.csv" | ForEach-Object {
    (Get-Content $_.FullName) | Where { $_.Replace(",","").trim() -ne "" } |
    Out-File $_.FullName
}
Get-ChildItem "C:\Windows_InstalledPrograms\x64.csv" | ForEach-Object {
    (Get-Content $_.FullName) | Where { $_.Replace(",","").trim() -ne "" } |
    Out-File $_.FullName
}
if ((get-item "C:\Windows_InstalledPrograms\other_soft.csv").Length -eq 0)
{}
else
{
Get-ChildItem "C:\Windows_InstalledPrograms\other_soft.csv" | ForEach-Object {
    (Get-Content $_.FullName) | Where { $_.Replace(",","").trim() -ne "" } |
    Out-File $_.FullName
}
}


Compare-Object -referenceobject (Get-Content -Path C:\Windows_InstalledPrograms\x86.csv) -differenceobject (Get-Content -Path C:\Windows_InstalledPrograms\x64.csv) -IncludeEqual | Select-Object InputObject | Format-Table -HideTableHeaders > C:\Windows_InstalledPrograms\ALL_InstalledSoft.csv
if ((get-item "C:\Windows_InstalledPrograms\other_soft.csv").Length -eq 0)
{}
else
{
Compare-Object -referenceobject (Get-Content -Path C:\Windows_InstalledPrograms\ALL_InstalledSoft.csv) -differenceobject (Get-Content -Path C:\Windows_InstalledPrograms\other_soft.csv) -IncludeEqual | Select-Object InputObject | Format-Table -HideTableHeaders > C:\Windows_InstalledPrograms\ALL_InstalledSoft.csv
}


Get-ChildItem "C:\Windows_InstalledPrograms\ALL_InstalledSoft.csv" | ForEach-Object {
    (Get-Content $_.FullName) | Where { $_.Replace(",","").trim() -ne "" } |
    Out-File $_.FullName
}

#Remove-item C:\Windows_InstalledPrograms\x64.csv, C:\Windows_InstalledPrograms\x86.csv, C:\Windows_InstalledPrograms\other_soft.csv

"`n "
Get-Content C:\Windows_InstalledPrograms\WindowsVersion.csv
"`n `n "
"Installed soft:" | Write-Host -foregroundcolor Cyan
"`n "
"`n x86:" | Write-Host -foregroundcolor Cyan
Get-Content C:\Windows_InstalledPrograms\x86.csv
"`n x64:" | Write-Host -foregroundcolor Cyan
Get-Content  C:\Windows_InstalledPrograms\x64.csv
"`n other_soft:" | Write-Host -foregroundcolor Cyan
Get-Content  C:\Windows_InstalledPrograms\other_soft.csv
$sum = (Get-Content 'C:\Windows_InstalledPrograms\x86.csv').Length + (Get-Content 'C:\Windows_InstalledPrograms\x64.csv').Length + (Get-Content 'C:\Windows_InstalledPrograms\other_soft.csv').Length
"`n In sum = " + $sum + " programs" | Write-Host -foregroundcolor Green
"`0 `n All data saved in C:\Windows_InstalledPrograms\" | Write-Host -foregroundcolor Green
"`n Script finished - press [ENTER] to exit"
Read-Host 