$ErrorActionPreference= 'silentlycontinue'
"`0 Please wait..."
Remove-item -Recurse -Force -Path 'C:\Windows_InstalledPrograms' | Out-Null 
New-Item -Path 'C:\Windows_InstalledPrograms' -ItemType Directory | Out-Null
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -notlike "*False*"} | Select-Object DisplayName, DisplayVersion | Format-Table -AutoSize -Wrap > C:\Windows_InstalledPrograms\1.csv
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -notlike "*False*"}  | Select-Object DisplayName, DisplayVersion | Format-Table -AutoSize -Wrap > C:\Windows_InstalledPrograms\2.csv
Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -notlike "*False*"}  | Select-Object DisplayName, DisplayVersion | Format-Table -AutoSize -Wrap > C:\Windows_InstalledPrograms\3.csv

Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion"  | Select-Object ProductName, CSDVersion, CurrentBuild | Format-List > C:\Windows_InstalledPrograms\WindowsVersion.csv

Get-ChildItem "C:\Windows_InstalledPrograms\1.csv" | ForEach-Object {
    (Get-Content $_.FullName) | Where { $_.Replace(",","").trim() -ne "" } |
    Out-File $_.FullName
}
Get-ChildItem "C:\Windows_InstalledPrograms\2.csv" | ForEach-Object {
    (Get-Content $_.FullName) | Where { $_.Replace(",","").trim() -ne "" } |
    Out-File $_.FullName
}
if ((get-item "C:\Windows_InstalledPrograms\3.csv").Length -eq 0)
{}
else
{
Get-ChildItem "C:\Windows_InstalledPrograms\3.csv" | ForEach-Object {
    (Get-Content $_.FullName) | Where { $_.Replace(",","").trim() -ne "" } |
    Out-File $_.FullName
}
}


Compare-Object -referenceobject (Get-Content -Path C:\Windows_InstalledPrograms\1.csv) -differenceobject (Get-Content -Path C:\Windows_InstalledPrograms\2.csv) -IncludeEqual | Select-Object InputObject | Format-Table -HideTableHeaders > C:\Windows_InstalledPrograms\InstalledSoft.csv
if ((get-item "C:\Windows_InstalledPrograms\3.csv").Length -eq 0)
{}
else
{
Compare-Object -referenceobject (Get-Content -Path C:\Windows_InstalledPrograms\InstalledSoft.csv) -differenceobject (Get-Content -Path C:\Windows_InstalledPrograms\3.csv) -IncludeEqual | Select-Object InputObject | Format-Table -HideTableHeaders > C:\Windows_InstalledPrograms\InstalledSoft.csv
}


Get-ChildItem "C:\Windows_InstalledPrograms\InstalledSoft.csv" | ForEach-Object {
    (Get-Content $_.FullName) | Where { $_.Replace(",","").trim() -ne "" } |
    Out-File $_.FullName
}

Remove-item C:\Windows_InstalledPrograms\2.csv, C:\Windows_InstalledPrograms\1.csv, C:\Windows_InstalledPrograms\3.csv

"`n "
Get-Content C:\Windows_InstalledPrograms\WindowsVersion.csv
"`n `n Installed soft: `n "
Get-Content C:\Windows_InstalledPrograms\InstalledSoft.csv

"`0 `n All data saved in C:\Windows_InstalledPrograms\"
Read-Host "`n Script finished - press [ENTER] to exit"