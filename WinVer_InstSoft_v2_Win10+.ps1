"`0 Please wait..."
$dir = (dir).Name
if($dir -like "test"){
Remove-item -Recurse -Force -Path $PSScriptRoot"\test\" | Out-Null }
New-Item -Path $PSScriptRoot"\test\" -ItemType Directory | Out-Null

Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion"  | Select-Object ProductName, DisplayVersion, CurrentBuild, ReleaseId | Format-List > $PSScriptRoot\test\WindowsVersion.csv

Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -notlike "*False*"} | Select-Object DisplayName, DisplayVersion | Format-Table -AutoSize -Wrap > $PSScriptRoot\test\1.csv
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -notlike "*False*"}  | Select-Object DisplayName, DisplayVersion | Format-Table -AutoSize -Wrap > $PSScriptRoot\test\2.csv
Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -notlike "*False*"}  | Select-Object DisplayName, DisplayVersion | Format-Table -AutoSize -Wrap > $PSScriptRoot\test\3.csv
# InstallDate
Get-ChildItem $PSScriptRoot\test\1.csv | ForEach-Object {
    (Get-Content $_.FullName) | Where { $_.Replace(",","").trim() -ne "" } |
    Out-File $_.FullName
}
Get-ChildItem $PSScriptRoot\test\2.csv | ForEach-Object {
    (Get-Content $_.FullName) | Where { $_.Replace(",","").trim() -ne "" } |
    Out-File $_.FullName
}
if ((get-item $PSScriptRoot\test\3.csv).Length -eq 0)
{}
else
{
 Get-ChildItem $PSScriptRoot\test\3.csv | ForEach-Object {
    (Get-Content $_.FullName) | Where { $_.Replace(",","").trim() -ne "" } |
    Out-File $_.FullName
}
}

Compare-Object -referenceobject (Get-Content -Path $PSScriptRoot"\test\1.csv") -differenceobject (Get-Content -Path $PSScriptRoot"\test\2.csv") -IncludeEqual | Select-Object InputObject | Format-Table -HideTableHeaders > $PSScriptRoot"\test\Installed_Soft.csv"
if ((get-item $PSScriptRoot\test\3.csv).Length -eq 0)
{}
else
{
Compare-Object -referenceobject (Get-Content -Path $PSScriptRoot"\test\Installed_Soft.csv") -differenceobject (Get-Content -Path $PSScriptRoot"\test\3.csv") -IncludeEqual | Select-Object InputObject | Format-Table -HideTableHeaders > $PSScriptRoot"\test\Installed_Soft.csv"
}

Remove-item $PSScriptRoot\test\1.csv, $PSScriptRoot\test\2.csv, $PSScriptRoot\test\3.csv

"`n "
Get-Content $PSScriptRoot\test\WindowsVersion.csv
"`n `n Installed soft: `n "
Get-Content  $PSScriptRoot\test\Installed_Soft.csv
"`0 `n All data saved in \Windows_InstalledPrograms\test\"
Read-Host "`n Script finished - press [ENTER] to exit"
