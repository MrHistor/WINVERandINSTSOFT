# WINVERandINSTSOFT
Using this Powershell script you can find out the version of Windows and all the programs installed on your pc.

![Windows10](https://user-images.githubusercontent.com/71935087/153003487-c0086e1b-eee1-4c80-8182-c2a654bb7f4c.PNG)
![Windows 7](https://user-images.githubusercontent.com/71935087/153003492-2c8c92cc-eb5c-4cdf-9974-d47e67182b11.PNG)

## About
All information is taken from Windows registry.

Windows version information is taken from 
HKLM:\Software\Microsoft\Windows NT\CurrentVersion

Information about installed programs is taken from 
HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\, 
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\, 
HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\
## Usage
The script needs to be run with powershell (execute with powershell). 
The best way to run in Windows 7 is launch Powerhell, drag the script into it and click "Enter".

All data will be stored in \Windows_InstalledPrograms\test\ (Windows 10+) or in C:\Windows_InstalledPrograms\ (Windows 7)

If you have error: "Cannot load file because script execution is not allowed on this system", you need to allow scripts to run. Launch Powershell as Administrator and run: "Set-ExecutionPolicy RemoteSigned", or allow scripts to run through group policies or the registry.

## Notice
Version for Windows 10+ (WinVer_InstSoft_vx.x_Win10+) not working properly in Windows 7 because of another location of registers.

## Version differences
### v2.1
Added sort by names

Added division into types of programs (x64, x86)

Slightly changed colors

Added the total number of programs found

![Снимок2 1](https://user-images.githubusercontent.com/71935087/153359539-5d954196-d910-4a47-9fed-c939c5eb2a0c.PNG)
