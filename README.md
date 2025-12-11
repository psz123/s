reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\8EC4B3A5-6868-48c2-BE75-4F3044BE88A7 /v Attributes /t REG_DWORD /d 2 /f

powercfg.exe /SETACVALUEINDEX SCHEME_CURRENT SUB_VIDEO VIDEOCONLOCK 600

powercfg.exe /SETACTIVE SCHEME_CURRENT

reg.exe add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve

reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization

powercfg.exe /setacvalueindex SCHEME_CURRENT SUB_VIDEO VIDEOIDLE 600

reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization /v NoLockScreen /t REG_DWORD /d 1 /f

reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v BorderWidth /d 0 /f

reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v PaddedBorderWidth /d 0 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /t REG_DWORD /v AllowTelemetry /d 0 /reg:32 /f

for /f "delims=" %a in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace" /f "{"') do reg delete %a /f

for /f "delims=" %a in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace" /f "{"') do reg delete %a /f

setx PATH "C:\Perl\c\bin;C:\Perl\perl\bin;C:\Perl\perl\site\bin;C:\Program Files (x86)\GnuPG\bin;C:\Program Files (x86)\GnuWin32\bin;C:\Program Files (x86)\Nmap;C:\Program Files (x86)\Vim\vim90;C:\Program Files (x86)\gnupg\bin;C:\Program Files\7-Zip;C:\Program Files\Calibre2;C:\Program Files\Common Files\Oracle\Java\javapath;C:\Program Files\Lame;C:\Program Files\OpenSSL;C:\Program Files\OpenSSL\bin;C:\Program Files\PuTTY;C:\Program Files\curl;C:\Program Files\curl\bin;C:\Users\psz\AppData\Local\Microsoft\WindowsApps;C:\Windows;C:\Windows\System32;C:\Windows\System32\OpenSSH;C:\Windows\System32\WindowsPo
werShell\v1.0;C:\Windows\System32\wbem;G:\My Drive\Tools\Bin;G:\My Drive\Tools\Bin\Sysinternals;G:\My Drive\Tools\Bin\qpdf\bin;c:\Program Files\Python;"
