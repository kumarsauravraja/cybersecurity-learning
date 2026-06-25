@echo off
REM Nessus Windows Host Preparation Script
REM Run as Domain Admin / Local Admin

echo Enabling built-in Administrator account...
net user Administrator /active:yes

REM Set password ONLY if approved
net user Administrator admin@123

echo Enabling required services...
sc config RemoteRegistry start= auto
sc start RemoteRegistry

sc config Winmgmt start= auto
sc start Winmgmt

sc config LanmanServer start= auto
sc start LanmanServer

echo Enabling Admin Shares...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" ^
 /v AutoShareWks /t REG_DWORD /d 1 /f

echo Disabling UAC remote restrictions...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" ^
 /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f

echo Enabling DCOM...
reg add "HKLM\SOFTWARE\Microsoft\Ole" /v EnableDCOM /t REG_SZ /d Y /f

echo Configuring firewall rules...
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes
netsh advfirewall firewall set rule group="Windows Management Instrumentation (WMI)" new enable=Yes
netsh advfirewall firewall set rule group="Remote Service Management" new enable=Yes
netsh advfirewall firewall add rule name="Allow RPC Dynamic" ^
 dir=in action=allow protocol=TCP localport=49152-65535

echo Restarting WMI...
net stop winmgmt /y
net start winmgmt

echo Nessus host preparation completed.
