sc create mydumbedr type=kernel binpath=C:\Users\hacker\source\repos\mydumbedr\x64\Debug\MyDumbEDRDriver\MyDumbEDRDriver.sys
sc start mydumbedr
start cmd.exe /c C:\Users\hacker\source\repos\mydumbedr\x64\Debug\MyDumbEDRStaticAnalyzer.exe 
start cmd.exe /c C:\Users\hacker\source\repos\mydumbedr\x64\Debug\MyDumbEDRRemoteInjector.exe 
REM start cmd.exe /K "cd C:\Users\hacker\source\repos\mydumbedr\x64\Debug"

echo EDR's running, press any key to stop it
pause

taskkill /F /IM MyDumbEDRStaticAnalyzer.exe 
taskkill /F /IM MyDumbEDRRemoteInjector.exe
sc stop mydumbedr
sc delete mydumbedr
