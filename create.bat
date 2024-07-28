REM start cmd.exe /c C:\Users\hacker\source\repos\mydumbedr\x64\Debug\MyDumbEDRStaticAnalyzer.exe 

sc create mydumbedr type=kernel binpath=C:\Users\hacker\source\repos\mydumbedr\x64\Debug\MyDumbEDRDriver\MyDumbEDRDriver.sys
sc start mydumbedr

REM start cmd.exe /c C:\Users\hacker\source\repos\mydumbedr\x64\Debug\MyDumbEDRRemoteInjector.exe 
REM start cmd.exe /K "cd C:\Users\hacker\source\repos\mydumbedr\x64\Debug"

echo EDR's running, press any key to stop it
pause

REM taskkill /F /IM MyDumbEDRStaticAnalyzer.exe 
REM taskkill /F /IM MyDumbEDRRemoteInjector.exe
sc stop mydumbedr
sc delete mydumbedr
