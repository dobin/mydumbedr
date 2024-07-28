# MyThumbEdr

Used to trace and analyze loaders and other maldev.

https://sensepost.com/blog/2024/sensecon-23-from-windows-drivers-to-an-almost-fully-working-edr/



## Filter

* By working dir?


## Features

Kernel callbacks:
* PsSetCreateProcessNotifyRoutine: used to monitor process creation
* PsSetLoadImageNotifyRoutine: used to monitor DLL loading
* PsSetThreadCreateNotifyRoutine: used to monitor thread creation
* ObRegisterCallbacks: used to monitor calls to the OpenProcess, OpenThread and OpenDesktop functions
  * Todo

Todo: 
* Minifilter? For AMSI scan-buffer / scan-file
* DLL injection? For API calls
* ETW
  * https://github.com/microsoft/krabsetw/blob/master/examples/NativeExamples/user_trace_001.cpp
  * callback?


## Install


## Data

From: 
* function call
* PEB, EPROCESS

