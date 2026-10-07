@echo off
set "MSVC=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.51.36231"
set "KITS=C:\Program Files (x86)\Windows Kits\10"
set "KITVER=10.0.26100.0"
set "PATH=%MSVC%\bin\Hostx86\x86;%PATH%"
set "INCLUDE=%MSVC%\include;%KITS%\Include\%KITVER%\ucrt;%KITS%\Include\%KITVER%\um;%KITS%\Include\%KITVER%\shared"
set "LIB=%MSVC%\lib\x86;%KITS%\Lib\%KITVER%\ucrt\x86;%KITS%\Lib\%KITVER%\um\x86"
cd /d "%~dp0..\.."
cl -nologo -LD -O1 -MT crack_work\tools\rcreplay.c crack_work\tools\rclogger.def -Fe:crack_work\tools\RCGrandDogW32_replay.dll
