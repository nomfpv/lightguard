@echo off
rem builds lightguard.exe with msvc (found via vswhere), no crt
setlocal
set "VSW=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSW%" (echo vswhere not found - install visual studio build tools & exit /b 1)
for /f "usebackq delims=" %%i in (`"%VSW%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS=%%i"
if not defined VS (echo no msvc with c++ tools found & exit /b 1)
call "%VS%\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1

cd /d "%~dp0"
if not exist build mkdir build

rc /nologo /fo build\lightguard.res src\lightguard.rc || exit /b 1
cl /nologo /W4 /WX /O1 /GS- /Zl /Gy /Gm- /utf-8 /Fobuild\ /c src\lgcore.c src\wincore.c src\win.c || exit /b 1
link /nologo /WX /OUT:lightguard.exe /SUBSYSTEM:WINDOWS,6.00 /ENTRY:start /NODEFAULTLIB /OPT:REF,ICF ^
  /MANIFEST:EMBED /MANIFESTUAC:NO /MANIFESTINPUT:src\lightguard.manifest ^
  build\lgcore.obj build\wincore.obj build\win.obj build\lightguard.res ^
  kernel32.lib user32.lib gdi32.lib shell32.lib comctl32.lib comdlg32.lib advapi32.lib bcrypt.lib uxtheme.lib dwmapi.lib || exit /b 1
echo built lightguard.exe
