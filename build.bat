@echo off
setlocal
cd /d "%~dp0"

call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1

echo [1/4] Building RevokeHook.dll
msbuild "%~dp0native\RevokeHook\RevokeHook.sln" /m /p:Configuration=Release /p:Platform=x64 /v:minimal || exit /b 1

echo [2/4] Building update_stub.exe
cl /nologo /O1 /DUNICODE /D_UNICODE /Fo"%~dp0native\\" "%~dp0native\update_stub.c" /link /SUBSYSTEM:WINDOWS /OUT:"%~dp0native\update_stub.exe" >nul || exit /b 1

echo [3/4] Publishing GreenSoftAntiRecall.exe
dotnet publish "%~dp0src\GreenSoftAntiRecall\GreenSoftAntiRecall.csproj" -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -o "%~dp0dist" || exit /b 1

echo [4/4] Copy runtime files
copy /Y "%~dp0native\RevokeHook\x64\Release\RevokeHook.dll" "%~dp0dist\RevokeHook.dll" >nul || exit /b 1
copy /Y "%~dp0native\update_stub.exe" "%~dp0dist\update_stub.exe" >nul || exit /b 1
copy /Y "%~dp0config.yml" "%~dp0dist\config.yml" >nul || exit /b 1
copy /Y "%~dp0src\GreenSoftAntiRecall\Config3.json" "%~dp0dist\Config3.json" >nul || exit /b 1
copy /Y "%~dp0src\GreenSoftAntiRecall\Res\IcoE.ico" "%~dp0dist\IcoE.ico" >nul || exit /b 1

echo.
echo BUILD_OK
echo Output: %~dp0dist\GreenSoftAntiRecall.exe
exit /b 0
