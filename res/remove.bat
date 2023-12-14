@echo off

echo This is a removal script
echo generated by nebulder (https://github.com/erykjj/nebulder)
echo for removing the Nebula service
echo MIT License (c) 2023 Eryk J
echo.

set scriptpath=%~dp0

if NOT exist %scriptpath%\nebula.exe (
    echo ERROR: nebula.exe binary NOT FOUND!
    set /p k= Press ENTER to terminate
    goto :eof
) else (
    set binary=%scriptpath%nebula.exe
)

echo Stopping nebula service
%scriptpath%/nebula.exe -service stop
timeout /t 3 /nobreak > NUL
echo.

echo Uninstalling nebula service
%scriptpath%/nebula.exe -service uninstall
timeout /t 2 /nobreak > NUL
echo.

echo Done. You can remove this deployment package
set /p k= Press ENTER to close
