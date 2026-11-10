@echo off
chcp 65001 >nul
setlocal
rem Запуск elf-gate с правами администратора (нужно для режима TUN).
rem Положите этот файл в папку рядом с elf-gate.exe.

rem 1. Если уже запущены как администратор - идём дальше, иначе перезапускаемся с UAC.
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

rem 2. Если фоновая служба уже работает без прав администратора, TUN не включится.
tasklist /FI "IMAGENAME eq elf-gated.exe" 2>nul | find /I "elf-gated.exe" >nul
if %errorlevel% equ 0 (
    echo Фоновая служба elf-gated уже запущена.
    echo Если она была запущена без прав администратора, TUN не заработает:
    echo откройте elf-gate как обычно, нажмите Q, затем снова запустите этот файл.
    echo.
    pause
)

if not exist "elf-gate.exe" (
    echo Не найден elf-gate.exe рядом с этим файлом: %~dp0
    pause
    exit /b 1
)

start "" "elf-gate.exe"
