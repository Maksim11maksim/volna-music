@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ===========================
echo       VOLNA MUSIC
echo ===========================

where node >nul 2>nul
if errorlevel 1 (
    echo Node.js не установлен.
    echo Установите Node.js 24 или новее:
    echo https://nodejs.org/
    pause
    exit /b 1
)

node -e "if (+process.versions.node.split('.')[0] < 24) process.exit(1)"
if errorlevel 1 (
    echo Требуется Node.js версии 24 или новее.
    node -v
    pause
    exit /b 1
)

if not exist node_modules (
    echo Устанавливаем зависимости...
    call npm install
    if errorlevel 1 (
        echo Ошибка установки зависимостей.
        pause
        exit /b 1
    )
)

echo.
echo Открывайте сайт: http://localhost:3000
echo Для остановки нажмите Ctrl+C.
echo.
call npm start
pause