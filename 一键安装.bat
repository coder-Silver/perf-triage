@echo off
setlocal
cd /d "%~dp0"
set "PYTHONUNBUFFERED=1"
set "PY=%~dp0vendor\python\python.exe"
set "SHELL=%~dp0vendor\trace_processor_shell.exe"

if not exist "%PY%" (
  echo Bundled Python is missing: vendor\python\python.exe
  echo This installer does not download dependencies. Keep the vendor folder next to this file.
  pause
  exit /b 1
)
if not exist "%SHELL%" (
  echo Bundled trace processor is missing: vendor\trace_processor_shell.exe
  pause
  exit /b 1
)

"%PY%" -c "import perfetto.trace_processor" 
if errorlevel 1 (
  echo Bundled Python cannot import perfetto. The vendor\python folder is incomplete.
  pause
  exit /b 1
)

powershell -NoProfile -Command "try { $r = Invoke-RestMethod http://127.0.0.1:8765/api/config -TimeoutSec 2; if ($r.PSObject.Properties.Name -contains 'has_key') { exit 10 } } catch { exit 0 }"
if "%errorlevel%"=="10" (
  for /f "tokens=5" %%p in ('netstat -ano ^| findstr "127.0.0.1:8765" ^| findstr LISTENING') do taskkill /F /PID %%p >nul 2>&1
  timeout /t 1 >nul
)

"%PY%" "%~dp0server.py"
exit /b 0
