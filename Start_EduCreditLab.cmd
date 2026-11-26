@echo off
setlocal
cd /d "%~dp0"
set "EDUCREDIT_PY=.venv\Scripts\python.exe"
if not exist "%EDUCREDIT_PY%" (
    where py >nul 2>&1
    if errorlevel 1 (
        python -m venv .venv
    ) else (
        py -3 -m venv .venv
    )
    if errorlevel 1 goto failed
)
"%EDUCREDIT_PY%" -c "import sys; sys.exit(sys.version_info < (3, 11))"
if errorlevel 1 (
    echo Python 3.11 or later is required. Use a fresh virtual environment.
    goto failed
)
"%EDUCREDIT_PY%" -c "import sys, educreditlab, scipy, cryptography; sys.exit(educreditlab.__version__ != '1.28.0')"
if errorlevel 1 (
    "%EDUCREDIT_PY%" -m pip install dist\educreditlab-1.28.0-py3-none-any.whl
    if errorlevel 1 goto failed
)
echo Open http://127.0.0.1:8765 in your browser.
"%EDUCREDIT_PY%" -m educreditlab --workspace workbench serve --seed
if errorlevel 1 goto failed
exit /b 0
:failed
echo EduCreditLab did not start. See the message above and the quickstart guide.
pause
exit /b 1
