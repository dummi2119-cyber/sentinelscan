@echo off
chcp 65001 >nul
cd /d "%~dp0"
title SentinelScan
echo ============================================
echo   SentinelScan - Security Scanning SaaS
echo ============================================
echo.
echo Starting server on http://localhost:8000
echo   User login:   register a free account at /register
echo   Admin login:  /admin/login  (admin@sentinel.local / Admin123!)
echo.
echo Press Ctrl+C to stop.
echo.
python run.py
if errorlevel 1 (
  echo.
  echo If python failed, try:  python3 run.py
  pause
)
