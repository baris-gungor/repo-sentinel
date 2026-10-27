@echo off
rem Runs security-scan.sh from PowerShell / cmd. Finds Git Bash by itself, so no
rem machine-specific path is needed. Usage: security-scan.cmd <repo-path>... [mode] [options]
setlocal
set "SENTINEL_BASH="
rem 1) bash from the installation of git.exe on PATH (cmd\git.exe or mingw64\bin\git.exe)
for /f "delims=" %%G in ('where git 2^>nul') do (
  if not defined SENTINEL_BASH if exist "%%~dpG..\bin\bash.exe" set "SENTINEL_BASH=%%~dpG..\bin\bash.exe"
  if not defined SENTINEL_BASH if exist "%%~dpG..\..\bin\bash.exe" set "SENTINEL_BASH=%%~dpG..\..\bin\bash.exe"
)
rem 2) Standard install locations
for %%P in ("%ProgramFiles%\Git\bin\bash.exe" "%LOCALAPPDATA%\Programs\Git\bin\bash.exe") do (
  if not defined SENTINEL_BASH if exist %%P set "SENTINEL_BASH=%%~P"
)
if not defined SENTINEL_BASH (
  echo Git Bash not found. Install Git for Windows: winget install Git.Git 1>&2
  exit /b 2
)
"%SENTINEL_BASH%" "%~dp0security-scan.sh" %*
exit /b %ERRORLEVEL%
