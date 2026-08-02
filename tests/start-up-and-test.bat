@echo off
call "%~dp0run-test-in-docker.bat"
exit /b %ERRORLEVEL%
