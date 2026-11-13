@echo off
rem Start the Security-channel collector with a UAC elevation prompt.
set "SCRIPT=%~dp0collect-security.ps1"
echo Requesting administrator rights to read the Windows Security log...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList @('-NoExit','-NoProfile','-ExecutionPolicy','Bypass','-File','%SCRIPT%')"
