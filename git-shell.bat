cd /d %~dp0

set V2SHELL=%PROGRAMFILES%\Git\bin\sh.exe 
if exist "%V2SHELL%" (
	"%V2SHELL%" %*
) else (
	if "%PROCESSOR_ARCHITECTURE%" NEQ "x86" (
		set SHELL="C:\Program Files (x86)\Git\bin\sh.exe"
	) else (
		set SHELL="C:\Program Files\Git\bin\sh.exe"
	)
	%SHELL% --login -i %*
)
