@echo off
rem =====================================================================
rem  USB Security Audit Toolkit v1.0.0 - Entrada Windows
rem  ASCII puro. Sin tildes. CRLF. Sin BOM.
rem  Uso: doble clic, o INICIAR.cmd [1|2|3|4] [destino web...]
rem =====================================================================
setlocal EnableExtensions
chcp 65001 >nul 2>&1
cd /d "%~dp0"
set "ROOT=%~dp0"
set "SELF=%~f0"
set "VERSION=1.0.0"
set "ENGINE=%ROOT%engine\Audit-Windows.ps1"
set "SETTINGS=%ROOT%engine\config\settings.json"
set "CFGSRC=%ROOT%config\settings.json"
set "PSFALLBACK=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "MODEARG="
set "MODE="
set "APPLY="
set "TARGETS="
set "TARGETSJOIN="
set "TARGSWITCH="
set "PSEXE="
set "RC=0"
set "HTML="
set "FINDINGS="

title USB Security Audit Toolkit v%VERSION%
color 0F

rem ---------------------------------------------------------------------
rem  1. Integridad del toolkit
rem ---------------------------------------------------------------------
if not exist "%ENGINE%" goto incomplete
if exist "%SETTINGS%" goto ps_detect
if not exist "%CFGSRC%" goto incomplete
echo [INFO] engine\config\settings.json no existe; se copia desde config\settings.json
if not exist "%ROOT%engine\config" md "%ROOT%engine\config" >nul 2>&1
copy /y "%CFGSRC%" "%SETTINGS%" >nul 2>&1
if not exist "%SETTINGS%" goto incomplete

rem ---------------------------------------------------------------------
rem  2. Deteccion de PowerShell: pwsh.exe y luego powershell.exe
rem ---------------------------------------------------------------------
:ps_detect
where pwsh.exe >nul 2>&1
if not errorlevel 1 set "PSEXE=pwsh.exe"
if defined PSEXE goto args
where powershell.exe >nul 2>&1
if not errorlevel 1 set "PSEXE=powershell.exe"
if defined PSEXE goto args
if exist "%PSFALLBACK%" set "PSEXE=%PSFALLBACK%"
if defined PSEXE goto args
goto nops

rem ---------------------------------------------------------------------
rem  3. Argumentos de linea de comandos
rem ---------------------------------------------------------------------
:args
if "%~1"=="" goto menu
if /i "%~1"=="--help" goto help
if /i "%~1"=="-h" goto help
if /i "%~1"=="/?" goto help
set "MODEARG=%~1"
if /i "%MODEARG%"=="rapido" set "MODEARG=1"
if /i "%MODEARG%"=="completo" set "MODEARG=2"
if /i "%MODEARG%"=="web" set "MODEARG=3"
if /i "%MODEARG%"=="aplicar" set "MODEARG=4"
if /i "%MODEARG%"=="hardening" set "MODEARG=4"
shift

:collect
if "%~1"=="" goto apply_mode
if not defined TARGETS goto first_target
set TARGETS=%TARGETS% "%~1"
set "TARGETSJOIN=%TARGETSJOIN%,%~1"
shift
goto collect

:first_target
set TARGETS="%~1"
set "TARGETSJOIN=%~1"
shift
goto collect

rem ---------------------------------------------------------------------
rem  4. Mapeo de la opcion numerica a modo del motor
rem ---------------------------------------------------------------------
:apply_mode
set "MODE="
set "APPLY="
if "%MODEARG%"=="1" set "MODE=rapido"
if "%MODEARG%"=="2" set "MODE=completo"
if "%MODEARG%"=="3" set "MODE=web"
if "%MODEARG%"=="4" set "MODE=rapido"
if "%MODEARG%"=="4" set "APPLY=-Apply"
if "%MODEARG%"=="5" goto bye
if not defined MODE goto usage

rem ---------------------------------------------------------------------
rem  5. Elevacion UAC si hace falta
rem ---------------------------------------------------------------------
net session >nul 2>&1
if not errorlevel 1 goto run
"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -Command "if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 1 }" >nul 2>&1
if not errorlevel 1 goto run

echo.
echo [INFO] Se necesitan privilegios de administrador para auditar el sistema.
echo [INFO] Se abrira una ventana de UAC. Pulse "Si" para continuar.
echo.
"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Process -FilePath '%SELF%' -ArgumentList ('%MODEARG% ' + [char]34 + '%TARGETSJOIN%' + [char]34) -Verb RunAs -ErrorAction Stop; exit 0 } catch { exit 2 }"
if errorlevel 2 goto uac_cancel
if errorlevel 1 goto uac_fail
exit /b 0

:uac_cancel
echo.
echo [ERROR] Elevacion cancelada en el aviso de UAC.
echo [ERROR] No se ejecuto ninguna comprobacion. Vuelva a intentarlo y acepte UAC.
echo.
pause
exit /b 2

:uac_fail
echo.
echo [ERROR] No fue posible relanzar el toolkit con privilegios elevados.
echo [ERROR] Abra una consola como administrador y ejecute INICIAR.cmd manualmente.
echo.
pause
exit /b 1

rem ---------------------------------------------------------------------
rem  6. Ejecucion del motor
rem ---------------------------------------------------------------------
:run
cls
echo ==========================================================
echo   USB SECURITY AUDIT TOOLKIT v%VERSION%
echo ==========================================================
echo   Raiz    : %ROOT%
echo   Motor   : %PSEXE%
echo   Modo    : %MODE%
if defined APPLY echo   Cambios : SI - se aplicara hardening
if not defined APPLY echo   Cambios : NO - solo lectura
if defined TARGETS echo   Destinos: %TARGETS%
echo ==========================================================
echo.
if /i "%MODE%"=="web" if not defined TARGETS echo [INFO] Modo web sin destinos en la linea de comandos: se usaran los de settings.json.
if /i "%MODE%"=="web" if not defined TARGETS echo.

if defined TARGETS set TARGSWITCH=-Targets "%TARGETSJOIN%"

pushd "%ROOT%"
"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -File "%ENGINE%" -Mode %MODE% %APPLY% -RootPath "%ROOT%." %TARGSWITCH%
set "RC=%ERRORLEVEL%"
popd

echo.
echo [INFO] Codigo de salida del motor: %RC%
if not "%RC%"=="0" (
  echo [WARN] El motor termino con errores. Revise engine.log dentro de la carpeta de evidencia.
)

rem Localiza el informe y el findings.json mas recientes bajo evidencia\
for /f "delims=" %%F in ('dir /b /s /o-d "%ROOT%evidencia\informe.html" 2^>nul') do if not defined HTML set "HTML=%%F"
for /f "delims=" %%F in ('dir /b /s /o-d "%ROOT%evidencia\findings.json" 2^>nul') do if not defined FINDINGS set "FINDINGS=%%F"

echo.
if defined FINDINGS (
  echo [OK] Datos de la auditoria: %FINDINGS%
) else (
  echo [WARN] No se encontro findings.json. La auditoria no llego a completarse.
)

if "%RC%"=="0" if defined HTML (
  echo [OK] Informe HTML: %HTML%
  echo [INFO] Abriendo el informe en el navegador...
  rem Se abre a traves del shell del usuario. Con "start" el navegador se
  rem lanzaria con los mismos privilegios que el toolkit, es decir, elevado.
  "%PSEXE%" -NoProfile -ExecutionPolicy Bypass -Command "$f = '%HTML%'; if (Get-Process explorer -ErrorAction SilentlyContinue) { & explorer.exe $f } else { Start-Process -FilePath $f }" >nul 2>&1
) else (
  if defined HTML echo [INFO] Informe HTML disponible en: %HTML%
)

if not defined HTML echo [WARN] No se encontro informe.html en la carpeta evidencia.
echo.
pause
exit /b %RC%

rem ---------------------------------------------------------------------
rem  7. Menu interactivo
rem ---------------------------------------------------------------------
:menu
cls
echo ==========================================================
echo   USB SECURITY AUDIT TOOLKIT v%VERSION%
echo   Auditoria defensiva de Windows - solo lectura por defecto
echo ==========================================================
echo.
echo    1  Auditoria RAPIDA           - comprobaciones esenciales
echo    2  Auditoria COMPLETA         - revision profunda
echo    3  Auditoria WEB              - TLS, cabeceras, cookies
echo    4  RAPIDA + APLICAR HARDENING - modifica el sistema
echo    5  Salir
echo.
where choice >nul 2>&1
if errorlevel 1 goto menu_setp
choice /c 12345 /n /m "  Seleccione una opcion 1-5: "
set "MODEARG=%ERRORLEVEL%"
goto apply_mode

:menu_setp
set "SEL="
set /p "SEL=  Seleccione una opcion 1-5: "
if not defined SEL goto menu_eof
set "MODEARG=%SEL%"
if "%MODEARG%"=="1" goto apply_mode
if "%MODEARG%"=="2" goto apply_mode
if "%MODEARG%"=="3" goto apply_mode
if "%MODEARG%"=="4" goto apply_mode
if "%MODEARG%"=="5" goto apply_mode
echo   Opcion no valida.
echo.
pause
goto menu

:menu_eof
echo.
echo No se selecciono ninguna opcion. Saliendo sin ejecutar nada.
exit /b 0

:bye
echo.
echo Saliendo. No se ejecuto ninguna comprobacion.
exit /b 0

rem ---------------------------------------------------------------------
rem  8. Ayuda
rem ---------------------------------------------------------------------
:help
echo.
echo USB Security Audit Toolkit v%VERSION%
echo.
echo USO:
echo   INICIAR.cmd                 Menu interactivo
echo   INICIAR.cmd 1               Auditoria rapida
echo   INICIAR.cmd 2               Auditoria completa
echo   INICIAR.cmd 3               Auditoria web con destinos de settings.json
echo   INICIAR.cmd 3 URL [URL...]  Auditoria web con destinos indicados
echo   INICIAR.cmd 4               Auditoria rapida y aplicar hardening
echo   INICIAR.cmd 5               Salir
echo   INICIAR.cmd --help          Esta ayuda
echo.
echo MODOS:
echo   1 rapido    Comprobaciones esenciales. Menos de 90 segundos.
echo   2 completo  Revision profunda de sistema, red y servicios.
echo   3 web       TLS, certificados, cabeceras y cookies de los destinos.
echo   4 aplicar   Modo rapido y despues aplica los 16 controles de hardening.
echo               Genera rollback para revertir. Modifica el sistema.
echo.
echo REQUISITOS:
echo   Windows 10/11/Server 2016 o superior, PowerShell 5.1.
echo   Privilegios de administrador, el script eleva por UAC.
echo.
echo SALIDA:
echo   evidencia^<ID^>\findings.json  datos de la auditoria
echo   evidencia^<ID^>\informe.html   informe navegable
echo.
echo AVISO LEGAL:
echo   Use esta herramienta solo en equipos propios o con autorizacion
echo   escrita del responsable. Auditarlos sin permiso puede ser ilegal.
echo.
pause
exit /b 0

rem ---------------------------------------------------------------------
rem  9. Errores de entorno
rem ---------------------------------------------------------------------
:incomplete
echo.
echo ==========================================================
echo   TOOLKIT INCOMPLETO
echo ==========================================================
echo.
echo No se encontraron los archivos del motor en:
echo   %ROOT%
echo.
echo Se esperaba:
echo   engine\Audit-Windows.ps1
echo   engine\config\settings.json
echo.
echo Copie de nuevo el toolkit completo al USB y reintente.
echo No se ejecuto ninguna comprobacion.
echo.
pause
exit /b 3

:nops
echo.
echo ==========================================================
echo   POWERSHELL NO DISPONIBLE
echo ==========================================================
echo.
echo No se encontro pwsh.exe ni powershell.exe en este equipo.
echo El toolkit necesita PowerShell 5.1 o superior para funcionar.
echo.
echo En Windows 10/11 deberia estar en:
echo   %PSFALLBACK%
echo.
echo No se ejecuto ninguna comprobacion.
echo.
pause
exit /b 4

:usage
echo.
echo [ERROR] Opcion no reconocida: %MODEARG%
echo [INFO] Opciones validas: 1, 2, 3, 4, 5, --help
echo.
pause
exit /b 5
