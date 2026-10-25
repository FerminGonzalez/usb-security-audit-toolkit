<#
.SYNOPSIS
    Instalador OPCIONAL de una tarea programada que lanza la auditoria al
    insertar este USB. Deja persistencia en el equipo auditado.

.DESCRIPTION
    Registra una tarea programada en el Programador de tareas de Windows con
    un trigger de evento (Microsoft-Windows-Kernel-PnP/Configuration, eventos
    2001 y 2003) y una accion que ejecuta INICIAR.cmd en modo rapido con
    ventana visible.

    ADVERTENCIA: esto deja persistencia. Crea una tarea programada y un
    registro de evento. Un analista forense lo vera. Por eso el script pide
    confirmacion explicita antes de tocar nada.

    Genera ademas desinstalar-autorun.ps1 junto al toolkit para revertir.

.PARAMETER Force
    Omite la confirmacion interactiva. Solo para automatizacion controlada.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\PREPARAR-AUTORUN.ps1
#>
[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

$TaskName = 'USBAuditToolkit-AutoRun'
$TaskPath = '\'
$ToolkitRoot = $PSScriptRoot
$EntryPoint = Join-Path $ToolkitRoot 'INICIAR.cmd'
$UninstallerPath = Join-Path $ToolkitRoot 'desinstalar-autorun.ps1'

# ---------------------------------------------------------------------
# 1. Requisitos: administrador y toolkit presente
# ---------------------------------------------------------------------
$isAdmin = $false
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $isAdmin = $false
}

if (-not $isAdmin) {
    Write-Host ''
    Write-Host 'ERROR: se requieren privilegios de administrador.' -ForegroundColor Red
    Write-Host 'Abra PowerShell como administrador y vuelva a ejecutar este script.'
    Write-Host 'Este script NO intenta elevarse solo: es un instalador y usted debe'
    Write-Host 'decidir consciente en que contexto se ejecuta.'
    Write-Host ''
    exit 1
}

if (-not (Test-Path -LiteralPath $EntryPoint -PathType Leaf)) {
    Write-Host ''
    Write-Host "ERROR: no se encontro $EntryPoint" -ForegroundColor Red
    Write-Host 'Ejecute este script desde la raiz del USB del toolkit.'
    Write-Host ''
    exit 1
}

$driveLetter = ''
if ($ToolkitRoot.Length -ge 2 -and $ToolkitRoot[1] -eq ':') {
    $driveLetter = $ToolkitRoot.Substring(0, 1).ToUpperInvariant()
}

$volumeLabel = ''
try {
    if ($driveLetter -ne '') {
        $vol = Get-Volume -DriveLetter $driveLetter -ErrorAction SilentlyContinue
        if ($null -ne $vol) { $volumeLabel = $vol.FileSystemLabel }
    }
} catch {
    $volumeLabel = ''
}

# ---------------------------------------------------------------------
# 2. AVISO EXPLICITO EN MAYUSCULAS
# ---------------------------------------------------------------------
Clear-Host
Write-Host '====================================================================' -ForegroundColor Yellow
Write-Host '  ATENCION - ESTO DEJA PERSISTENCIA EN EL EQUIPO AUDITADO' -ForegroundColor Yellow
Write-Host '====================================================================' -ForegroundColor Yellow
Write-Host ''
Write-Host '  Va a crear una TAREA PROGRAMADA en este equipo:' -ForegroundColor Yellow
Write-Host ("    Nombre : {0}" -f $TaskName)
Write-Host ("    Accion : {0} 1" -f $EntryPoint)
Write-Host '    Disparo: evento 2001 o 2003 de Microsoft-Windows-Kernel-PnP/Configuration'
Write-Host '             (configuracion de dispositivo, incluida la llegada de un USB)'
Write-Host ''
Write-Host '  CONSECUENCIAS QUE DEBE ASUMIR:' -ForegroundColor Yellow
Write-Host '   - Queda un registro persistente en el Programador de tareas.'
Write-Host '   - Un analista forense vera la tarea, su autor y su fecha de creacion.'
Write-Host '   - La tarea se ejecuta con privilegios elevados al insertar dispositivos.'
Write-Host '   - Cambiar el toolkit de sitio deja la tarea apuntando a una ruta muerta.'
Write-Host ''
Write-Host '  Es OPCIONAL. La auditoria funciona igual con doble clic en INICIAR.cmd.'
Write-Host '  Para revertir: ejecute desinstalar-autorun.ps1 (se genera al terminar).'
Write-Host ''
Write-Host '  Use esto SOLO en equipos propios o con autorizacion escrita.' -ForegroundColor Yellow
Write-Host '  En un equipo de terceros esto puede ser delito.' -ForegroundColor Yellow
Write-Host ''
Write-Host '====================================================================' -ForegroundColor Yellow
Write-Host ''

if (-not $Force) {
    $answer = Read-Host 'Escriba CONFIRMO (en mayusculas) para instalar la tarea, o cualquier otra cosa para cancelar'
    if ($answer -cne 'CONFIRMO') {
        Write-Host ''
        Write-Host 'Cancelado. No se creo ninguna tarea ni se modifico el sistema.' -ForegroundColor Green
        Write-Host ''
        exit 0
    }
} else {
    Write-Host 'Modo -Force: confirmacion omitida por parametro explicito.' -ForegroundColor Yellow
}

Write-Host ''

# ---------------------------------------------------------------------
# 3. Definir accion, trigger de evento (CIM) y principal
# ---------------------------------------------------------------------
$displayPath = $ToolkitRoot.TrimEnd('\')

# La accion solo actua si INICIAR.cmd sigue existiendo: evita ejecuciones
# huerfanas si el USB se reasigna a otra letra de unidad.
$actionArgs = '/c if exist "' + $EntryPoint + '" start "" "' + $EntryPoint + '" 1'
$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument $actionArgs -WorkingDirectory $displayPath

# Trigger de evento. New-ScheduledTaskTrigger no admite eventos en PS 5.1;
# hay que construir MSFT_TaskEventTrigger por CIM.
$subscriptionXml = @'
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Kernel-PnP/Configuration">
    <Select Path="Microsoft-Windows-Kernel-PnP/Configuration">*[System[(EventID=2001 or EventID=2003)]]</Select>
  </Query>
</QueryList>
'@

$triggerClass = Get-CimClass -ClassName 'MSFT_TaskEventTrigger' -Namespace 'Root/Microsoft/Windows/TaskScheduler'
if ($null -eq $triggerClass) {
    Write-Host 'ERROR: no se pudo obtener la clase MSFT_TaskEventTrigger del Programador de tareas.' -ForegroundColor Red
    exit 1
}

$trigger = New-CimInstance -CimClass $triggerClass -ClientOnly
$trigger.Enabled = $true
$trigger.Subscription = $subscriptionXml
$trigger.Delay = 'PT10S'

$userName = [string]$env:USERNAME
if (-not [string]::IsNullOrWhiteSpace($env:USERDOMAIN)) {
    $userName = "$env:USERDOMAIN\$env:USERNAME"
}
$taskPrincipal = New-ScheduledTaskPrincipal -UserId $userName -LogonType Interactive -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

# ---------------------------------------------------------------------
# 4. Registro idempotente (-Force actualiza, no duplica)
# ---------------------------------------------------------------------
$existing = $null
try {
    $existing = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
} catch {
    $existing = $null
}

$created = $false
try {
    if ($null -ne $existing) {
        Write-Host "[INFO] La tarea '$TaskName' ya existe. Se actualiza en sitio (sin duplicar)." -ForegroundColor Cyan
    } else {
        $created = $true
        Write-Host "[INFO] Registrando la tarea '$TaskName'..." -ForegroundColor Cyan
    }

    Register-ScheduledTask `
        -TaskName $TaskName `
        -TaskPath $TaskPath `
        -Action $action `
        -Trigger $trigger `
        -Principal $taskPrincipal `
        -Settings $settings `
        -Description 'Lanza la auditoria defensiva del USB Security Audit Toolkit al conectar un dispositivo (opcional, reversible).' `
        -Force | Out-Null
} catch {
    Write-Host ''
    Write-Host "ERROR: no se pudo registrar la tarea: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'No se genero el desinstalador porque la tarea no existe.'
    Write-Host ''
    exit 1
}

# Verificacion posterior
$verify = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
if ($null -eq $verify) {
    Write-Host 'ERROR: la tarea no aparece tras el registro. Revise el Visor de eventos.' -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------
# 5. Generar desinstalador junto al toolkit
# ---------------------------------------------------------------------
$uninstallerTemplate = @'
<#
.SYNOPSIS
    Desinstala la tarea programada del USB Security Audit Toolkit.

.DESCRIPTION
    Elimina la tarea '__TASKNAME__' del Programador de tareas y limpia el
    archivo de desinstalacion. Requiere administrador.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\desinstalar-autorun.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$TaskName = '__TASKNAME__'
$TaskPath = '\'

$isAdmin = $false
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $isAdmin = $false
}

if (-not $isAdmin) {
    Write-Host 'ERROR: se requieren privilegios de administrador para quitar la tarea.' -ForegroundColor Red
    exit 1
}

$task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
if ($null -eq $task) {
    Write-Host "La tarea '$TaskName' no existe. Nada que desinstalar." -ForegroundColor Green
} else {
    Write-Host "Quitando la tarea '$TaskName'..." -ForegroundColor Cyan
    try {
        Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
        Write-Host 'Tarea eliminada.' -ForegroundColor Green
    } catch {
        Write-Host "ERROR al quitar la tarea: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Limpieza defensiva: si quedo una copia en la raiz del Programador de tareas.
$stray = Get-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction SilentlyContinue
if ($null -ne $stray) {
    try {
        Unregister-ScheduledTask -TaskName $TaskName -TaskPath '\' -Confirm:$false
        Write-Host 'Copia residual en la raiz eliminada.' -ForegroundColor Green
    } catch {
        Write-Host "No se pudo eliminar la copia residual: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Host ''
Write-Host 'La persistencia del toolkit quedo revertida en este equipo.'
Write-Host 'Nota: el registro de eventos conserva el historial de la tarea;'
Write-Host 'eso es normal y no se puede borrar sin privilegios forenses.'
Write-Host ''
Write-Host 'Puede borrar este archivo manualmente:'
Write-Host ('  ' + $PSCommandPath)
Write-Host ''
'@

$uninstallerBody = $uninstallerTemplate.Replace('__TASKNAME__', $TaskName)
$utf8Bom = New-Object System.Text.UTF8Encoding($true)
try {
    [System.IO.File]::WriteAllText($UninstallerPath, $uninstallerBody, $utf8Bom)
} catch {
    Write-Host "[WARN] La tarea se creo pero no se pudo escribir el desinstalador: $($_.Exception.Message)" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------
# 6. Resumen
# ---------------------------------------------------------------------
Write-Host ''
Write-Host '====================================================================' -ForegroundColor Green
Write-Host '  TAREA INSTALADA' -ForegroundColor Green
Write-Host '====================================================================' -ForegroundColor Green
Write-Host ("  Nombre      : {0}" -f $TaskName)
Write-Host ("  Estado      : {0}" -f $verify.State)
Write-Host ("  Usuario     : {0}" -f $userName)
Write-Host ("  Accion      : {0} 1" -f $EntryPoint)
if ($volumeLabel -ne '') {
    Write-Host ("  Volumen     : {0}: ({1})" -f $driveLetter, $volumeLabel)
}
Write-Host '  Disparo     : evento 2001/2003 de Kernel-PnP/Configuration'
Write-Host '  Ventana     : visible (la auditoria se ve ejecutarse)'
Write-Host ''
Write-Host '  LIMITACION HONESTA:' -ForegroundColor Yellow
Write-Host '  Los eventos 2001/2003 de Kernel-PnP no incluyen la letra de unidad,'
Write-Host '  asi que el trigger no puede filtrar por la letra del USB de forma'
Write-Host '  fiable. La tarea se dispara al configurarse cualquier dispositivo,'
Write-Host '  y la accion solo ejecuta algo si INICIAR.cmd sigue existiendo en:'
Write-Host ("    {0}" -f $EntryPoint)
Write-Host ''
Write-Host '  PARA REVERTIR:' -ForegroundColor Cyan
Write-Host ("    powershell -NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $UninstallerPath)
Write-Host ("    o bien: Unregister-ScheduledTask -TaskName `"{0}`" -Confirm:`$false" -f $TaskName)
Write-Host ''
if ($created) {
    Write-Host '  Recuerde: esto deja persistencia. Documentelo en el alcance del trabajo.' -ForegroundColor Yellow
} else {
    Write-Host '  La tarea se actualizo; no se crearon duplicados.' -ForegroundColor Yellow
}
Write-Host ''
exit 0
