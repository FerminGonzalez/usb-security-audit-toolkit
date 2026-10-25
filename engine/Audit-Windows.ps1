<#
  Audit-Windows.ps1
  USB Security Audit Toolkit - orquestador Windows
  Dueno: UNIDAD A | Version: 1.0.0
  PowerShell 5.1 compatible

  Por defecto SOLO LEE. El hardening se aplica unicamente con -Apply.

  Uso:
    powershell -NoProfile -ExecutionPolicy Bypass -File engine\Audit-Windows.ps1 -Mode rapido
    ... -Mode completo
    ... -Mode web -Targets "https://sitio.com"
    ... -Mode rapido -Apply
#>

[CmdletBinding()]
param(
    [ValidateSet('rapido', 'completo', 'web')]
    [string] $Mode = 'rapido',

    [switch] $Apply,

    [string] $RootPath = '',

    [string[]] $Targets = @(),

    [switch] $NoColor
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# $PSScriptRoot no es fiable dentro del bloque param en PS 5.1 con -File:
# se resuelve aqui, ya en el cuerpo del script.
if (-not $RootPath) {
    try { $RootPath = (Split-Path -Parent (Split-Path -Parent $PSCommandPath)) } catch { $RootPath = '' }
}
if (-not $RootPath) {
    try { $RootPath = (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)) } catch { $RootPath = '' }
}
if (-not $RootPath) { $RootPath = (Get-Location).Path }
try { $RootPath = (Resolve-Path -LiteralPath $RootPath).Path } catch { }

# ---------------------------------------------------------------- carga dinamica
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }
catch { }

$engineDir = Join-Path $RootPath 'engine'
$libDir = Join-Path $engineDir 'lib'
$modDir = Join-Path $engineDir 'modules'
if (-not (Test-Path -LiteralPath $libDir) -and $PSScriptRoot) {
    $engineDir = $PSScriptRoot
    $libDir = Join-Path $engineDir 'lib'
    $modDir = Join-Path $engineDir 'modules'
}

if (-not (Test-Path -LiteralPath $libDir)) {
    Write-Host ('[ERROR] Falta la carpeta de librerias: {0}' -f $libDir) -ForegroundColor Red
    exit 1
}
if (-not (Test-Path -LiteralPath $modDir)) {
    Write-Host ('[ERROR] Falta la carpeta de modulos: {0}' -f $modDir) -ForegroundColor Red
    exit 1
}

Get-ChildItem -Path $libDir -Filter '*.ps1' | Sort-Object Name | ForEach-Object {
    . $_.FullName
}
Get-ChildItem -Path $modDir -Filter '*.ps1' | Sort-Object Name | ForEach-Object {
    . $_.FullName
}

# ---------------------------------------------------------------- banner
$isAdmin = Test-Admin
Write-Host ''
Write-Host '===============================================================' -ForegroundColor DarkCyan
Write-Host '        USB SECURITY AUDIT TOOLKIT  -  Windows                 ' -ForegroundColor Cyan
Write-Host '===============================================================' -ForegroundColor DarkCyan
Write-Host ('  Equipo     : {0}' -f $env:COMPUTERNAME)
Write-Host ('  Modo       : {0}' -f $Mode)
if ($Apply) {
    Write-Host '  Hardening  : APLICAR (modificara el sistema)' -ForegroundColor Yellow
}
else {
    Write-Host '  Hardening  : solo diagnostico (sin cambios)' -ForegroundColor Green
}
Write-Host ('  Elevado    : {0}' -f $(if ($isAdmin) { 'SI' } else { 'NO - cobertura limitada' })) -ForegroundColor $(if ($isAdmin) { 'Green' } else { 'Yellow' })
Write-Host ('  Raiz       : {0}' -f $RootPath)
Write-Host '===============================================================' -ForegroundColor DarkCyan
Write-Host ''

$totalSw = [Diagnostics.Stopwatch]::StartNew()
$fatal   = $false
$ctx     = $null

# ---------------------------------------------------------------- contexto
try {
    $ctx = Initialize-AuditContext -Mode $Mode -Apply:$Apply -RootPath $RootPath
}
catch {
    Write-Host ('[ERROR] No se pudo inicializar el contexto: {0}' -f $_.Exception.Message) -ForegroundColor Red
    exit 1
}

if ($Targets.Count -gt 0) {
    $ctx.Config['web']['targets'] = @($Targets)
    Write-Log -Level INFO -Message ('Destinos web recibidos por parametro: {0}' -f ($Targets -join ', '))
}

$webTargets = @()
if ($ctx.Config.ContainsKey('web') -and $ctx.Config['web'].ContainsKey('targets')) {
    $webTargets = @($ctx.Config['web']['targets'] | Where-Object { $_ })
}

# ---------------------------------------------------------------- plan de fases
$runP10 = $true
$runP20 = $true
$runP30 = $false

if ($Mode -eq 'web') {
    $runP10 = $false
    $runP20 = $false
    $runP30 = $true
}
elseif ($Mode -eq 'completo') {
    $runP30 = $true
}
else {
    # rapido: la web solo si el operador dio destinos
    if ($webTargets.Count -gt 0) { $runP30 = $true }
}

if ($runP30 -and $webTargets.Count -eq 0) {
    Write-Log -Level WARN -Message 'Modo web sin destinos configurados: no hay nada que auditar. Edite engine\config\settings.json o pase -Targets.'
    $runP30 = $false
    if ($Mode -eq 'web') {
        Add-Finding -Id 'WEB-NOTGT' -Severity 'Medium' -Category 'Web' `
            -Title 'Sin destinos web configurados' `
            -Detail 'Se solicito el modo web pero la lista de destinos esta vacia.' `
            -Remediation 'Anada al menos un destino en engine\config\settings.json ("web.targets") o use -Targets "https://sitio.com".'
    }
}

# ---------------------------------------------------------------- ejecucion
Invoke-Checked -Name 'Fase-P00-Preflight' -Block {
    if (Get-Command Invoke-Preflight -ErrorAction SilentlyContinue) { Invoke-Preflight -Ctx $ctx }
    else { Write-Log -Level WARN -Message 'P00-Preflight no disponible' }
}

if ($runP10) {
    Invoke-Checked -Name 'Fase-P10-Sistema' -Block {
        if (Get-Command Invoke-Sistema -ErrorAction SilentlyContinue) { Invoke-Sistema -Ctx $ctx }
        else { Write-Log -Level WARN -Message 'P10-Sistema no disponible' }
    }
}

if ($runP20) {
    Invoke-Checked -Name 'Fase-P20-Red' -Block {
        if (Get-Command Invoke-Red -ErrorAction SilentlyContinue) { Invoke-Red -Ctx $ctx }
        else { Write-Log -Level WARN -Message 'P20-Red no disponible' }
    }
}

if ($runP30) {
    Invoke-Checked -Name 'Fase-P30-Web' -Block {
        if (Get-Command Invoke-Web -ErrorAction SilentlyContinue) { Invoke-Web -Ctx $ctx }
        else { Write-Log -Level WARN -Message 'P30-Web no disponible' }
    }
}

Invoke-Checked -Name 'Fase-P40-Hardening' -Block {
    if (Get-Command Invoke-Hardening -ErrorAction SilentlyContinue) { Invoke-Hardening -Ctx $ctx }
    else { Write-Log -Level WARN -Message 'P40-Hardening no disponible' }
}

# Contenedor mutable: los scriptblocks no escriben en el scope del llamador
$out = @{ Html = ''; Findings = '' }

Invoke-Checked -Name 'Fase-P50-Informe' -Block {
    if (Get-Command Invoke-Informe -ErrorAction SilentlyContinue) {
        $res = Invoke-Informe -Ctx $ctx
        if ($res) {
            if ($res.PSObject.Properties['Html'] -and $res.Html)         { $out['Html']     = [string]$res.Html }
            if ($res.PSObject.Properties['Findings'] -and $res.Findings) { $out['Findings'] = [string]$res.Findings }
        }
    }
    else { Write-Log -Level WARN -Message 'P50-Informe no disponible' }
}
$informePath  = [string]$out['Html']
$findingsPath = [string]$out['Findings']

$totalSw.Stop()

# ---------------------------------------------------------------- resumen
$score = $null
$postureMain = $null
if (Get-Command Get-AuditScore -ErrorAction SilentlyContinue) {
    $score = Get-AuditScore -Findings $ctx.Findings
    # Postura: lectura principal del resumen (ADENDA 1.0.2).
    if ([string]$ctx.Mode -eq 'web') {
        $postureMain = Get-AuditScore -Findings $ctx.Findings -Formula posture
    }
    else {
        $postureMain = Get-AuditScore -Findings $ctx.Findings -Formula posture -ExcludeCategories @('Web', 'Preflight')
    }
}
else {
    $score = [PSCustomObject]@{ value = 0; grade = '?'; critical = 0; high = 0; medium = 0; low = 0; info = 0 }
}

if (-not $informePath)  { $informePath  = Join-Path $ctx.EvidenceDir 'informe.html' }
if (-not $findingsPath) { $findingsPath = Join-Path $ctx.EvidenceDir 'findings.json' }

Write-Host ''
Write-Host '===============================================================' -ForegroundColor DarkCyan
Write-Host '                        RESUMEN                                ' -ForegroundColor Cyan
Write-Host '===============================================================' -ForegroundColor DarkCyan
Write-Host ('  Postura       : {0}/100  (grado {1})  <- lectura principal' -f $postureMain.value, $postureMain.grade) -ForegroundColor $(if ($postureMain.value -ge 80) { 'Green' } elseif ($postureMain.value -ge 60) { 'Yellow' } else { 'Red' })
Write-Host ('  Cumplimiento  : {0}/100  (grado {1})  formula del contrato' -f $score.value, $score.grade)
Write-Host ('  Critical      : {0}' -f $score.critical) -ForegroundColor $(if ($score.critical -gt 0) { 'Magenta' } else { 'Gray' })
Write-Host ('  High          : {0}' -f $score.high)     -ForegroundColor $(if ($score.high -gt 0) { 'Red' } else { 'Gray' })
Write-Host ('  Medium        : {0}' -f $score.medium)   -ForegroundColor $(if ($score.medium -gt 0) { 'Yellow' } else { 'Gray' })
Write-Host ('  Low           : {0}' -f $score.low)
Write-Host ('  Info          : {0}' -f $score.info)
Write-Host ('  Checks fallidos: {0}' -f $ctx.Errors)
Write-Host ('  Duracion      : {0} s' -f [math]::Round($totalSw.Elapsed.TotalSeconds, 1))
Write-Host ('  Informe       : {0}' -f $informePath) -ForegroundColor Cyan
Write-Host ('  Datos         : {0}' -f $findingsPath) -ForegroundColor Cyan
Write-Host '===============================================================' -ForegroundColor DarkCyan
Write-Host ''

if ($Apply) {
    $rb = [string]$ctx.Hardening['RollbackFile']
    if ($rb) {
        Write-Host ('  Rollback      : {0}' -f $rb) -ForegroundColor Yellow
        Write-Host '  Para revertir: ejecute Rollback-Hardening.ps1 desde esa carpeta.' -ForegroundColor Yellow
        Write-Host ''
    }
}

# ---------------------------------------------------------------- resultado
return [PSCustomObject]@{
    AuditId      = $ctx.Id
    Score        = $score.value
    Grade        = $score.grade
    Critical     = $score.critical
    High         = $score.high
    Medium       = $score.medium
    Low          = $score.low
    Info         = $score.info
    Errors       = $ctx.Errors
    DurationS    = [math]::Round($totalSw.Elapsed.TotalSeconds, 1)
    EvidenceDir  = $ctx.EvidenceDir
    HtmlReport   = $informePath
    FindingsJson = $findingsPath
    Applied      = [bool]$Apply
    Fatal        = $fatal
}
