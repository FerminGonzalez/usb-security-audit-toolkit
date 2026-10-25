<#
.SYNOPSIS
    Genera un informe HTML a partir de una carpeta de evidencia, Windows o Linux.

.DESCRIPTION
    Lee <EvidenceDir>\findings.json (esquema compartido de la seccion 3 del
    contrato), construye el objeto de contexto que espera New-HtmlReport y
    escribe informe.html en la propia carpeta de evidencia.

    El generador HTML y el calculo del score viven en engine\lib\Report-Html.ps1
    (propiedad de otro modulo del toolkit). Este script NO los reimplementa:
    solo los consume.

.PARAMETER EvidenceDir
    Carpeta que contiene findings.json. Tipicamente evidencia\<ID>.

.PARAMETER OutFile
    Ruta opcional donde copiar el HTML generado.

.EXAMPLE
    .\Build-Report.ps1 -EvidenceDir ..\evidencia\DESKTOP-20261025-143012

.EXAMPLE
    .\Build-Report.ps1 -EvidenceDir D:\evidencia\srv-01 -OutFile C:\temp\srv-01.html
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$EvidenceDir,

    [Parameter(Position = 1)]
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'

function Fail {
    param([string]$Message, [int]$Code = 1)
    Write-Host ''
    Write-Host '[ERROR] ' -ForegroundColor Red -NoNewline
    Write-Host $Message
    Write-Host ''
    exit $Code
}

function Get-Field {
    param(
        $Object,
        [string]$Name,
        $Default = $null
    )
    if ($null -eq $Object) { return $Default }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $Default }
    if ($null -eq $prop.Value) { return $Default }
    return $prop.Value
}

function ConvertTo-AuditDate {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value }
    $parsed = [datetime]::MinValue
    if ([datetime]::TryParse([string]$Value, [ref]$parsed)) { return $parsed }
    return [string]$Value
}

function ConvertTo-AuditBool {
    param($Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return $Value }
    $text = ([string]$Value).Trim().ToLowerInvariant()
    if ($text -eq 'true' -or $text -eq '1' -or $text -eq 'yes' -or $text -eq 'si') { return $true }
    return $false
}

# ---------------------------------------------------------------------
# 1. Localizar el generador HTML (unico dueno de New-HtmlReport y del score)
# ---------------------------------------------------------------------
$libPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\engine\lib\Report-Html.ps1'))
if (-not (Test-Path -LiteralPath $libPath -PathType Leaf)) {
    Fail ("No se encontro el generador de informes:`n  $libPath`n`n" +
          "El toolkit esta incompleto. Restaure engine\lib\Report-Html.ps1 " +
          "desde la copia original del USB.")
}
try {
    . $libPath
} catch {
    Fail "No se pudo cargar Report-Html.ps1: $($_.Exception.Message)"
}
if (-not (Get-Command -Name 'New-HtmlReport' -ErrorAction SilentlyContinue)) {
    Fail "Report-Html.ps1 no define la funcion New-HtmlReport. Toolkit incompleto."
}

# ---------------------------------------------------------------------
# 2. Validar carpeta y findings.json
# ---------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $EvidenceDir)) {
    Fail "No existe la carpeta de evidencia: $EvidenceDir"
}
if (-not (Test-Path -LiteralPath $EvidenceDir -PathType Container)) {
    Fail "La ruta de evidencia no es una carpeta: $EvidenceDir"
}
$evidencePath = (Resolve-Path -LiteralPath $EvidenceDir).Path

$jsonPath = Join-Path $evidencePath 'findings.json'
if (-not (Test-Path -LiteralPath $jsonPath -PathType Leaf)) {
    Fail "No se encontro findings.json en: $evidencePath"
}

$raw = $null
try {
    $raw = Get-Content -LiteralPath $jsonPath -Raw -Encoding UTF8
} catch {
    Fail "No se pudo leer findings.json: $($_.Exception.Message)"
}
if ([string]::IsNullOrWhiteSpace($raw)) {
    Fail "findings.json esta vacio: $jsonPath"
}

try {
    $data = $raw | ConvertFrom-Json
} catch {
    Fail "findings.json no es JSON valido: $($_.Exception.Message)"
}
if ($null -eq $data) {
    Fail "findings.json no contiene un objeto JSON."
}

foreach ($required in @('tool', 'audit', 'findings')) {
    if ($null -eq $data.PSObject.Properties[$required]) {
        Fail ("findings.json no cumple el esquema: falta la seccion '$required'.`n" +
              "Se esperaban las claves tool, audit y findings.")
    }
}

$tool = $data.tool
$audit = $data.audit

$toolName = [string](Get-Field -Object $tool -Name 'name' -Default 'USB Security Audit Toolkit')
$toolVersion = [string](Get-Field -Object $tool -Name 'version' -Default '1.0.0')

$auditId = [string](Get-Field -Object $audit -Name 'id' -Default $null)
if ([string]::IsNullOrWhiteSpace($auditId)) {
    $auditId = [System.IO.Path]::GetFileName($evidencePath)
}
$hostName = [string](Get-Field -Object $audit -Name 'host' -Default 'desconocido')
$osText = [string](Get-Field -Object $audit -Name 'os' -Default 'desconocido')
$osFamily = [string](Get-Field -Object $audit -Name 'os_family' -Default 'desconocido')
$modeText = [string](Get-Field -Object $audit -Name 'mode' -Default 'desconocido')
$applyBool = ConvertTo-AuditBool (Get-Field -Object $audit -Name 'apply' -Default $false)
$startedValue = ConvertTo-AuditDate (Get-Field -Object $audit -Name 'started' -Default $null)
$finishedValue = ConvertTo-AuditDate (Get-Field -Object $audit -Name 'finished' -Default $null)
$durationValue = Get-Field -Object $audit -Name 'duration_s' -Default $null
$operatorName = [string](Get-Field -Object $audit -Name 'operator' -Default '')
$elevatedBool = ConvertTo-AuditBool (Get-Field -Object $audit -Name 'elevated' -Default $false)

# ---------------------------------------------------------------------
# 3. Findings, metricas y hardening con valores por defecto defensivos
# ---------------------------------------------------------------------
$rawFindings = Get-Field -Object $data -Name 'findings' -Default @()
$findings = @()
if ($null -ne $rawFindings) {
    foreach ($item in @($rawFindings)) {
        if ($null -ne $item) { $findings += $item }
    }
}

$metrics = Get-Field -Object $data -Name 'metrics' -Default ([PSCustomObject]@{})

$hardeningRaw = Get-Field -Object $data -Name 'hardening' -Default $null
$hardening = [PSCustomObject]@{
    Applied      = @()
    Skipped      = @()
    RollbackFile = ''
}
if ($null -ne $hardeningRaw) {
    $appliedRaw = Get-Field -Object $hardeningRaw -Name 'applied' -Default @()
    $skippedRaw = Get-Field -Object $hardeningRaw -Name 'skipped' -Default @()
    if ($null -ne $appliedRaw) { $hardening.Applied = @($appliedRaw) }
    if ($null -ne $skippedRaw) { $hardening.Skipped = @($skippedRaw) }
    $pendingRaw = Get-Field -Object $hardeningRaw -Name 'pending' -Default @()
    if ($null -ne $pendingRaw) {
        $hardening | Add-Member -NotePropertyName 'Pending' -NotePropertyValue @($pendingRaw) -Force
    }
    $rb = Get-Field -Object $hardeningRaw -Name 'rollback_file' -Default ''
    if ($null -ne $rb) { $hardening.RollbackFile = [string]$rb }
}

# Postura por dominio: se conserva tal cual la calculo el motor, para que el
# informe regenerado muestre las mismas cifras que el original.
$postureRaw = Get-Field -Object $data -Name 'posture' -Default $null

# Score: siempre desde Get-AuditScore, nunca recalculado aqui.
$scoreObject = $null
if (Get-Command -Name 'Get-AuditScore' -ErrorAction SilentlyContinue) {
    try {
        $scoreObject = Get-AuditScore -Findings $findings
    } catch {
        Write-Host "[WARN] Get-AuditScore fallo, el informe calculara el score: $($_.Exception.Message)" -ForegroundColor Yellow
        $scoreObject = $null
    }
}

# ---------------------------------------------------------------------
# 4. Contexto compatible con New-HtmlReport (lectura defensiva, adenda 9.6)
# ---------------------------------------------------------------------
$ctx = [PSCustomObject]@{
    Id          = $auditId
    Host        = $hostName
    Os          = $osText
    OsFamily    = $osFamily
    Mode        = $modeText
    Apply       = $applyBool
    Started     = $startedValue
    Finished    = $finishedValue
    Findings    = $findings
    Metrics     = $metrics
    Hardening   = $hardening
    ToolVersion = $toolVersion
    EvidenceDir = $evidencePath
}
if ($null -ne $scoreObject) {
    $ctx | Add-Member -NotePropertyName 'Score' -NotePropertyValue $scoreObject -Force
}
if ($null -ne $postureRaw) {
    $ctx | Add-Member -NotePropertyName 'Posture' -NotePropertyValue $postureRaw -Force
}
if ($null -ne $durationValue) {
    $ctx | Add-Member -NotePropertyName 'Duration' -NotePropertyValue $durationValue -Force
}
if (-not [string]::IsNullOrWhiteSpace($operatorName)) {
    $ctx | Add-Member -NotePropertyName 'Operator' -NotePropertyValue $operatorName -Force
}
if (-not [string]::IsNullOrWhiteSpace($toolName)) {
    $ctx | Add-Member -NotePropertyName 'ToolName' -NotePropertyValue $toolName -Force
}
$ctx | Add-Member -NotePropertyName 'Elevated' -NotePropertyValue $elevatedBool -Force

# ---------------------------------------------------------------------
# 5. Generar el HTML
# ---------------------------------------------------------------------
$defaultHtml = Join-Path $evidencePath 'informe.html'
$htmlPath = $defaultHtml

try {
    $result = New-HtmlReport -Ctx $ctx
} catch {
    Fail "New-HtmlReport fallo al generar el informe: $($_.Exception.Message)"
}

if ($result -is [string] -and -not [string]::IsNullOrWhiteSpace($result) -and (Test-Path -LiteralPath $result -PathType Leaf)) {
    $htmlPath = (Resolve-Path -LiteralPath $result).Path
}

if (-not (Test-Path -LiteralPath $htmlPath -PathType Leaf)) {
    $candidate = Get-ChildItem -LiteralPath $evidencePath -Filter '*.html' -File -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTime -Descending |
                 Select-Object -First 1
    if ($null -ne $candidate) {
        $htmlPath = $candidate.FullName
    } else {
        Fail ("New-HtmlReport no genero ningun archivo HTML.`n" +
              "Se esperaba: $defaultHtml")
    }
}

Write-Host ''
Write-Host 'USB Security Audit Toolkit - generador de informes' -ForegroundColor Cyan
Write-Host '---------------------------------------------------'
Write-Host ("  Equipo     : {0}" -f $hostName)
Write-Host ("  Auditoria  : {0} ({1})" -f $auditId, $osFamily)
Write-Host ("  Sistema    : {0}" -f $osText)
Write-Host ("  Modo       : {0}{1}" -f $modeText, $(if ($applyBool) { ' + aplicar hardening' } else { '' }))
Write-Host ("  Hallazgos  : {0}" -f $findings.Count)
if ($null -ne $scoreObject) {
    Write-Host ("  Score      : {0} / 100  (grado {1})" -f $scoreObject.value, $scoreObject.grade)
}
Write-Host ("  Origen     : {0}" -f $jsonPath)
Write-Host ("  Informe    : {0}" -f $htmlPath)

# ---------------------------------------------------------------------
# 6. Copia opcional a OutFile
# ---------------------------------------------------------------------
if (-not [string]::IsNullOrWhiteSpace($OutFile)) {
    try {
        $outDir = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($OutFile))
        if (-not [string]::IsNullOrWhiteSpace($outDir) -and -not (Test-Path -LiteralPath $outDir)) {
            New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        }
        Copy-Item -LiteralPath $htmlPath -Destination $OutFile -Force
        Write-Host ("  Copia      : {0}" -f ([System.IO.Path]::GetFullPath($OutFile)))
    } catch {
        Fail "No se pudo copiar el informe a ${OutFile}: $($_.Exception.Message)"
    }
}

Write-Host ''
exit 0
