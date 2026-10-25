<#
  Common.ps1
  USB Security Audit Toolkit - nucleo compartido
  Dueno: UNIDAD A | Version: 1.0.0
  PowerShell 5.1 compatible (sin ?, sin ??, sin -Parallel, sin class)

  Provee: contexto global, logging, findings, evidencia, metricas y acceso
  al registro con captura automatica del valor previo (para rollback).
#>

$script:AuditToolVersion = '1.0.0'
$script:LogBuffer        = New-Object System.Collections.ArrayList
$script:LogPath          = $null
$script:Ctx              = $null
$script:FindingIds       = New-Object System.Collections.ArrayList

$script:SeverityOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }

# ------------------------------------------------------------------ utilidades

function Format-Size {
    param([Parameter(Mandatory = $true)] [long] $Bytes)
    if ($Bytes -ge 1TB) { return ('{0:N2} TB' -f ($Bytes / 1TB)) }
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N2} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N1} KB' -f ($Bytes / 1KB)) }
    return ('{0} B' -f $Bytes)
}

function New-TempFile {
    param([string] $Suffix = '.tmp')
    $name = 'usbaudit-' + [Guid]::NewGuid().ToString('N') + $Suffix
    return (Join-Path $env:TEMP $name)
}

function Test-Admin {
    try {
        $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    }
    catch { return $false }
}

# Recursive JSON/PSCustomObject -> hashtable (necesario para fusionar defaults)
function ConvertTo-AuditHashtable {
    param($InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $h = @{}
        foreach ($k in @($InputObject.Keys)) { $h[$k] = ConvertTo-AuditHashtable $InputObject[$k] }
        return $h
    }
    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        $h = @{}
        foreach ($p in $InputObject.PSObject.Properties) { $h[$p.Name] = ConvertTo-AuditHashtable $p.Value }
        return $h
    }
    if ($InputObject -is [string]) { return $InputObject }
    if ($InputObject -is [System.Collections.IEnumerable]) {
        $a = New-Object System.Collections.ArrayList
        foreach ($i in $InputObject) { [void]$a.Add((ConvertTo-AuditHashtable $i)) }
        return $a
    }
    return $InputObject
}

# --------------------------------------------------------------------- logging

function Write-Log {
    param(
        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR', 'CHECK')]
        [string] $Level = 'INFO',
        [string] $Message = ''
    )
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line  = '{0} [{1}] {2}' -f $stamp, $Level, $Message

    if ($script:LogPath) {
        try { Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8 -ErrorAction Stop }
        catch { }
    }
    else {
        [void]$script:LogBuffer.Add($line)
    }

    $color = 'Gray'
    switch ($Level) {
        'INFO'  { $color = 'Cyan' }
        'OK'    { $color = 'Green' }
        'WARN'  { $color = 'Yellow' }
        'ERROR' { $color = 'Red' }
        'CHECK' { $color = 'DarkGray' }
    }
    try { Write-Host $line -ForegroundColor $color } catch { }
}

# -------------------------------------------------------------------- metricas

function Add-Metric {
    param([string] $Name, $Value)
    if (-not $script:Ctx) { return }
    if ($script:Ctx.Metrics -is [hashtable]) { $script:Ctx.Metrics[$Name] = $Value }
    else {
        try { $script:Ctx.Metrics | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force } catch { }
    }
}

# -------------------------------------------------------------------- findings

function Add-Finding {
    param(
        [string] $Id = '',
        [string] $Severity = 'Info',
        [string] $Category = 'General',
        [string] $Title = '',
        [string] $Detail = '',
        [string] $Remediation = '',
        [string] $Evidence = ''
    )
    $sev = 'Info'
    if ($Severity -and $script:SeverityOrder.ContainsKey($Severity)) {
        $sev = $Severity
    }
    elseif ($Severity) {
        Write-Log -Level WARN -Message ("Severidad invalida '{0}' en el finding '{1}'; se fuerza Info" -f $Severity, $Id)
    }

    if (-not $Id) { $Id = 'GEN-' + [Guid]::NewGuid().ToString('N').Substring(0, 6) }

    # Id unico en toda la ejecucion
    if ($script:FindingIds.Contains($Id)) {
        $n = 2
        while ($script:FindingIds.Contains(('{0}-{1}' -f $Id, $n))) { $n++ }
        $Id = '{0}-{1}' -f $Id, $n
    }
    [void]$script:FindingIds.Add($Id)

    $finding = [PSCustomObject]@{
        id          = $Id
        severity    = $sev
        category    = $Category
        title       = $Title
        detail      = $Detail
        remediation = $Remediation
        evidence    = $Evidence
        status      = 'open'
    }
    # ArrayList vacio es FALSY en PowerShell: hay que comparar contra $null,
    # no evaluar la coleccion como booleano (bug que descartaba todos los hallazgos).
    if ($null -ne $script:Ctx) {
        if ($null -ne $script:Ctx.Findings) { [void]$script:Ctx.Findings.Add($finding) }
    }
}

# ------------------------------------------------------------------ ejecucion

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)] [string] $Name,
        [Parameter(Mandatory = $true)] [scriptblock] $Block
    )
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Write-Log -Level CHECK -Message ('-> {0}' -f $Name)
    try {
        & $Block | Out-Null
    }
    catch {
        if ($script:Ctx) { $script:Ctx.Errors = [int]$script:Ctx.Errors + 1 }
        $msg = $_.Exception.Message
        Write-Log -Level WARN -Message ('{0} no se pudo ejecutar: {1}' -f $Name, $msg)
        $safeId = 'ERR-' + ($Name -replace '[^A-Za-z0-9]', '')
        Add-Finding -Id $safeId -Severity 'Info' -Category 'Interno' `
            -Title ('Check omitido: {0}' -f $Name) `
            -Detail $msg `
            -Remediation 'Ninguna. El check no pudo completarse y la auditoria continuo.'
    }
    finally {
        $sw.Stop()
        Add-Metric -Name ($Name + '_ms') -Value $sw.ElapsedMilliseconds
    }
}

# ------------------------------------------------------------------- evidencia

function Write-Evidence {
    param(
        [Parameter(Mandatory = $true)] [string] $Name,
        $Data
    )
    if (-not $script:Ctx) { throw 'El contexto de auditoria no esta inicializado.' }
    if (-not (Test-Path -LiteralPath $script:Ctx.EvidenceDir)) {
        New-Item -ItemType Directory -Path $script:Ctx.EvidenceDir -Force | Out-Null
    }
    $path = Join-Path $script:Ctx.EvidenceDir $Name
    if ($Data -is [string]) {
        $text = $Data
    }
    else {
        $text = ($Data | ConvertTo-Json -Depth 8)
    }
    if ($null -eq $text) { $text = 'null' }
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($path, $text, $enc)
    Add-Metric -Name ('evidence_' + $Name) -Value 'ok'
    return $path
}

# --------------------------------------------------------------------- registro

function Get-RegValue {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $Name,
        $Default = $null
    )
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $Default }
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        $value = $item.$Name
        if ($null -eq $value) { return $Default }
        return $value
    }
    catch { return $Default }
}

function Reset-PsV2StateCache {
    $script:__PsV2Cache = $null
}

function Get-PsV2State {
    # Estado de la caracteristica opcional MicrosoftWindowsPowerShellV2 SIN DISM.
    # Get-WindowsOptionalFeature -Online puede tardar mas de dos minutos y aun
    # asi fallar con elevacion; Win32_OptionalFeature y el registro responden en
    # milisegundos con la misma informacion.
    # Devuelve @{ State = 'Enabled'|'Disabled'|'Absent'|'Unknown'; Source = '...' }
    if ($null -ne $script:__PsV2Cache) { return $script:__PsV2Cache }

    $res = @{ State = 'Unknown'; Source = 'sin fuente consultable' }

    foreach ($feature in @('MicrosoftWindowsPowerShellV2', 'MicrosoftWindowsPowerShellV2Root')) {
        try {
            $of = @(Get-CimInstance -ClassName Win32_OptionalFeature -Filter ("Name='{0}'" -f $feature) -ErrorAction Stop)
            if ($of.Count -eq 0) { continue }
            $inst = $of[0].InstallState
            if ($null -eq $inst) { continue }
            $state = 'Unknown'
            switch ([int]$inst) {
                1 { $state = 'Enabled' }
                2 { $state = 'Disabled' }
                3 { $state = 'Absent' }
            }
            if ($state -ne 'Unknown') {
                $res = @{ State = $state; Source = ('Win32_OptionalFeature:{0} InstallState={1}' -f $feature, [int]$inst) }
                break
            }
        }
        catch { }
    }

    if ($res.State -eq 'Unknown') {
        # La clave PowerShellEngine solo existe si el motor 1.0/2.0 esta instalado.
        if (-not (Test-Path 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine')) {
            $res = @{ State = 'Absent'; Source = 'registro: PowerShellEngine ausente' }
        }
        else {
            $res = @{ State = 'Unknown'; Source = 'registro: PowerShellEngine presente, caracteristica no consultable' }
        }
    }

    $script:__PsV2Cache = $res
    return $res
}

function Get-HardeningOriginal {
    param(
        [string] $ControlId = 'GEN',
        [string] $Path = '',
        [string] $Name = '',
        [string] $Kind = 'Reg',
        [hashtable] $Payload = @{}
    )
    if (-not $script:Ctx) { return $null }

    if (-not $script:Ctx.Hardening.ContainsKey('Originals')) {
        $script:Ctx.Hardening['Originals'] = @{}
    }
    $key = '{0}|{1}|{2}|{3}' -f $ControlId, $Kind, $Path, $Name
    if ($script:Ctx.Hardening.Originals.ContainsKey($key)) {
        return $script:Ctx.Hardening.Originals[$key]
    }

    $orig = @{
        Key       = $key
        ControlId = $ControlId
        Kind      = $Kind
        Path      = $Path
        Name      = $Name
        Existed   = $false
        Value     = $null
        ValueType = $null
        Payload   = $Payload
    }

    if ($Kind -eq 'Reg' -and $Path) {
        if (Test-Path -LiteralPath $Path) {
            try {
                $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
                $orig.Existed = $true
                $orig.Value   = $item.$Name
                try { $orig.ValueType = (Get-Item -LiteralPath $Path).GetValueKind($Name).ToString() }
                catch { $orig.ValueType = $null }
            }
            catch { $orig.Existed = $false }
        }
    }

    $script:Ctx.Hardening.Originals[$key] = $orig
    return $orig
}

function Set-RegValueChecked {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $Name,
        [Parameter(Mandatory = $true)] $Value,
        [ValidateSet('DWord', 'String', 'QWord', 'ExpandString', 'MultiString', 'Binary')]
        [string] $Type = 'DWord',
        [string] $ControlId = 'GEN'
    )
    [void](Get-HardeningOriginal -ControlId $ControlId -Path $Path -Name $Name -Kind 'Reg')

    $current = Get-RegValue -Path $Path -Name $Name -Default $null
    if ($null -ne $current -and ([string]$current) -eq ([string]$Value)) {
        return $false   # idempotente: ya estaba bien
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
    }
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
    Write-Log -Level OK -Message ('  {0}: {1} :: {2} = {3}' -f $ControlId, $Path, $Name, $Value)
    return $true
}

# -------------------------------------------------------------------- contexto

function Initialize-AuditContext {
    param(
        [ValidateSet('rapido', 'completo', 'web')] [string] $Mode = 'rapido',
        [switch] $Apply,
        [string] $RootPath,
        [string] $Operator = ''
    )

    if (-not $RootPath) { $RootPath = (Get-Location).Path }
    try { $RootPath = (Resolve-Path -LiteralPath $RootPath).Path }
    catch { throw ('Ruta raiz invalida: {0}' -f $RootPath) }

    $hostName = $env:COMPUTERNAME
    if (-not $hostName) {
        try { $hostName = [System.Net.Dns]::GetHostName() } catch { $hostName = 'EQUIPO' }
    }
    $safeHost = ($hostName.ToUpper() -replace '[^A-Z0-9\-]', '-')

    $now  = Get-Date
    $id   = '{0}-{1}' -f $safeHost, $now.ToString('yyyyMMdd-HHmmss')
    $evDir = Join-Path (Join-Path $RootPath 'evidencia') $id
    if (-not (Test-Path -LiteralPath $evDir)) {
        New-Item -ItemType Directory -Path $evDir -Force | Out-Null
    }

    # --- sistema operativo
    $osDesc   = 'Windows'
    $osFamily = 'Windows'
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $osDesc = ('{0} (build {1})' -f $os.Caption.Trim(), $os.BuildNumber)
    }
    catch {
        try { $osDesc = 'Windows ' + [System.Environment]::OSVersion.Version.ToString() } catch { }
    }

    # --- configuracion
    $defaults = @{
        tool_version = $script:AuditToolVersion
        web          = @{ targets = @(); timeout_s = 15 }
        network      = @{
            dns_test_hosts = @('www.google.com', 'www.cloudflare.com', 'www.microsoft.com')
            ping_count     = 4
        }
        hardening    = @{ skip_controls = @() }
        report       = @{ organization = '' }
    }

    $cfg = @{}
    $cfgPath = Join-Path (Join-Path (Join-Path $RootPath 'engine') 'config') 'settings.json'
    if (Test-Path -LiteralPath $cfgPath) {
        try {
            $raw = Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8
            $loaded = ConvertTo-AuditHashtable ($raw | ConvertFrom-Json)
            if ($loaded -is [hashtable]) { $cfg = $loaded }
        }
        catch { $cfg = @{} }
    }
    foreach ($k in $defaults.Keys) {
        if (-not $cfg.ContainsKey($k)) { $cfg[$k] = $defaults[$k] }
    }
    if (-not $cfg.ContainsKey('web')) { $cfg['web'] = $defaults['web'] }
    if (-not ($cfg['web'] -is [hashtable])) { $cfg['web'] = $defaults['web'] }
    if (-not $cfg['web'].ContainsKey('targets')) { $cfg['web']['targets'] = @() }
    if (-not $cfg['web'].ContainsKey('timeout_s')) { $cfg['web']['timeout_s'] = 15 }
    if (-not $cfg.ContainsKey('network') -or -not ($cfg['network'] -is [hashtable])) { $cfg['network'] = $defaults['network'] }
    if (-not $cfg['network'].ContainsKey('dns_test_hosts')) { $cfg['network']['dns_test_hosts'] = $defaults['network']['dns_test_hosts'] }
    if (-not $cfg['network'].ContainsKey('ping_count')) { $cfg['network']['ping_count'] = 4 }
    if (-not $cfg.ContainsKey('hardening') -or -not ($cfg['hardening'] -is [hashtable])) { $cfg['hardening'] = $defaults['hardening'] }
    if (-not $cfg['hardening'].ContainsKey('skip_controls')) { $cfg['hardening']['skip_controls'] = @() }

    if (-not $Operator) {
        if ($env:USERNAME) { $Operator = $env:USERNAME } else { $Operator = 'operador' }
    }

    $script:Ctx = [PSCustomObject]@{
        Id          = $id
        Host        = $safeHost
        Os          = $osDesc
        OsFamily    = $osFamily
        Mode        = $Mode
        Apply       = [bool]$Apply
        Started     = $now
        Finished    = $null
        DurationS   = 0
        Score       = $null
        Posture     = $null
        RootPath    = $RootPath
        EvidenceDir = $evDir
        Operator    = $Operator
        Findings    = (New-Object System.Collections.ArrayList)
        Metrics     = @{}
        Hardening   = @{
            Applied      = (New-Object System.Collections.ArrayList)
            Skipped      = (New-Object System.Collections.ArrayList)
            Pending      = (New-Object System.Collections.ArrayList)
            RollbackFile = ''
            RemediationFile = ''
            Originals    = @{}
        }
        Config      = $cfg
        ToolVersion = $script:AuditToolVersion
        Elevated    = (Test-Admin)
        Errors      = 0
    }

    $script:LogPath  = Join-Path $evDir 'engine.log'
    $script:FindingIds = New-Object System.Collections.ArrayList
    if ($script:LogBuffer.Count -gt 0) {
        try { Set-Content -LiteralPath $script:LogPath -Value $script:LogBuffer -Encoding UTF8 } catch { }
        $script:LogBuffer.Clear()
    }

    Write-Log -Level INFO -Message ('Contexto creado: {0}' -f $id)
    Write-Log -Level INFO -Message ('Evidencia en: {0}' -f $evDir)
    return $script:Ctx
}
