<#
  P50-Informe.ps1
  USB Security Audit Toolkit - cierre de auditoria y serializacion
  Dueno: UNIDAD C | Version: 1.0.0
  PowerShell 5.1 compatible

  Responsabilidades:
    - Fijar Finished y DurationS en el contexto
    - Calcular el score con Get-AuditScore (unico dueno de la formula)
    - Escribir findings.json con el esquema exacto de la seccion 3 del contrato
    - Escribir resumen.txt legible
    - Invocar New-HtmlReport
    - Devolver [PSCustomObject]@{ Html; Findings }
#>

function P50-EnsureLog {
    param($Ctx)
    # engine.log vive dentro de EvidenceDir desde Initialize-AuditContext.
    # Aqui solo se garantiza su existencia para que la evidencia sea autocontenida.
    $logPath = Join-Path $Ctx.EvidenceDir 'engine.log'
    if (-not (Test-Path -LiteralPath $logPath)) {
        try {
            $enc = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::WriteAllText($logPath, '', $enc)
        }
        catch { }
    }
    return $logPath
}

function Invoke-Informe {
    param([Parameter(Mandatory = $true)] $Ctx)

    Write-Log -Level INFO -Message 'INFORME: consolidando resultados'

    # ------------------------------------------------------------------ cierre
    $Ctx.Finished = Get-Date
    $durationS = 0
    try {
        $durationS = [int](($Ctx.Finished) - ([datetime]$Ctx.Started)).TotalSeconds
    }
    catch { $durationS = 0 }
    if ($durationS -lt 0) { $durationS = 0 }
    $Ctx.DurationS = $durationS

    $findings = @($Ctx.Findings | Where-Object { $null -ne $_ })

    # ------------------------------------------------------------------ score
    $score = $null
    if (Get-Command Get-AuditScore -ErrorAction SilentlyContinue) {
        $score = Get-AuditScore -Findings $findings
    }
    else {
        # Nunca deberia ocurrir: Report-Html.ps1 carga antes por orden alfabetico.
        Write-Log -Level WARN -Message 'Get-AuditScore no disponible; se usa score neutro.'
        $score = [PSCustomObject]@{ value = 0; grade = '?'; critical = 0; high = 0; medium = 0; low = 0; info = 0 }
    }
    $Ctx.Score = [int]$score.value

    # ------------------------------------------------------------------ postura
    # El score del contrato suma TODOS los hallazgos, incluidos los de sitios
    # web de terceros y los de preflight del operador. Para que el informe
    # distinga "como esta este equipo" de "como esta el sitio auditado", se
    # calcula ademas una postura por dominio con la escala calibrada
    # (ADENDA 1.0.2: 20/6/3/1, techo C con Critical).
    $hostScore = $null
    $webScores = @()
    try {
        # En modo web el equipo no se audita: excluir Web sobre cero hallazgos
        # daria 100/A, una conformidad que nadie comprobo.
        if ([string]$Ctx.Mode -ne 'web') {
            $hostScore = Get-AuditScore -Findings $findings -Formula posture -ExcludeCategories @('Web', 'Preflight')
        }

        $slugs = @()
        try {
            if ($Ctx.Metrics -is [System.Collections.IDictionary]) {
                foreach ($k in $Ctx.Metrics.Keys) {
                    $ks = [string]$k
                    if ($ks -like 'web_target_*') {
                        $s = $ks.Substring('web_target_'.Length)
                        if ($s -and ($slugs -notcontains $s)) { $slugs += $s }
                    }
                }
            }
        }
        catch { }
        foreach ($slug in $slugs) {
            $pattern = '^WEB-[A-Z0-9]+-' + [regex]::Escape($slug) + '$'
            $wf = @($findings | Where-Object { [string]$_.id -match $pattern })
            $ws = Get-AuditScore -Findings $wf -Formula posture
            $webScores += [PSCustomObject]@{
                target   = $slug
                value    = [int]$ws.value
                grade    = [string]$ws.grade
                critical = [int]$ws.critical
                high     = [int]$ws.high
                medium   = [int]$ws.medium
                low      = [int]$ws.low
                info     = [int]$ws.info
            }
        }
    }
    catch {
        Write-Log -Level WARN -Message ('No se pudo calcular la postura por dominio: {0}' -f $_.Exception.Message)
    }
    $Ctx.Posture = [PSCustomObject]@{
        Host = $hostScore
        Web  = $webScores
    }

    # ------------------------------------------------------------------ hardening
    $hApplied = @()
    $hSkipped = @()
    $hPending = @()
    $hRollback = ''
    $hRemediation = ''
    try {
        if ($Ctx.Hardening.ContainsKey('Applied')) { $hApplied = @($Ctx.Hardening['Applied'] | Where-Object { $_ }) }
        if ($Ctx.Hardening.ContainsKey('Skipped')) { $hSkipped = @($Ctx.Hardening['Skipped'] | Where-Object { $_ }) }
        if ($Ctx.Hardening.ContainsKey('Pending')) { $hPending = @($Ctx.Hardening['Pending'] | Where-Object { $_ }) }
        if ($Ctx.Hardening.ContainsKey('RollbackFile')) { $hRollback = [string]$Ctx.Hardening['RollbackFile'] }
        if ($Ctx.Hardening.ContainsKey('RemediationFile')) { $hRemediation = [string]$Ctx.Hardening['RemediationFile'] }
    }
    catch { }

    # ------------------------------------------------------------------ fechas
    $startedIso = ''
    $finishedIso = ''
    try { $startedIso = ([datetime]$Ctx.Started).ToString('o') } catch { $startedIso = [string]$Ctx.Started }
    try { $finishedIso = ([datetime]$Ctx.Finished).ToString('o') } catch { $finishedIso = [string]$Ctx.Finished }

    # ------------------------------------------------------------------ metrics
    $metricsOut = @{}
    try {
        if ($Ctx.Metrics -is [System.Collections.IDictionary]) {
            foreach ($k in $Ctx.Metrics.Keys) {
                $v = $Ctx.Metrics[$k]
                if ($null -eq $v) { $v = '' }
                $metricsOut[[string]$k] = $v
            }
        }
    }
    catch { }

    # ------------------------------------------------------------------ findings.json
    $findingsOut = @()
    foreach ($f in $findings) {
        $evidence = ''
        try { if ($f.PSObject.Properties['evidence']) { $evidence = [string]$f.evidence } } catch { }
        $status = 'open'
        try { if ($f.PSObject.Properties['status'] -and $f.status) { $status = [string]$f.status } } catch { }

        $findingsOut += [PSCustomObject]@{
            id          = [string]$f.id
            severity    = [string]$f.severity
            category    = [string]$f.category
            title       = [string]$f.title
            detail      = [string]$f.detail
            remediation = [string]$f.remediation
            evidence    = $evidence
            status      = $status
        }
    }

    $hostPostureOut = $null
    if ($null -ne $hostScore) {
        $hostPostureOut = [PSCustomObject]@{
            value    = [int]$hostScore.value
            grade    = [string]$hostScore.grade
            critical = [int]$hostScore.critical
            high     = [int]$hostScore.high
            medium   = [int]$hostScore.medium
            low      = [int]$hostScore.low
            info     = [int]$hostScore.info
        }
    }

    $doc = [PSCustomObject]@{
        tool     = [PSCustomObject]@{
            name    = 'USB Security Audit Toolkit'
            version = [string]$Ctx.ToolVersion
        }
        audit    = [PSCustomObject]@{
            id         = [string]$Ctx.Id
            host       = [string]$Ctx.Host
            os         = [string]$Ctx.Os
            os_family  = [string]$Ctx.OsFamily
            mode       = [string]$Ctx.Mode
            apply      = [bool]$Ctx.Apply
            started    = $startedIso
            finished   = $finishedIso
            duration_s = [int]$durationS
            operator   = [string]$Ctx.Operator
            elevated   = [bool]$Ctx.Elevated
        }
        score    = [PSCustomObject]@{
            value    = [int]$score.value
            grade    = [string]$score.grade
            critical = [int]$score.critical
            high     = [int]$score.high
            medium   = [int]$score.medium
            low      = [int]$score.low
            info     = [int]$score.info
        }
        findings = $findingsOut
        metrics  = $metricsOut
        posture  = [PSCustomObject]@{
            host = $hostPostureOut
            web  = $webScores
            note = 'posture usa una escala calibrada para lectura operativa (100 - 20xCritical - 6xHigh - 3xMedium - 1xLow, techo C si hay Critical). score conserva la formula del contrato (25/12/5/1) sobre todos los hallazgos. posture.host excluye Web y Preflight; en modo web es null porque el equipo no se audito.'
        }
        hardening = [PSCustomObject]@{
            applied          = $hApplied
            skipped          = $hSkipped
            pending          = $hPending
            rollback_file    = $hRollback
            remediation_file = $hRemediation
        }
    }

    $findingsPath = ''
    try {
        $json = $doc | ConvertTo-Json -Depth 8
        $findingsPath = Write-Evidence -Name 'findings.json' -Data $json
    }
    catch {
        Write-Log -Level WARN -Message ('No se pudo serializar findings.json: {0}' -f $_.Exception.Message)
        # Fallback: si los hallazgos no serializan, al menos no perdemos el informe.
        $minimal = [PSCustomObject]@{
            tool = [PSCustomObject]@{ name = 'USB Security Audit Toolkit'; version = [string]$Ctx.ToolVersion }
            audit = [PSCustomObject]@{ id = [string]$Ctx.Id; host = [string]$Ctx.Host; os_family = [string]$Ctx.OsFamily }
            score = [PSCustomObject]@{ value = [int]$score.value; grade = [string]$score.grade }
            findings = @()
            error = $_.Exception.Message
        }
        $findingsPath = Write-Evidence -Name 'findings.json' -Data ($minimal | ConvertTo-Json -Depth 8)
    }

    # ------------------------------------------------------------------ resumen.txt
    $modeText = [string]$Ctx.Mode
    $applyText = 'No (solo diagnostico)'
    if ($Ctx.Apply) { $applyText = 'SI (hardening aplicado)' }

    $lines = @()
    $lines += '==============================================================='
    $lines += '  USB SECURITY AUDIT TOOLKIT - RESUMEN DE LA AUDITORIA'
    $lines += '==============================================================='
    $lines += ('  Equipo        : {0}' -f $Ctx.Host)
    $lines += ('  Sistema       : {0}' -f $Ctx.Os)
    $lines += ('  Fecha         : {0}' -f (([datetime]$Ctx.Finished).ToString('yyyy-MM-dd HH:mm:ss')))
    $lines += ('  Modo          : {0}' -f $modeText)
    $lines += ('  Hardening     : {0}' -f $applyText)
    $lines += ('  Duracion      : {0} s' -f $durationS)
    $lines += '---------------------------------------------------------------'
    if ($null -ne $hostScore) {
        $lines += ('  POSTURA       : {0}/100  (grado {1})  <- lectura principal' -f $hostScore.value, $hostScore.grade)
    }
    else {
        $lines += '  POSTURA       : equipo no auditado en este modo'
    }
    foreach ($w in $webScores) {
        $lines += ('  Sitio         : {0} -> {1}/100 (grado {2})' -f $w.target, $w.value, $w.grade)
    }
    $lines += ('  CUMPLIMIENTO  : {0}/100  (grado {1})  formula del contrato' -f $score.value, $score.grade)
    $lines += ('  Critical      : {0}' -f $score.critical)
    $lines += ('  High          : {0}' -f $score.high)
    $lines += ('  Medium        : {0}' -f $score.medium)
    $lines += ('  Low           : {0}' -f $score.low)
    $lines += ('  Info          : {0}' -f $score.info)
    $lines += ('  Total         : {0} hallazgo(s)' -f $findings.Count)
    $lines += '---------------------------------------------------------------'
    if ($Ctx.Apply) {
        $lines += ('  Aplicados     : {0}' -f $(if ($hApplied.Count -gt 0) { $hApplied -join ', ' } else { 'ninguno' }))
        $lines += ('  Rollback      : {0}' -f $(if ($hRollback) { $hRollback } else { 'no generado' }))
    }
    else {
        $lines += ('  Pendientes    : {0}' -f $(if ($hPending.Count -gt 0) { $hPending -join ', ' } else { 'ninguno' }))
        $lines += '  Rollback      : no aplica (no se modifico el sistema)'
    }
    if ($hRemediation) {
        $lines += ('  Remedacion    : {0} (comandos para aplicar los pendientes)' -f $hRemediation)
    }
    $lines += '---------------------------------------------------------------'
    $lines += '  Hallazgos mas graves'
    $top = @($findings | Where-Object { $_.severity -in @('Critical', 'High') } | Select-Object -First 8)
    if ($top.Count -eq 0) {
        $lines += '  (ninguno de severidad Critical/High)'
    }
    else {
        foreach ($f in $top) {
            $lines += ('  [{0}] {1} - {2}' -f $f.severity, $f.id, $f.title)
        }
    }
    $lines += '==============================================================='
    $lines += '  El detalle completo esta en informe.html.'
    $lines += '==============================================================='

    $resumenText = ($lines -join "`r`n")
    [void](Write-Evidence -Name 'resumen.txt' -Data $resumenText)
    [void](P50-EnsureLog -Ctx $Ctx)

    # ------------------------------------------------------------------ HTML
    $htmlPath = ''
    if (Get-Command New-HtmlReport -ErrorAction SilentlyContinue) {
        try {
            $htmlPath = New-HtmlReport -Ctx $Ctx
        }
        catch {
            Write-Log -Level WARN -Message ('No se pudo generar el informe HTML: {0}' -f $_.Exception.Message)
            Add-Finding -Id 'INF-HTML' -Severity 'Low' -Category 'Informe' `
                -Title 'No se pudo generar el informe HTML' `
                -Detail $_.Exception.Message `
                -Remediation 'Use report\Build-Report.ps1 -EvidenceDir <carpeta> para regenerarlo a partir de findings.json.'
        }
    }
    else {
        Write-Log -Level WARN -Message 'New-HtmlReport no disponible: se omite el informe HTML.'
    }

    # ------------------------------------------------------------------ consola
    Write-Host ''
    Write-Host ('  Informe HTML  : {0}' -f $htmlPath) -ForegroundColor Cyan
    Write-Host ('  Datos JSON    : {0}' -f $findingsPath) -ForegroundColor Cyan
    if ($null -ne $hostScore) {
        Write-Host ('  Postura       : {0}/100 (grado {1})  lectura principal' -f $hostScore.value, $hostScore.grade) -ForegroundColor $(if ($hostScore.value -ge 80) { 'Green' } elseif ($hostScore.value -ge 60) { 'Yellow' } else { 'Red' })
    }
    else {
        Write-Host '  Postura       : equipo no auditado en este modo'
    }
    Write-Host ('  Cumplimiento  : {0}/100 (grado {1})  formula del contrato' -f $score.value, $score.grade)

    Write-Log -Level OK -Message ('INFORME: completado (score {0}/{1}, {2} hallazgos)' -f $score.value, $score.grade, $findings.Count)

    # El orquestador consume este objeto. Se devuelven rutas absolutas.
    return [PSCustomObject]@{
        Html     = $htmlPath
        Findings = $findingsPath
    }
}
