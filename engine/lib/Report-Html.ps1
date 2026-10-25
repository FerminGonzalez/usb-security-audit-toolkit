<#
  Report-Html.ps1
  USB Security Audit Toolkit - generador de informe HTML self-contained
  Dueno: UNIDAD C | Version: 1.0.0
  PowerShell 5.1 compatible

  Expone:
    Get-AuditScore  -Findings <list> [-Formula contract|posture]
                    -> PSCustomObject @{value;grade;critical;high;medium;low;info}
    New-HtmlReport  -Ctx <object>        -> escribe <EvidenceDir>\informe.html

  Get-AuditScore es el UNICO dueno de las dos escalas del toolkit:
    contract (25/12/5/1) -> cumplimiento estricto, se publica en findings.json
    posture  (20/6/3/1, techo C con Critical) -> lectura principal del informe
  ADENDA 1.0.2 del contrato.
#>

function ConvertTo-HtmlSafe {
    param([string] $Text)
    if ($null -eq $Text) { return '' }
    $s = [string]$Text
    $s = $s -replace '&', '&amp;'
    $s = $s -replace '<', '&lt;'
    $s = $s -replace '>', '&gt;'
    $s = $s -replace '"', '&quot;'
    $s = $s -replace "'", '&#39;'
    return $s
}

# Lee una propiedad de un objeto de contexto que puede ser PSCustomObject o hashtable
function Get-CtxProp {
    param($Object, [string] $Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) {
            $v = $Object[$Name]
            if ($null -ne $v) { return $v }
        }
        return $Default
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -ne $p -and $null -ne $p.Value) { return $p.Value }
    return $Default
}

# Normaliza a hashtable un mapa que puede venir como hashtable (motor) o como
# PSCustomObject (findings.json releido por Build-Report). Las claves de un
# hashtable de PowerShell se comparan sin distinguir mayusculas, de modo que
# 'Applied' y 'applied' son la misma clave.
function ConvertTo-AuditMap {
    param($Object)
    $map = @{}
    if ($null -eq $Object) { return $map }
    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($k in $Object.Keys) { $map[[string]$k] = $Object[$k] }
        return $map
    }
    foreach ($p in $Object.PSObject.Properties) { $map[[string]$p.Name] = $p.Value }
    return $map
}

function Get-AuditScore {
    param(
        $Findings,
        # Filtro opcional por categoria. Sin argumentos el calculo es
        # exactamente el del contrato (seccion 3).
        [string[]] $ExcludeCategories = @(),
        [string[]] $IncludeCategories = @(),
        # 'contract' = formula del contrato 25/12/5/1 (findings.json).
        # 'posture'  = escala calibrada 20/6/3/1 con techo C si hay Critical
        #              (ADENDA 1.0.2). Es la lectura principal del informe.
        [ValidateSet('contract', 'posture')]
        [string] $Formula = 'contract'
    )

    $c = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
    if ($null -ne $Findings) {
        foreach ($f in @($Findings)) {
            if ($null -eq $f) { continue }
            $cat = [string](Get-CtxProp $f 'category' '')
            if ($ExcludeCategories.Count -gt 0 -and ($ExcludeCategories -contains $cat)) { continue }
            if ($IncludeCategories.Count -gt 0 -and -not ($IncludeCategories -contains $cat)) { continue }
            $sev = [string](Get-CtxProp $f 'severity' 'Info')
            if ($c.ContainsKey($sev)) { $c[$sev] = $c[$sev] + 1 }
            else { $c['Info'] = $c['Info'] + 1 }
        }
    }

    if ($Formula -eq 'posture') {
        $value = 100 - ($c.Critical * 20) - ($c.High * 6) - ($c.Medium * 3) - ($c.Low * 1)
    }
    else {
        $value = 100 - ($c.Critical * 25) - ($c.High * 12) - ($c.Medium * 5) - ($c.Low * 1)
    }
    if ($value -lt 0) { $value = 0 }

    $grade = 'F'
    if ($value -ge 90) { $grade = 'A' }
    elseif ($value -ge 80) { $grade = 'B' }
    elseif ($value -ge 70) { $grade = 'C' }
    elseif ($value -ge 60) { $grade = 'D' }

    # Un Critical no puede producir un grado bueno aunque el numero salga alto.
    if ($Formula -eq 'posture' -and $c.Critical -gt 0) {
        if ($grade -eq 'A' -or $grade -eq 'B') { $grade = 'C' }
    }

    return [PSCustomObject]@{
        value    = [int]$value
        grade    = $grade
        critical = $c.Critical
        high     = $c.High
        medium   = $c.Medium
        low      = $c.Low
        info     = $c.Info
    }
}

function New-HtmlReport {
    param([Parameter(Mandatory = $true)] $Ctx)

    # ---------------------------------------------------------------- lectura defensiva
    $id        = [string](Get-CtxProp $Ctx 'Id' 'AUDITORIA')
    $hostName  = [string](Get-CtxProp $Ctx 'Host' (Get-CtxProp $Ctx 'host' 'EQUIPO'))
    $osDesc    = [string](Get-CtxProp $Ctx 'Os' (Get-CtxProp $Ctx 'os' 'Desconocido'))
    $osFamily  = [string](Get-CtxProp $Ctx 'OsFamily' (Get-CtxProp $Ctx 'os_family' 'Windows'))
    $mode      = [string](Get-CtxProp $Ctx 'Mode' (Get-CtxProp $Ctx 'mode' 'rapido'))
    $apply     = [bool](Get-CtxProp $Ctx 'Apply' (Get-CtxProp $Ctx 'apply' $false))
    $operator  = [string](Get-CtxProp $Ctx 'Operator' (Get-CtxProp $Ctx 'operator' ''))
    $version   = [string](Get-CtxProp $Ctx 'ToolVersion' (Get-CtxProp $Ctx 'tool_version' '1.0.0'))
    $evDir     = [string](Get-CtxProp $Ctx 'EvidenceDir' '')
    $elevated  = Get-CtxProp $Ctx 'Elevated' (Get-CtxProp $Ctx 'elevated' $null)
    $started   = Get-CtxProp $Ctx 'Started' (Get-CtxProp $Ctx 'started' $null)
    $finished  = Get-CtxProp $Ctx 'Finished' (Get-CtxProp $Ctx 'finished' $null)
    $duration  = Get-CtxProp $Ctx 'DurationS' (Get-CtxProp $Ctx 'duration_s' $null)
    $findings  = Get-CtxProp $Ctx 'Findings' (Get-CtxProp $Ctx 'findings' @())
    $metrics   = Get-CtxProp $Ctx 'Metrics' (Get-CtxProp $Ctx 'metrics' @{})
    $hardening = Get-CtxProp $Ctx 'Hardening' (Get-CtxProp $Ctx 'hardening' @{})

    # El motor entrega hashtables; findings.json releido entrega PSCustomObject
    # con claves en minuscula. Se normaliza aqui para que ambas rutas generen
    # exactamente el mismo informe.
    $metrics   = ConvertTo-AuditMap $metrics
    $hardening = ConvertTo-AuditMap $hardening

    if ($null -eq $findings) { $findings = @() }
    $all = @($findings) | Where-Object { $null -ne $_ }

    $score = Get-AuditScore -Findings $all

    # ---------------------------------------------------------------- postura
    # Lectura principal (ADENDA 1.0.2). En modo web el equipo no se audita:
    # excluir Web daria 100/A sobre cero hallazgos, una conformidad inventada.
    $primaryLabel = 'Este equipo'
    $primary = Get-AuditScore -Findings $all -Formula posture -ExcludeCategories @('Web', 'Preflight')
    if ($mode -eq 'web') {
        $primaryLabel = 'Sitios auditados'
        $primary = Get-AuditScore -Findings $all -Formula posture
    }

    if ($null -eq $duration) {
        if ($started -and $finished) {
            try { $duration = [int](([datetime]$finished) - ([datetime]$started)).TotalSeconds }
            catch { $duration = 0 }
        }
        else { $duration = 0 }
    }

    $startedText = ''
    if ($started) {
        try { $startedText = ([datetime]$started).ToString('yyyy-MM-dd HH:mm:ss') } catch { $startedText = [string]$started }
    }

    if ($null -eq $elevated) { $elevatedText = 'no determinado' }
    elseif ([bool]$elevated) { $elevatedText = 'SI' }
    else { $elevatedText = 'NO (solo lectura parcial)' }

    $applyText = 'No (diagnostico)'
    if ($apply) { $applyText = 'SI (hardening aplicado)' }

    # ---------------------------------------------------------------- colores
    $gradeColor = '#c0392b'
    switch ($primary.grade) {
        'A' { $gradeColor = '#1e8449' }
        'B' { $gradeColor = '#2471a3' }
        'C' { $gradeColor = '#b9770e' }
        'D' { $gradeColor = '#ca6f1e' }
        'F' { $gradeColor = '#c0392b' }
    }

    $sevColor = @{
        Critical = '#8e1b3f'
        High     = '#c0392b'
        Medium   = '#b9770e'
        Low      = '#2471a3'
        Info     = '#5d6d7e'
    }
    $sevBg = @{
        Critical = '#f5d0d8'
        High     = '#fadbd8'
        Medium   = '#fdebd0'
        Low      = '#d6eaf8'
        Info     = '#eaeded'
    }

    # ---------------------------------------------------------------- orden de findings
    $order = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    $sorted = @()
    foreach ($s in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
        $sorted += @($all | Where-Object { [string](Get-CtxProp $_ 'severity' 'Info') -eq $s } | Sort-Object { [string](Get-CtxProp $_ 'id' '') })
    }

    # ---------------------------------------------------------------- bloques HTML
    $sb = New-Object System.Text.StringBuilder

    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="es">')
    [void]$sb.AppendLine('<head>')
    [void]$sb.AppendLine('<meta charset="utf-8">')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine(('<title>Informe de auditoria - {0}</title>' -f (ConvertTo-HtmlSafe $hostName)))
    [void]$sb.AppendLine(@'
<style>
  :root{--ink:#1b2631;--muted:#5d6d7e;--line:#d5dbdb;--bg:#ffffff;--soft:#f4f6f7;}
  *{box-sizing:border-box}
  body{margin:0;padding:0;background:var(--soft);color:var(--ink);
       font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
       font-size:14px;line-height:1.5}
  .wrap{max-width:1080px;margin:0 auto;padding:24px 18px 60px}
  header.top{background:#fff;border:1px solid var(--line);border-radius:10px;padding:22px 24px;margin-bottom:18px}
  h1{margin:0 0 4px;font-size:21px;letter-spacing:.2px}
  .sub{color:var(--muted);font-size:13px}
  .grid{display:flex;flex-wrap:wrap;gap:14px;margin-top:18px}
  .meta{flex:1 1 150px;min-width:140px;border-left:3px solid var(--line);padding-left:10px}
  .meta b{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);font-weight:600}
  .meta span{font-size:14px;font-weight:600}
  .badge{display:flex;align-items:center;gap:16px;background:#fff;border:1px solid var(--line);
         border-radius:10px;padding:18px 24px;margin-bottom:18px}
  .score{display:flex;align-items:baseline;gap:6px}
  .score .n{font-size:44px;font-weight:800;line-height:1}
  .score .g{font-size:22px;font-weight:700;padding:2px 10px;border-radius:6px;color:#fff}
  .score .of{color:var(--muted);font-size:13px}
  .cards{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:20px}
  .card{flex:1 1 110px;min-width:104px;background:#fff;border:1px solid var(--line);border-radius:8px;
        padding:12px 14px;border-top:4px solid var(--line)}
  .card b{display:block;font-size:24px;line-height:1.1}
  .card span{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);font-weight:600}
  section{background:#fff;border:1px solid var(--line);border-radius:10px;padding:20px 22px;margin-bottom:18px}
  h2{margin:0 0 14px;font-size:16px;text-transform:uppercase;letter-spacing:.8px;color:var(--muted)}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);
     border-bottom:2px solid var(--line);padding:8px 8px;font-weight:700}
  td{border-bottom:1px solid #eef1f2;padding:9px 8px;vertical-align:top}
  tr:last-child td{border-bottom:none}
  code{font-family:ui-monospace,Consolas,"Courier New",monospace;font-size:12px;
       background:#f4f6f7;padding:1px 5px;border-radius:4px;word-break:break-word}
  .pill{display:inline-block;padding:2px 9px;border-radius:99px;font-size:11px;font-weight:700;
        text-transform:uppercase;letter-spacing:.5px;white-space:nowrap}
  details{border:1px solid var(--line);border-radius:8px;margin-bottom:10px;overflow:hidden}
  details>summary{cursor:pointer;padding:11px 14px;background:var(--soft);font-weight:700;font-size:13px;
                  list-style:none}
  details>summary::-webkit-details-marker{display:none}
  details>summary:before{content:"\25B8";display:inline-block;width:16px;transition:transform .15s}
  details[open]>summary:before{transform:rotate(90deg)}
  .cnt{color:var(--muted);font-weight:600}
  .empty{color:var(--muted);font-style:italic;padding:6px 0}
  .filters{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px}
  .filters button{border:1px solid var(--line);background:#fff;border-radius:6px;padding:5px 11px;
                  font-size:12px;font-weight:600;cursor:pointer;color:var(--ink)}
  .filters button:hover{background:var(--soft)}
  .filters button.on{background:var(--ink);color:#fff;border-color:var(--ink)}
  footer{color:var(--muted);font-size:12px;text-align:center;padding:22px 10px 0;line-height:1.7}
  .warn{background:#fdf2e9;border:1px solid #f5cba7;border-radius:8px;padding:12px 14px;margin-bottom:14px;font-size:13px}
  .ok{background:#eafaf1;border:1px solid #abebc6;border-radius:8px;padding:12px 14px;margin-bottom:14px;font-size:13px}
  @media print{
    body{background:#fff;font-size:11px}
    .wrap{max-width:none;padding:0}
    section,header.top,.badge,.card{break-inside:avoid;border-color:#bbb}
    .filters{display:none}
    details{border:none}
    details>summary{background:none}
    details:not([open])>*{display:revert!important}
    a{color:#000;text-decoration:none}
  }
</style>
'@)
    [void]$sb.AppendLine('</head>')
    [void]$sb.AppendLine('<body>')
    [void]$sb.AppendLine('<div class="wrap">')

    # ---------------------------------------------------------------- cabecera
    [void]$sb.AppendLine('<header class="top">')
    [void]$sb.AppendLine(('<h1>Informe de auditoria de seguridad</h1>'))
    $subLine = '<div class="sub">{0} &middot; {1} &middot; auditoria <code>{2}</code></div>' `
        -f (ConvertTo-HtmlSafe $hostName), (ConvertTo-HtmlSafe $osDesc), (ConvertTo-HtmlSafe $id)
    [void]$sb.AppendLine($subLine)
    [void]$sb.AppendLine('<div class="grid">')
    [void]$sb.AppendLine(('<div class="meta"><b>Fecha</b><span>{0}</span></div>' -f (ConvertTo-HtmlSafe $startedText)))
    [void]$sb.AppendLine(('<div class="meta"><b>Duracion</b><span>{0} s</span></div>' -f [int]$duration))
    [void]$sb.AppendLine(('<div class="meta"><b>Modo</b><span>{0}</span></div>' -f (ConvertTo-HtmlSafe $mode)))
    [void]$sb.AppendLine(('<div class="meta"><b>Hardening</b><span>{0}</span></div>' -f (ConvertTo-HtmlSafe $applyText)))
    [void]$sb.AppendLine(('<div class="meta"><b>Elevado</b><span>{0}</span></div>' -f (ConvertTo-HtmlSafe $elevatedText)))
    if ($operator) {
        [void]$sb.AppendLine(('<div class="meta"><b>Operador</b><span>{0}</span></div>' -f (ConvertTo-HtmlSafe $operator)))
    }
    [void]$sb.AppendLine(('<div class="meta"><b>Plataforma</b><span>{0}</span></div>' -f (ConvertTo-HtmlSafe $osFamily)))
    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine('</header>')

    # ---------------------------------------------------------------- score
    [void]$sb.AppendLine('<div class="badge">')
    $badgeLine = '<div class="score"><span class="n" style="color:{0}">{1}</span><span class="g" style="background:{0}">{2}</span><span class="of">/ 100 &middot; postura</span></div>' `
        -f $gradeColor, $primary.value, (ConvertTo-HtmlSafe $primary.grade)
    [void]$sb.AppendLine($badgeLine)
    $formulaLine = '<div class="sub" style="margin-left:auto;text-align:right">Postura: 100 &minus; 20&times;Critical &minus; 6&times;High &minus; 3&times;Medium &minus; 1&times;Low (techo C con Critical)<br>{0} &middot; cumplimiento del contrato: {1}/100 {2} &middot; {3} hallazgo(s)</div>' `
        -f (ConvertTo-HtmlSafe $primaryLabel), $score.value, (ConvertTo-HtmlSafe $score.grade), $all.Count
    [void]$sb.AppendLine($formulaLine)
    [void]$sb.AppendLine('</div>')

    # ---------------------------------------------------------------- tarjetas
    [void]$sb.AppendLine('<div class="cards">')
    foreach ($s in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
        $n = 0
        switch ($s) {
            'Critical' { $n = $score.critical }
            'High'     { $n = $score.high }
            'Medium'   { $n = $score.medium }
            'Low'      { $n = $score.low }
            'Info'     { $n = $score.info }
        }
        $cardLine = '<div class="card" style="border-top-color:{0}"><b style="color:{0}">{1}</b><span>{2}</span></div>' `
            -f $sevColor[$s], $n, $s
        [void]$sb.AppendLine($cardLine)
    }
    [void]$sb.AppendLine('</div>')

    # ---------------------------------------------------------------- postura por dominio
    $posture = Get-CtxProp $Ctx 'Posture' $null
    if ($null -ne $posture) {
        $pHost = Get-CtxProp $posture 'Host' $null
        $pWeb = @(Get-CtxProp $posture 'Web' @())
        if ($null -ne $pHost -or $pWeb.Count -gt 0) {
            [void]$sb.AppendLine('<section>')
            [void]$sb.AppendLine('<h2>Postura por dominio</h2>')
            [void]$sb.AppendLine('<p class="muted">Postura = base 100 &minus; 20&times;Critical &minus; 6&times;High &minus; 3&times;Medium &minus; 1&times;Low; con algun Critical el grado no pasa de C. Aqui se separa la postura del equipo auditado de la de cada sitio web, porque son objetos distintos y no deberian promediarse. El cumplimiento estricto del contrato (25/12/5/1) se muestra en el badge como dato secundario.</p>')
            [void]$sb.AppendLine('<table><thead><tr><th>Objeto</th><th style="width:90px">Puntos</th><th style="width:70px">Grado</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr></thead><tbody>')
            if ($null -ne $pHost) {
                $hv = [int](Get-CtxProp $pHost 'value' 0)
                $hg = ConvertTo-HtmlSafe ([string](Get-CtxProp $pHost 'grade' '?'))
                $hColor = $gradeColor
                $rowHost = '<tr><td><b>Este equipo</b> <span class="muted">(sin hallazgos Web ni de preflight)</span></td><td><b>{0}</b></td><td><span class="pill" style="background:{1}">{2}</span></td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>' -f `
                    $hv, $hColor, $hg, (Get-CtxProp $pHost 'critical' 0), (Get-CtxProp $pHost 'high' 0), (Get-CtxProp $pHost 'medium' 0), (Get-CtxProp $pHost 'low' 0)
                [void]$sb.AppendLine($rowHost)
            }
            foreach ($w in $pWeb) {
                if ($null -eq $w) { continue }
                $rowWeb = '<tr><td>Sitio <code>{0}</code></td><td><b>{1}</b></td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>' -f `
                    (ConvertTo-HtmlSafe ([string](Get-CtxProp $w 'target' ''))), (Get-CtxProp $w 'value' 0), (ConvertTo-HtmlSafe ([string](Get-CtxProp $w 'grade' '?'))), (Get-CtxProp $w 'critical' 0), (Get-CtxProp $w 'high' 0), (Get-CtxProp $w 'medium' 0), (Get-CtxProp $w 'low' 0)
                [void]$sb.AppendLine($rowWeb)
            }
            [void]$sb.AppendLine('</tbody></table>')
            [void]$sb.AppendLine('</section>')
        }
    }

    # ---------------------------------------------------------------- aviso de alcance
    if (-not $apply) {
        [void]$sb.AppendLine('<div class="ok"><b>Modo diagnostico.</b> Esta ejecucion NO modifico la configuracion del equipo. Las remediaciones propuestas quedan a decision del operador; el hardening se aplica unicamente con <code>-Apply</code>.</div>')
    }
    else {
        [void]$sb.AppendLine('<div class="warn"><b>Hardening aplicado.</b> Se modifico la configuracion del equipo. Use el archivo de rollback indicado abajo para revertir los cambios si es necesario.</div>')
    }

    # ---------------------------------------------------------------- findings
    [void]$sb.AppendLine('<section>')
    [void]$sb.AppendLine(('<h2>Hallazgos ({0})</h2>' -f $all.Count))

    if ($all.Count -eq 0) {
        [void]$sb.AppendLine('<div class="empty">No se registraron hallazgos.</div>')
    }
    else {
        [void]$sb.AppendLine('<div class="filters">')
        [void]$sb.AppendLine('<button type="button" class="on" data-sev="all">Todos</button>')
        foreach ($s in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
            [void]$sb.AppendLine(('<button type="button" data-sev="{0}">{0}</button>' -f $s))
        }
        [void]$sb.AppendLine('</div>')

        $categories = @()
        foreach ($f in $sorted) {
            $cat = [string](Get-CtxProp $f 'category' 'General')
            if ($categories -notcontains $cat) { $categories += $cat }
        }

        foreach ($cat in $categories) {
            $catFindings = @($sorted | Where-Object { [string](Get-CtxProp $_ 'category' 'General') -eq $cat })
            $openAttr = ''
            if ($catFindings.Count -gt 0 -and [string](Get-CtxProp $catFindings[0] 'severity' 'Info') -eq 'Critical') {
                $openAttr = ' open'
            }
            $catSummary = '<details{0}><summary>{1} <span class="cnt">({2})</span></summary>' -f $openAttr, (ConvertTo-HtmlSafe $cat), $catFindings.Count
            [void]$sb.AppendLine($catSummary)
            [void]$sb.AppendLine('<table><thead><tr><th style="width:88px">Id</th><th style="width:78px">Sev.</th><th>Titulo</th><th>Detalle</th><th>Remediacion</th></tr></thead><tbody>')

            foreach ($f in $catFindings) {
                $sev = [string](Get-CtxProp $f 'severity' 'Info')
                $fid = [string](Get-CtxProp $f 'id' '')
                $ttl = [string](Get-CtxProp $f 'title' '')
                $det = [string](Get-CtxProp $f 'detail' '')
                $rem = [string](Get-CtxProp $f 'remediation' '')
                $evd = [string](Get-CtxProp $f 'evidence' '')

                $detHtml = ConvertTo-HtmlSafe $det
                if ($evd) {
                    $detHtml = $detHtml + '<br><span class="cnt">evidencia: <code>' + (ConvertTo-HtmlSafe $evd) + '</code></span>'
                }
                if (-not $rem) { $rem = '&mdash;' } else { $rem = '<code>' + (ConvertTo-HtmlSafe $rem) + '</code>' }

                $rowFmt = '<tr data-sev="{0}"><td><code>{1}</code></td><td><span class="pill" style="background:{2};color:{3}">{0}</span></td><td>{4}</td><td>{5}</td><td>{6}</td></tr>'
                $rowLine = $rowFmt -f (ConvertTo-HtmlSafe $sev), (ConvertTo-HtmlSafe $fid), $sevBg[$sev], $sevColor[$sev], (ConvertTo-HtmlSafe $ttl), $detHtml, $rem
                [void]$sb.AppendLine($rowLine)
            }
            [void]$sb.AppendLine('</tbody></table></details>')
        }
        [void]$sb.AppendLine(@'
<script>
(function(){
  var btns=document.querySelectorAll('.filters button');
  for(var i=0;i<btns.length;i++){
    btns[i].addEventListener('click',function(){
      var sev=this.getAttribute('data-sev');
      for(var j=0;j<btns.length;j++){btns[j].className='';}
      this.className='on';
      var rows=document.querySelectorAll('tr[data-sev]');
      for(var k=0;k<rows.length;k++){
        rows[k].style.display=(sev==='all'||rows[k].getAttribute('data-sev')===sev)?'':'none';
      }
      var ds=document.querySelectorAll('details');
      for(var m=0;m<ds.length;m++){ds[m].open=true;}
    });
  }
})();
</script>
'@)
    }
    [void]$sb.AppendLine('</section>')

    # ---------------------------------------------------------------- hardening
    if ($null -ne $hardening -and $hardening -is [System.Collections.IDictionary]) {
        $applied = @()
        $skipped = @()
        $pending = @()
        $rollback = ''
        $remediation = ''
        if ($hardening.Contains('Applied'))  { $applied = @($hardening['Applied']) }
        if ($hardening.Contains('Skipped'))  { $skipped = @($hardening['Skipped']) }
        if ($hardening.Contains('Pending'))  { $pending = @($hardening['Pending']) }
        if ($hardening.Contains('RollbackFile')) { $rollback = [string]$hardening['RollbackFile'] }
        if ($hardening.Contains('RemediationFile')) { $remediation = [string]$hardening['RemediationFile'] }

        $applied  = @($applied  | Where-Object { $_ })
        $skipped  = @($skipped  | Where-Object { $_ })
        $pending  = @($pending  | Where-Object { $_ })

        if ($applied.Count + $skipped.Count + $pending.Count -gt 0) {
            [void]$sb.AppendLine('<section>')
            [void]$sb.AppendLine('<h2>Hardening</h2>')
            [void]$sb.AppendLine('<table><thead><tr><th style="width:150px">Estado</th><th>Controles</th></tr></thead><tbody>')
            [void]$sb.AppendLine(('<tr><td><span class="pill" style="background:#d5f5e3;color:#196f3d">Aplicado</span></td><td>{0}</td></tr>' -f (Get-HardeningCell $applied)))
            [void]$sb.AppendLine(('<tr><td><span class="pill" style="background:#fdebd0;color:#b9770e">Pendiente</span></td><td>{0}</td></tr>' -f (Get-HardeningCell $pending)))
            [void]$sb.AppendLine(('<tr><td><span class="pill" style="background:#eaeded;color:#5d6d7e">Omitido</span></td><td>{0}</td></tr>' -f (Get-HardeningCell $skipped)))
            [void]$sb.AppendLine('</tbody></table>')
            if ($rollback) {
                [void]$sb.AppendLine(('<div class="warn" style="margin-top:14px">Rollback disponible: <code>{0}</code> &mdash; ejecute <code>Rollback-Hardening.ps1</code> junto a ese archivo para revertir.</div>' -f (ConvertTo-HtmlSafe $rollback)))
            }
            if ($remediation) {
                [void]$sb.AppendLine(('<div class="warn" style="margin-top:14px">Remediacion por comandos: <code>{0}</code> &mdash; ejecutelo como administrador para aplicar solo los controles pendientes sin usar PowerShell como motor.</div>' -f (ConvertTo-HtmlSafe $remediation)))
            }
            [void]$sb.AppendLine('</section>')
        }
    }

    # ---------------------------------------------------------------- metricas
    # El contrato exige registrar duraciones (<Name>_ms) y marcadores de
    # evidencia en Metrics; en el informe visible se separan porque son
    # diagnostico de la herramienta, no postura del equipo.
    if ($null -ne $metrics -and $metrics -is [System.Collections.IDictionary] -and $metrics.Count -gt 0) {
        $publicKeys = @()
        $diagKeys = @()
        foreach ($k in ($metrics.Keys | Sort-Object)) {
            $ks = [string]$k
            if ($ks -like '*_ms' -or $ks -like 'evidence_*' -or $ks -like 'web_target_*') { $diagKeys += $ks } else { $publicKeys += $ks }
        }

        [void]$sb.AppendLine('<section>')
        [void]$sb.AppendLine(('<h2>Metricas ({0})</h2>' -f $publicKeys.Count))
        [void]$sb.AppendLine('<table><thead><tr><th>Metrica</th><th style="width:170px">Valor</th></tr></thead><tbody>')
        foreach ($k in $publicKeys) {
            $rowMetric = '<tr><td><code>{0}</code></td><td>{1}</td></tr>' -f (ConvertTo-HtmlSafe ([string]$k)), (ConvertTo-HtmlSafe ([string]$metrics[$k]))
            [void]$sb.AppendLine($rowMetric)
        }
        [void]$sb.AppendLine('</tbody></table>')

        if ($diagKeys.Count -gt 0) {
            [void]$sb.AppendLine(('<details><summary>Diagnostico de la herramienta ({0} medidas de tiempo y evidencia)</summary>' -f $diagKeys.Count))
            [void]$sb.AppendLine('<table><thead><tr><th>Metrica</th><th style="width:170px">Valor</th></tr></thead><tbody>')
            foreach ($k in $diagKeys) {
                $rowDiag = '<tr><td><code>{0}</code></td><td>{1}</td></tr>' -f (ConvertTo-HtmlSafe ([string]$k)), (ConvertTo-HtmlSafe ([string]$metrics[$k]))
                [void]$sb.AppendLine($rowDiag)
            }
            [void]$sb.AppendLine('</tbody></table></details>')
        }
        [void]$sb.AppendLine('</section>')
    }

    # ---------------------------------------------------------------- pie
    [void]$sb.AppendLine('<footer>')
    [void]$sb.AppendLine(('USB Security Audit Toolkit v{0} &middot; generado el {1}<br>' -f (ConvertTo-HtmlSafe $version), (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')))
    [void]$sb.AppendLine('Herramienta defensiva. Utilicela unicamente en equipos propios o con autorizacion escrita del responsable.<br>')
    [void]$sb.AppendLine(('Auditoria <code>{0}</code> &middot; evidencia en <code>{1}</code>' -f (ConvertTo-HtmlSafe $id), (ConvertTo-HtmlSafe $evDir)))
    [void]$sb.AppendLine('</footer>')

    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine('</body>')
    [void]$sb.AppendLine('</html>')

    # ---------------------------------------------------------------- escritura
    if (-not $evDir) {
        throw 'No se puede escribir el informe: el contexto no tiene EvidenceDir.'
    }
    if (-not (Test-Path -LiteralPath $evDir)) {
        New-Item -ItemType Directory -Path $evDir -Force | Out-Null
    }
    $path = Join-Path $evDir 'informe.html'
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($path, $sb.ToString(), $enc)
    return $path
}

function Get-HardeningCell {
    param($Items)
    if ($null -eq $Items) { return '&mdash;' }
    $list = @($Items | Where-Object { $_ })
    if ($list.Count -eq 0) { return '&mdash;' }
    $parts = @()
    foreach ($i in $list) { $parts += ('<code>' + (ConvertTo-HtmlSafe ([string]$i)) + '</code>') }
    return ($parts -join ' ')
}
