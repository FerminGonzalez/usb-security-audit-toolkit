<#
  P30-Web.ps1
  USB Security Audit Toolkit - auditoria de sitios web (externa)
  Dueno: UNIDAD B | Version: 1.0.0
  PowerShell 5.1 compatible

  No usa Invoke-WebRequest (motor IE, lento y fragil en PS 5.1).
  Usa SslStream para TLS y HttpWebRequest para HTTP.
  Un destino caido no impide auditar el siguiente.
#>

function P30-NormalizeUrl {
    param([string] $Url)
    $u = $Url.Trim()
    if ($u -notmatch '^[a-zA-Z][a-zA-Z0-9+\.\-]*://') { $u = 'https://' + $u }
    return $u
}

function P30-Slug {
    param([string] $Text)
    $s = $Text.ToLower()
    $s = $s -replace '^[a-z]+://', ''
    $s = $s -replace '[/\\:\?\=\&\#\.]', '-'
    $s = $s -replace '[^a-z0-9\-]', ''
    $s = $s -replace '-+', '-'
    $s = $s.Trim('-')
    if (-not $s) { $s = 'destino' }
    if ($s.Length -gt 40) { $s = $s.Substring(0, 40) }
    return $s
}

function P30-TlsProbe {
    param(
        [Parameter(Mandatory = $true)] [string] $HostName,
        [int] $Port = 443,
        [int] $TimeoutMs = 10000
    )

    $res = @{
        ok = $false; error = ''; protocol = ''; cipher = ''; key_exchange = ''; hash = ''
        subject = ''; issuer = ''; not_before = ''; not_after = ''; days_left = $null
        san_count = 0; san = @(); signature_algorithm = ''; thumbprint = ''
        chain_errors = ''; cert_valid = $false; tcp_ms = $null
    }

    $tcp = New-Object System.Net.Sockets.TcpClient
    $ssl = $null
    $sw = [Diagnostics.Stopwatch]::StartNew()

    try {
        $iar = $tcp.BeginConnect($HostName, $Port, $null, $null)
        $connected = $iar.AsyncWaitHandle.WaitOne($TimeoutMs)
        if (-not $connected) { throw ('Timeout conectando a {0}:{1}' -f $HostName, $Port) }
        $tcp.EndConnect($iar)
        $sw.Stop()
        $res.tcp_ms = [int]$sw.ElapsedMilliseconds

        $captured = New-Object psobject -Property @{ Errors = [System.Net.Security.SslPolicyErrors]::None; Text = '' }
        $callback = [System.Net.Security.RemoteCertificateValidationCallback]{
            param($sndr, $cert, $chain, $errors)
            $captured.Errors = $errors
            if ($errors -ne [System.Net.Security.SslPolicyErrors]::None) {
                $captured.Text = ([string]$errors)
            }
            return $true
        }

        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $callback)

        $proto = [Net.SecurityProtocolType]::Tls12
        $authenticated = $false
        $protoErrors = @()

        # Tls12 primero; si falla, probar el conjunto completo (para detectar servidores viejos)
        $attempts = @(
            [Net.SecurityProtocolType]::Tls12,
            ([Net.SecurityProtocolType]'Tls12,Tls11,Tls')
        )
        foreach ($p in $attempts) {
            try {
                $ssl.AuthenticateAsClient($HostName, $null, $p, $false)
                $authenticated = $true
                break
            }
            catch {
                $protoErrors += $_.Exception.Message
                if ($ssl) { try { $ssl.Dispose() } catch { } }
                $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $callback)
            }
        }

        if (-not $authenticated) {
            throw ('No se pudo negociar TLS: ' + ($protoErrors -join ' | '))
        }

        $res.ok = $true
        $res.protocol = [string]$ssl.SslProtocol
        try { $res.cipher = [string]$ssl.CipherAlgorithm } catch { }
        try { $res.hash = [string]$ssl.HashAlgorithm } catch { }
        try { $res.key_exchange = [string]$ssl.KeyExchangeAlgorithm } catch { }

        $cert2 = $null
        try { $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate) }
        catch { $cert2 = $null }

        if ($cert2) {
            $res.subject    = [string]$cert2.Subject
            $res.issuer     = [string]$cert2.Issuer
            $res.thumbprint = [string]$cert2.Thumbprint
            try { $res.not_before = $cert2.NotBefore.ToString('yyyy-MM-dd') } catch { }
            try {
                $res.not_after = $cert2.NotAfter.ToString('yyyy-MM-dd')
                $res.days_left = [int](($cert2.NotAfter - (Get-Date)).TotalDays)
            }
            catch { }
            try { $res.signature_algorithm = [string]$cert2.SignatureAlgorithm.FriendlyName } catch { }

            try {
                foreach ($ext in $cert2.Extensions) {
                    if ($ext.Oid.Value -eq '2.5.29.17') {
                        $sanText = $ext.Format($false)
                        $names = @()
                        foreach ($part in ($sanText -split ',')) {
                            $n = $part.Trim()
                            if ($n) { $names += $n }
                        }
                        $res.san = $names
                        $res.san_count = $names.Count
                        break
                    }
                }
            }
            catch { }
        }

        $res.chain_errors = [string]$captured.Text
        if ($captured.Errors -eq [System.Net.Security.SslPolicyErrors]::None) { $res.cert_valid = $true }
    }
    catch {
        $sw.Stop()
        $res.ok = $false
        $res.error = $_.Exception.Message
    }
    finally {
        if ($ssl) { try { $ssl.Dispose() } catch { } }
        try { $tcp.Close() } catch { }
    }

    return $res
}

function P30-HttpProbe {
    param(
        [Parameter(Mandatory = $true)] [string] $Url,
        [int] $TimeoutMs = 15000
    )

    $res = @{
        ok = $false; error = ''; status = $null; status_text = ''; final_url = ''; redirected = $false
        scheme = ''; server = ''; powered_by = ''; aspnet_version = ''
        headers = @{}; set_cookie = @(); body_length = $null; elapsed_ms = $null
    }

    $savedCallback = $null
    $resp = $null
    $sw = [Diagnostics.Stopwatch]::StartNew()

    try {
        try { $savedCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback } catch { }
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
            param($s, $c, $ch, $e)
            return $true
        }

        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method = 'GET'
        $req.Timeout = $TimeoutMs
        $req.ReadWriteTimeout = $TimeoutMs
        $req.AllowAutoRedirect = $true
        $req.MaximumAutomaticRedirections = 10
        $req.UserAgent = 'USB-AuditToolkit/1.0'
        $req.Accept = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        try { $req.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate } catch { }
        $req.KeepAlive = $false

        try {
            $resp = $req.GetResponse()
        }
        catch [System.Net.WebException] {
            $we = $_.Exception
            if ($we.Response) {
                $resp = $we.Response
            }
            else {
                throw
            }
        }

        $sw.Stop()
        $res.elapsed_ms = [int]$sw.ElapsedMilliseconds
        $res.ok = $true
        $res.status = [int]$resp.StatusCode
        $res.status_text = [string]$resp.StatusCode
        $res.final_url = [string]$resp.ResponseUri.AbsoluteUri
        $res.scheme = [string]$resp.ResponseUri.Scheme
        if ($res.final_url -ne $Url) { $res.redirected = $true }

        try { $res.server = [string]$resp.Headers['Server'] } catch { }
        try { $res.powered_by = [string]$resp.Headers['X-Powered-By'] } catch { }
        try { $res.aspnet_version = [string]$resp.Headers['X-AspNet-Version'] } catch { }

        $keys = @('Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options',
                  'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy',
                  'Cross-Origin-Opener-Policy', 'Cross-Origin-Embedder-Policy',
                  'Cross-Origin-Resource-Policy', 'X-XSS-Protection', 'Server',
                  'X-Powered-By', 'X-AspNet-Version', 'Set-Cookie')
        foreach ($k in $keys) {
            try {
                $vals = $resp.Headers.GetValues($k)
                if ($vals -and $vals.Count -gt 0) { $res.headers[$k] = ($vals -join ' ; ') }
            }
            catch { }
        }

        try {
            $cookieLines = @()
            $rawCookies = $resp.Headers.GetValues('Set-Cookie')
            if ($rawCookies) { $cookieLines = @($rawCookies) }
            $res.set_cookie = $cookieLines
        }
        catch { }

        try { $res.body_length = [long]$resp.ContentLength } catch { }
    }
    catch {
        $sw.Stop()
        $res.ok = $false
        $res.elapsed_ms = [int]$sw.ElapsedMilliseconds
        $res.error = $_.Exception.Message
    }
    finally {
        if ($resp) { try { $resp.Close() } catch { } }
        try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $savedCallback } catch { }
    }

    return $res
}

function P30-FetchSmall {
    param([string] $Url, [int] $TimeoutMs = 5000)
    $saved = $null
    $resp = $null
    try {
        try { $saved = [System.Net.ServicePointManager]::ServerCertificateValidationCallback } catch { }
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { param($s, $c, $ch, $e) return $true }
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method = 'GET'
        $req.Timeout = $TimeoutMs
        $req.ReadWriteTimeout = $TimeoutMs
        $req.AllowAutoRedirect = $true
        $req.UserAgent = 'USB-AuditToolkit/1.0'
        $req.KeepAlive = $false
        $resp = $req.GetResponse()
        return @{ ok = $true; status = [int]$resp.StatusCode; length = [long]$resp.ContentLength }
    }
    catch [System.Net.WebException] {
        if ($_.Exception.Response) {
            try { return @{ ok = $true; status = [int]$_.Exception.Response.StatusCode; length = $null } }
            catch { return @{ ok = $false; error = $_.Exception.Message } }
        }
        return @{ ok = $false; error = $_.Exception.Message }
    }
    catch {
        return @{ ok = $false; error = $_.Exception.Message }
    }
    finally {
        if ($resp) { try { $resp.Close() } catch { } }
        try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $saved } catch { }
    }
}

function Invoke-Web {
    param([Parameter(Mandatory = $true)] $Ctx)

    $targets = @()
    try {
        if ($Ctx.Config['web'] -and $Ctx.Config['web']['targets']) {
            $targets = @($Ctx.Config['web']['targets'] | Where-Object { $_ })
        }
    }
    catch { }

    if ($targets.Count -eq 0) {
        Write-Log -Level WARN -Message 'WEB: sin destinos configurados'
        return
    }

    $timeoutS = 15
    try {
        if ($Ctx.Config['web']['timeout_s']) { $timeoutS = [int]$Ctx.Config['web']['timeout_s'] }
    }
    catch { }
    if ($timeoutS -lt 5) { $timeoutS = 5 }
    if ($timeoutS -gt 30) { $timeoutS = 30 }

    Write-Log -Level INFO -Message ('WEB: auditando {0} destino(s)' -f $targets.Count)

    # ArrayList y no @(): dentro del scriptblock de Invoke-Checked la variable
    # local se copia, pero el objeto ArrayList se comparte por referencia.
    $results = New-Object System.Collections.ArrayList

    foreach ($rawTarget in $targets) {
        $url = P30-NormalizeUrl ([string]$rawTarget)
        $slug = P30-Slug $url
        # Registra el slug real: P50 lo usa para puntuar cada sitio por separado.
        Add-Metric -Name ('web_target_' + $slug) -Value $url

        Invoke-Checked -Name ('WEB-' + $slug) -Block {
            $uri = $null
            try { $uri = [Uri]$url }
            catch {
                Add-Finding -Id ('WEB-000-' + $slug) -Severity 'Low' -Category 'Web' `
                    -Title 'URL invalida' `
                    -Detail ('No se pudo interpretar "{0}".' -f $rawTarget) `
                    -Remediation 'Corrija el destino en engine\config\settings.json.'
                return
            }

            $hostName = $uri.Host
            $isHttps = ($uri.Scheme -eq 'https')
            $port = $uri.Port

            $record = @{
                url = $url; host = $hostName; scheme = $uri.Scheme
                dns = @(); tls = $null; http = $null; checks = @()
            }

            # ---------------------------------------------------- DNS
            $ips = @()
            try {
                $ips = @([System.Net.Dns]::GetHostAddresses($hostName) | ForEach-Object { $_.IPAddressToString })
            }
            catch { }
            $record.dns = $ips
            if ($ips.Count -eq 0) {
                Add-Finding -Id ('WEB-001-' + $slug) -Severity 'High' -Category 'Web' `
                    -Title ('DNS no resuelve: {0}' -f $hostName) `
                    -Detail ('El nombre "{0}" no resolvio a ninguna direccion IP. El sitio no es alcanzable.' -f $hostName) `
                    -Remediation 'Verifique el dominio y los registros DNS.'
                [void]$results.Add($record)
                return
            }
            else {
                Add-Finding -Id ('WEB-OK-DNS-' + $slug) -Severity 'Info' -Category 'Web' `
                    -Title ('{0} resuelve correctamente' -f $hostName) `
                    -Detail ('IPs: {0}' -f ($ips -join ', ')) `
                    -Remediation 'Ninguna.'
            }

            # ---------------------------------------------------- TLS
            if ($isHttps) {
                $tls = P30-TlsProbe -HostName $hostName -Port $port -TimeoutMs ($timeoutS * 1000)
                $record.tls = $tls

                if (-not $tls['ok']) {
                    Add-Finding -Id ('WEB-002-' + $slug) -Severity 'Critical' -Category 'Web' `
                        -Title ('Sin TLS funcional en {0}' -f $hostName) `
                        -Detail ('No se pudo establecer una sesion TLS: {0}' -f $tls['error']) `
                        -Remediation 'Revise el certificado y la configuracion del servidor web (puerto 443, cadena de confianza).'
                }
                else {
                    if (-not $tls['cert_valid']) {
                        Add-Finding -Id ('WEB-003-' + $slug) -Severity 'Critical' -Category 'Web' `
                            -Title ('Certificado TLS invalido' -f $hostName) `
                            -Detail ('La cadena de certificacion no valida: {0}. Subject: {1}. Un navegador mostraria una advertencia.' -f $tls['chain_errors'], $tls['subject']) `
                            -Remediation 'Instale un certificado valido emitido por una CA publica y complete la cadena intermedia.'
                    }

                    if ($tls['days_left'] -ne $null) {
                        $days = [int]$tls['days_left']
                        if ($days -lt 0) {
                            Add-Finding -Id ('WEB-004-' + $slug) -Severity 'Critical' -Category 'Web' `
                                -Title 'Certificado TLS vencido' `
                                -Detail ('Vencio el {0} (hace {1} dias).' -f $tls['not_after'], [math]::Abs($days)) `
                                -Remediation 'Renueve el certificado inmediatamente.'
                        }
                        elseif ($days -lt 15) {
                            Add-Finding -Id ('WEB-005-' + $slug) -Severity 'High' -Category 'Web' `
                                -Title ('Certificado TLS por vencer ({0} dias)' -f $days) `
                                -Detail ('Vence el {0}. Quedan {1} dias.' -f $tls['not_after'], $days) `
                                -Remediation 'Renueve el certificado y verifique la automatizacion (ACME).'
                        }
                        elseif ($days -lt 30) {
                            Add-Finding -Id ('WEB-006-' + $slug) -Severity 'Medium' -Category 'Web' `
                                -Title ('Certificado TLS proximo a vencer ({0} dias)' -f $days) `
                                -Detail ('Vence el {0}.' -f $tls['not_after']) `
                                -Remediation 'Programe la renovacion.'
                        }
                    }

                    $protoText = [string]$tls['protocol']
                    if ($protoText -match 'Tls11|Tls\b|Ssl3|Ssl2') {
                        Add-Finding -Id ('WEB-007-' + $slug) -Severity 'High' -Category 'Web' `
                            -Title ('Protocolo TLS obsoleto: {0}' -f $protoText) `
                            -Detail ('Se negocio {0} con cifrado {1}. Protocolos anteriores a TLS 1.2 tienen debilidades conocidas.' -f $protoText, $tls['cipher']) `
                            -Remediation 'Deshabilite TLS 1.0/1.1 en el servidor y exija TLS 1.2 o superior.'
                    }
                    elseif ($protoText -match 'Tls12') {
                        Add-Finding -Id ('WEB-OK-TLS-' + $slug) -Severity 'Info' -Category 'Web' `
                            -Title ('TLS correcto: {0}' -f $protoText) `
                            -Detail ('Cifrado: {0}. Certificado emitido por {1}, valido hasta {2} ({3} dias).' -f $tls['cipher'], $tls['issuer'], $tls['not_after'], $tls['days_left']) `
                            -Remediation 'Ninguna.'
                    }
                }
            }

            # ---------------------------------------------------- HTTP
            $http = P30-HttpProbe -Url $url -TimeoutMs ($timeoutS * 1000)
            $record.http = $http

            if (-not $http['ok']) {
                Add-Finding -Id ('WEB-008-' + $slug) -Severity 'High' -Category 'Web' `
                    -Title ('Sin respuesta HTTP en {0}' -f $url) `
                    -Detail ('La peticion fallo: {0}' -f $http['error']) `
                    -Remediation 'Verifique que el servicio web este arriba y que el puerto este accesible.'
                [void]$results.Add($record)
                return
            }

            Add-Metric -Name ('web_' + $slug + '_status') -Value $http['status']
            Add-Metric -Name ('web_' + $slug + '_ms') -Value $http['elapsed_ms']

            if ($http['status'] -ge 500) {
                Add-Finding -Id ('WEB-009-' + $slug) -Severity 'Medium' -Category 'Web' `
                    -Title ('Error del servidor: HTTP {0}' -f $http['status']) `
                    -Detail ('{0} devolvio {1} en {2} ms.' -f $url, $http['status'], $http['elapsed_ms']) `
                    -Remediation 'Revise los logs del servidor web.'
            }

            # Downgrade / ausencia de HTTPS
            if (-not $isHttps) {
                if ($http['scheme'] -eq 'https') {
                    Add-Finding -Id ('WEB-OK-REDIR-' + $slug) -Severity 'Info' -Category 'Web' `
                        -Title 'HTTP redirige a HTTPS' `
                        -Detail ('{0} termino en {1}.' -f $url, $http['final_url']) `
                        -Remediation 'Ninguna.'
                }
                else {
                    Add-Finding -Id ('WEB-010-' + $slug) -Severity 'High' -Category 'Web' `
                        -Title 'Sitio sin HTTPS' `
                        -Detail ('{0} responde por HTTP y no redirige a HTTPS (URL final: {1}). Todo el trafico, incluidas credenciales, viaja en claro.' -f $url, $http['final_url']) `
                        -Remediation 'Sirva el sitio por HTTPS y redirija todo el trafico HTTP con un 301 permanente.'
                }
            }
            elseif ($http['scheme'] -eq 'http') {
                Add-Finding -Id ('WEB-011-' + $slug) -Severity 'Critical' -Category 'Web' `
                    -Title 'Redireccion de HTTPS a HTTP (downgrade)' `
                    -Detail ('{0} termino en {1}: el servidor degrada la conexion a texto claro.' -f $url, $http['final_url']) `
                    -Remediation 'Elimine la redireccion a HTTP y fuerce HTTPS en toda la cadena.'
            }

            # ---------------------------------------------------- cabeceras de seguridad
            $h = $http['headers']
            $secureScheme = ($http['scheme'] -eq 'https')

            if ($secureScheme) {
                if (-not $h['Strict-Transport-Security']) {
                    Add-Finding -Id ('WEB-020-' + $slug) -Severity 'Medium' -Category 'Web' `
                        -Title 'Falta cabecera HSTS' `
                        -Detail 'No se envio Strict-Transport-Security. Un ataque de downgrade en la primera visita puede forzar HTTP.' `
                        -Remediation 'Anada: Strict-Transport-Security: max-age=31536000; includeSubDomains'
                }
                else {
                    $hsts = [string]$h['Strict-Transport-Security']
                    if ($hsts -match '(?i)max-age\s*=\s*(\d+)') {
                        $maxAge = [long]$matches[1]
                        if ($maxAge -lt 15552000) {
                            Add-Finding -Id ('WEB-021-' + $slug) -Severity 'Low' -Category 'Web' `
                                -Title ('HSTS con max-age corto: {0} s' -f $maxAge) `
                                -Detail ('Valor actual: {0}. Se recomienda al menos 15552000 s (180 dias).' -f $hsts) `
                                -Remediation 'Aumente max-age a 31536000 e incluya includeSubDomains.'
                        }
                    }
                }
            }

            if (-not $h['Content-Security-Policy']) {
                Add-Finding -Id ('WEB-022-' + $slug) -Severity 'Medium' -Category 'Web' `
                    -Title 'Falta Content-Security-Policy' `
                    -Detail 'Sin CSP, un fallo de inyeccion (XSS) ejecuta script arbitrario sin restriccion del navegador.' `
                    -Remediation 'Defina una CSP restrictiva, por ejemplo: default-src ''self''; object-src ''none''; base-uri ''self'''
            }

            if (-not $h['X-Frame-Options'] -and -not ($h['Content-Security-Policy'] -match '(?i)frame-ancestors')) {
                Add-Finding -Id ('WEB-023-' + $slug) -Severity 'Medium' -Category 'Web' `
                    -Title 'Sin proteccion contra clickjacking' `
                    -Detail 'No hay X-Frame-Options ni frame-ancestors en CSP: el sitio puede embeberse en un iframe malicioso.' `
                    -Remediation 'Anada X-Frame-Options: DENY (o frame-ancestors en CSP).'
            }

            if (-not $h['X-Content-Type-Options']) {
                Add-Finding -Id ('WEB-024-' + $slug) -Severity 'Low' -Category 'Web' `
                    -Title 'Falta X-Content-Type-Options' `
                    -Detail 'Sin "nosniff", el navegador puede interpretar un archivo con un tipo distinto al declarado.' `
                    -Remediation 'Anada X-Content-Type-Options: nosniff'
            }

            if (-not $h['Referrer-Policy']) {
                Add-Finding -Id ('WEB-025-' + $slug) -Severity 'Low' -Category 'Web' `
                    -Title 'Falta Referrer-Policy' `
                    -Detail 'La URL completa puede filtrarse a terceros en la cabecera Referer.' `
                    -Remediation 'Anada Referrer-Policy: strict-origin-when-cross-origin'
            }

            if (-not $h['Permissions-Policy']) {
                Add-Finding -Id ('WEB-026-' + $slug) -Severity 'Low' -Category 'Web' `
                    -Title 'Falta Permissions-Policy' `
                    -Detail 'Sin Permissions-Policy no se restringen camara, microfono, geolocalizacion ni sensores.' `
                    -Remediation 'Anada Permissions-Policy: geolocation=(), microphone=(), camera=()'
            }

            if (-not $h['Cross-Origin-Opener-Policy']) {
                Add-Finding -Id ('WEB-027-' + $slug) -Severity 'Low' -Category 'Web' `
                    -Title 'Falta Cross-Origin-Opener-Policy' `
                    -Detail 'Sin COOP, una ventana abierta desde otro origen puede mantener una referencia (riesgo de XS-Leaks).' `
                    -Remediation 'Anada Cross-Origin-Opener-Policy: same-origin'
            }

            # ---------------------------------------------------- divulgacion de informacion
            $leaks = @()
            if ($h['Server'] -and ([string]$h['Server'] -match '\d')) { $leaks += ('Server: ' + [string]$h['Server']) }
            if ($h['X-Powered-By']) { $leaks += ('X-Powered-By: ' + [string]$h['X-Powered-By']) }
            if ($h['X-AspNet-Version']) { $leaks += ('X-AspNet-Version: ' + [string]$h['X-AspNet-Version']) }
            if ($h['X-XSS-Protection'] -and ([string]$h['X-XSS-Protection'] -match '0')) { $leaks += ('X-XSS-Protection: 0 (desactiva el filtro en navegadores antiguos)') }

            if ($leaks.Count -gt 0) {
                Add-Finding -Id ('WEB-030-' + $slug) -Severity 'Low' -Category 'Web' `
                    -Title 'Divulgacion de tecnologia en cabeceras' `
                    -Detail (($leaks -join ' | ') + '. Facilita al atacante elegir exploits para la version exacta.') `
                    -Remediation 'Elimine o generalice estas cabeceras (server_tokens off en nginx, <httpRuntime enableVersionHeader="false"> en IIS).'
            }

            # ---------------------------------------------------- cookies
            $cookieLines = @($http['set_cookie'])
            $badSecure = @()
            $badHttpOnly = @()
            $badSameSite = @()
            $seen = @()

            foreach ($line in $cookieLines) {
                if (-not $line) { continue }
                $cookieName = ''
                if ($line -match '^\s*([^=]+)=') { $cookieName = $matches[1].Trim() }
                if (-not $cookieName) { continue }
                if ($seen -contains $cookieName) { continue }
                $seen += $cookieName

                if ($secureScheme -and ($line -notmatch '(?i);\s*secure')) { $badSecure += $cookieName }
                if ($line -notmatch '(?i);\s*httponly') { $badHttpOnly += $cookieName }
                if ($line -notmatch '(?i);\s*samesite') { $badSameSite += $cookieName }
            }

            if ($badSecure.Count -gt 0) {
                Add-Finding -Id ('WEB-040-' + $slug) -Severity 'High' -Category 'Web' `
                    -Title 'Cookies sin atributo Secure' `
                    -Detail ('El sitio es HTTPS pero estas cookies no llevan Secure: {0}. Se envian tambien por HTTP si el usuario cae en una peticion no cifrada.' -f ($badSecure -join ', ')) `
                    -Remediation 'Anada el atributo Secure a todas las cookies de sesion.'
            }
            if ($badHttpOnly.Count -gt 0) {
                Add-Finding -Id ('WEB-041-' + $slug) -Severity 'Medium' -Category 'Web' `
                    -Title 'Cookies sin atributo HttpOnly' `
                    -Detail ('Cookies accesibles desde JavaScript: {0}. Un XSS puede robarlas.' -f ($badHttpOnly -join ', ')) `
                    -Remediation 'Anada HttpOnly a las cookies que no necesite leer el cliente.'
            }
            if ($badSameSite.Count -gt 0) {
                Add-Finding -Id ('WEB-042-' + $slug) -Severity 'Low' -Category 'Web' `
                    -Title 'Cookies sin atributo SameSite' `
                    -Detail ('Cookies sin SameSite: {0}. Sin el, el navegador aplica Lax por defecto pero no esta garantizado en clientes antiguos.' -f ($badSameSite -join ', ')) `
                    -Remediation 'Anada SameSite=Lax o Strict segun el flujo.'
            }

            # ---------------------------------------------------- archivos de politica
            $base = $uri.GetLeftPart([UriPartial]::Authority)
            $robots = P30-FetchSmall -Url ($base + '/robots.txt') -TimeoutMs 5000
            if ($robots['ok'] -and $robots['status'] -eq 200) {
                Add-Finding -Id ('WEB-050-' + $slug) -Severity 'Info' -Category 'Web' `
                    -Title 'robots.txt presente' `
                    -Detail ('{0}/robots.txt responde 200. Revise que no exponga rutas internas (Disallow suele revelar paneles de administracion).' -f $base) `
                    -Remediation 'Ninguna, salvo revisar el contenido.'
            }

            $secTxt = P30-FetchSmall -Url ($base + '/.well-known/security.txt') -TimeoutMs 5000
            if ($secTxt['ok'] -and $secTxt['status'] -eq 200) {
                Add-Finding -Id ('WEB-051-' + $slug) -Severity 'Info' -Category 'Web' `
                    -Title 'security.txt presente' `
                    -Detail ('{0}/.well-known/security.txt responde 200: existe un canal declarado para reportar vulnerabilidades.' -f $base) `
                    -Remediation 'Ninguna.'
            }
            else {
                Add-Finding -Id ('WEB-052-' + $slug) -Severity 'Low' -Category 'Web' `
                    -Title 'Sin security.txt' `
                    -Detail ('No existe {0}/.well-known/security.txt ni respuesta valida: no hay canal publicado para reportar fallos de seguridad.' -f $base) `
                    -Remediation 'Publique /.well-known/security.txt con al menos un contacto y una politica de divulgacion.'
            }

            [void]$results.Add($record)
        }
    }

    [void](Write-Evidence -Name 'web.json' -Data $results)
    Write-Log -Level OK -Message ('WEB: auditoria completada ({0} destino(s))' -f $targets.Count)
}
