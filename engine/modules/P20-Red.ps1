<#
  P20-Red.ps1
  USB Security Audit Toolkit - diagnostico de red
  Dueno: UNIDAD B | Version: 1.0.0
  PowerShell 5.1 compatible

  Presupuesto objetivo: menos de 25 s en modo rapido.
  Todo acceso de red lleva timeout explicito.
#>

function P20-IsPrivate {
    param([string] $Ip)
    if (-not $Ip) { return $true }
    if ($Ip -eq '::1' -or $Ip -eq '127.0.0.1') { return $true }
    if ($Ip -like 'fe80*' -or $Ip -like 'fc*' -or $Ip -like 'fd*') { return $true }
    $parts = $Ip.Split('.')
    if ($parts.Count -ne 4) { return $false }
    $a = 0
    $b = 0
    if (-not [int]::TryParse($parts[0], [ref]$a)) { return $false }
    if (-not [int]::TryParse($parts[1], [ref]$b)) { return $false }
    if ($a -eq 10) { return $true }
    if ($a -eq 172 -and $b -ge 16 -and $b -le 31) { return $true }
    if ($a -eq 192 -and $b -eq 168) { return $true }
    if ($a -eq 169 -and $b -eq 254) { return $true }
    if ($a -eq 127) { return $true }
    return $false
}

function P20-Ping {
    param([string] $Target, [int] $Count = 3, [int] $BudgetSeconds = 8)

    $res = @{ target = $Target; sent = 0; received = 0; loss_pct = 100; avg_ms = $null; min_ms = $null; max_ms = $null }
    $times = @()
    $sw = [Diagnostics.Stopwatch]::StartNew()

    for ($i = 0; $i -lt $Count; $i++) {
        if ($sw.Elapsed.TotalSeconds -gt $BudgetSeconds) { break }
        $res.sent = $res.sent + 1
        try {
            $r = Test-Connection -ComputerName $Target -Count 1 -ErrorAction SilentlyContinue
            if ($r) {
                $res.received = $res.received + 1
                $rt = $null
                try { $rt = [int]$r.ResponseTime } catch { $rt = $null }
                if ($null -ne $rt) { $times += $rt }
            }
        }
        catch { }
        if ($i -lt ($Count - 1)) {
            $remain = $Count - $i - 1
            if ($remain -gt 0) { Start-Sleep -Milliseconds 200 }
        }
    }
    $sw.Stop()

    if ($res.sent -gt 0) {
        $res.loss_pct = [int][math]::Round((($res.sent - $res.received) / $res.sent) * 100, 0)
    }
    if ($times.Count -gt 0) {
        $res.avg_ms = [int][math]::Round((($times | Measure-Object -Average).Average), 0)
        $res.min_ms = [int]($times | Measure-Object -Minimum).Minimum
        $res.max_ms = [int]($times | Measure-Object -Maximum).Maximum
    }
    $res['elapsed_ms'] = [int]$sw.ElapsedMilliseconds
    return $res
}

function Invoke-Red {
    param([Parameter(Mandatory = $true)] $Ctx)

    Write-Log -Level INFO -Message 'RED: diagnostico de conectividad'

    $gw = $null
    $dnsServers = @()

    # ================================================================ adaptadores
    Invoke-Checked -Name 'NET-Adaptadores' -Block {
        $adapters = @()
        $configs  = @()

        try {
            $adapters = @(Get-NetAdapter -ErrorAction Stop)
            $configs  = @(Get-NetIPConfiguration -ErrorAction Stop)
        }
        catch {
            # Fallback WMI (Server antiguo)
            try {
                $wmi = @(Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop)
                foreach ($c in $wmi) {
                    $configs += [PSCustomObject]@{
                        InterfaceAlias  = $c.Description
                        IPv4Address     = @($c.IPAddress | Where-Object { $_ -match '^\d+\.' })
                        IPv4DefaultGateway = @([PSCustomObject]@{ NextHop = $c.DefaultIPGateway })
                        DNSServer       = @([PSCustomObject]@{ Address = $c.DNSServerSearchOrder })
                    }
                }
            }
            catch { }
        }

        $data = @()
        $active = 0
        foreach ($c in $configs) {
            $alias = [string]$c.InterfaceAlias
            $ips = @()
            try { $ips = @($c.IPv4Address | ForEach-Object { [string]$_.IPAddress }) } catch { }
            $gwAddr = ''
            try { $gt = @($c.IPv4DefaultGateway); if ($gt.Count -gt 0) { $gwAddr = [string]$gt[0].NextHop } } catch { }
            $dns = @()
            try { $dns = @($c.DNSServer | ForEach-Object { [string]$_.Address } | Where-Object { $_ }) } catch { }

            if ($gwAddr -and -not $gw) { $gw = $gwAddr }
            if ($dns.Count -gt 0 -and $dnsServers.Count -eq 0) { $dnsServers = $dns }

            if ($ips.Count -gt 0) { $active++ }
            $data += @{
                alias      = $alias
                ipv4       = $ips
                gateway    = $gwAddr
                dns        = $dns
                dhcp       = $(try { [bool]$c.Dhcp } catch { $null })
            }
        }

        $countActive = 0
        try { $countActive = @($adapters | Where-Object { $_.Status -eq 'Up' }).Count } catch { $countActive = $active }

        Add-Metric -Name 'network_adapters_up' -Value $countActive
        Add-Metric -Name 'default_gateway' -Value $gw
        [void](Write-Evidence -Name 'network.json' -Data $data)

        if ($countActive -eq 0) {
            Add-Finding -Id 'NET-001' -Severity 'High' -Category 'Red' `
                -Title 'Sin adaptadores de red activos' `
                -Detail 'Ningun adaptador presenta direccion IP activa. Los checks de conectividad no son concluyentes.' `
                -Remediation 'Verifique el cable/Wi-Fi y que el adaptador no este deshabilitado.'
        }
        elseif (-not $gw) {
            Add-Finding -Id 'NET-002' -Severity 'Medium' -Category 'Red' `
                -Title 'Sin puerta de enlace por defecto' `
                -Detail ('{0} adaptador(es) con IP pero ninguno con gateway IPv4. El equipo solo alcanza su propia subred.' -f $countActive) `
                -Remediation 'Configure gateway o DHCP: ipconfig /renew'
        }
        else {
            Add-Finding -Id 'NET-OK-01' -Severity 'Info' -Category 'Red' `
                -Title 'Conectividad configurada' `
                -Detail ('{0} adaptador(es) activo(s). Gateway: {1}. DNS: {2}.' -f $countActive, $gw, ($dnsServers -join ', ')) `
                -Remediation 'Ninguna.'
        }

        # Proxy
        $proxyEnable = Get-RegValue -Path 'HKCU:\SOFTWARE\Microsoft\Internet Explorer\Settings' -Name 'ProxyEnable' -Default 0
        $proxyServer = Get-RegValue -Path 'HKCU:\SOFTWARE\Microsoft\Internet Explorer\Settings' -Name 'ProxyServer' -Default ''
        if ([int]$proxyEnable -eq 1 -and $proxyServer) {
            Add-Finding -Id 'NET-003' -Severity 'Info' -Category 'Red' `
                -Title 'Proxy configurado en el usuario' `
                -Detail ('ProxyServer={0}. Todo el trafico HTTP/HTTPS pasa por ese intermediario.' -f $proxyServer) `
                -Remediation 'Confirme que el proxy sea corporativo y legitimo.'
        }

        # IPv6 / Teredo
        try {
            $teredo = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisabledComponents' -Default 0
            $sixToFour = Get-Service -Name '6to4' -ErrorAction SilentlyContinue
            if ($sixToFour -and $sixToFour.Status -eq 'Running') {
                Add-Finding -Id 'NET-004' -Severity 'Info' -Category 'Red' `
                    -Title 'Servicio 6to4 en ejecucion' `
                    -Detail 'Servicio 6to4 activo: tunelizacion IPv6 automatica que puede eludir controles de red.' `
                    -Remediation 'Set-Service 6to4 -StartupType Disabled'
            }
        }
        catch { }
    }

    # ================================================================ DNS
    Invoke-Checked -Name 'NET-DNS' -Block {
        $hosts = @('www.google.com', 'www.cloudflare.com', 'www.microsoft.com')
        try {
            if ($Ctx.Config['network'] -and $Ctx.Config['network']['dns_test_hosts']) {
                $hosts = @($Ctx.Config['network']['dns_test_hosts'] | Where-Object { $_ })
            }
        }
        catch { }

        $okCount = 0
        $failCount = 0
        $results = @()
        $slowest = 0

        foreach ($h in $hosts) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $ips = @()
            try {
                $ips = @([System.Net.Dns]::GetHostAddresses($h) | ForEach-Object { $_.IPAddressToString })
            }
            catch { $ips = @() }
            $sw.Stop()
            $ms = [int]$sw.ElapsedMilliseconds
            if ($ms -gt $slowest) { $slowest = $ms }

            if ($ips.Count -gt 0) { $okCount++ } else { $failCount++ }
            $results += @{ host = $h; ips = $ips; ms = $ms; ok = ($ips.Count -gt 0) }
        }

        [void](Write-Evidence -Name 'dns.json' -Data $results)
        Add-Metric -Name 'dns_resolved' -Value $okCount
        Add-Metric -Name 'dns_slowest_ms' -Value $slowest

        if ($failCount -eq $hosts.Count -and $hosts.Count -gt 0) {
            Add-Finding -Id 'NET-010' -Severity 'High' -Category 'Red' `
                -Title 'Resolucion DNS fallida' `
                -Detail ('Ninguno de los {0} dominios de prueba resolvio. DNS configurado: {1}.' -f $hosts.Count, ($dnsServers -join ', ')) `
                -Remediation 'ipconfig /flushdns ; verifique los servidores DNS configurados o que el DNS no este bloqueado.'
        }
        elseif ($failCount -gt 0) {
            Add-Finding -Id 'NET-011' -Severity 'Medium' -Category 'Red' `
                -Title 'Resolucion DNS parcialmente fallida' `
                -Detail ('{0} de {1} dominios no resolvieron.' -f $failCount, $hosts.Count) `
                -Remediation 'Revise los servidores DNS y posibles bloqueos por politica.'
        }
        else {
            Add-Finding -Id 'NET-OK-02' -Severity 'Info' -Category 'Red' `
                -Title 'Resolucion DNS correcta' `
                -Detail ('{0}/{1} dominios resueltos. Consulta mas lenta: {2} ms.' -f $okCount, $hosts.Count, $slowest) `
                -Remediation 'Ninguna.'
        }

        if ($slowest -gt 1000) {
            Add-Finding -Id 'NET-012' -Severity 'Low' -Category 'Red' `
                -Title 'Resolucion DNS lenta' `
                -Detail ('Consulta mas lenta: {0} ms.' -f $slowest) `
                -Remediation 'Revise la latencia hacia el servidor DNS y considere un resolver local.'
        }
    }

    # ================================================================ latencia
    Invoke-Checked -Name 'NET-Latencia' -Block {
        $count = 3
        try {
            if ($Ctx.Config['network'] -and $Ctx.Config['network']['ping_count']) {
                $count = [int]$Ctx.Config['network']['ping_count']
            }
            if ($count -lt 1) { $count = 1 }
            if ($count -gt 4) { $count = 4 }
        }
        catch { $count = 3 }

        $targets = @()
        # $gw se calculaba en el bloque de adaptadores (otro scope): aqui llega
        # vacio. Se recupera del metric ya publicado, con respaldo en la ruta.
        $gw = ''
        try { $gw = [string]$script:Ctx.Metrics['default_gateway'] } catch { $gw = '' }
        if (-not $gw) {
            try {
                $defRoute = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | Sort-Object RouteMetric | Select-Object -First 1
                if ($defRoute) { $gw = [string]$defRoute.NextHop }
            }
            catch { }
        }
        if ($gw) { $targets += @{ label = 'gateway'; host = $gw } }
        $targets += @{ label = 'internet'; host = '1.1.1.1' }

        $data = @()
        foreach ($t in $targets) {
            $r = P20-Ping -Target $t['host'] -Count $count -BudgetSeconds 6
            $r['label'] = $t['label']
            $data += $r
            Add-Metric -Name ('ping_' + $t['label'] + '_loss_pct') -Value $r.loss_pct

            if ($r.loss_pct -gt 50) {
                Add-Finding -Id ('NET-020-' + $t['label']) -Severity 'High' -Category 'Red' `
                    -Title ('Perdida de paquetes alta hacia {0}' -f $t['label']) `
                    -Detail ('{0}: {1}% de perdida ({2}/{3} respuestas), {4}.' -f $t['host'], $r.loss_pct, $r.received, $r.sent, (P20-TextLatency $r)) `
                    -Remediation 'Revise cableado, Wi-Fi y saturacion del enlace.'
            }
            elseif ($r.loss_pct -gt 20) {
                # Con 4 sondas, un solo paquete perdido ya son 25%: la cifra
                # exagera perdidas reales y algunos destinos limitan ICMP.
                $caveat = ''
                if ($r['sent'] -le 5) { $caveat = ' Muestra pequena: cada paquete perdido pesa 25%. Confirme con una prueba mas larga (ping -n 20).' }
                Add-Finding -Id ('NET-021-' + $t['label']) -Severity 'Medium' -Category 'Red' `
                    -Title ('Perdida de paquetes hacia {0}' -f $t['label']) `
                    -Detail ('{0}: {1}% de perdida ({2}/{3}), {4}.{5}' -f $t['host'], $r.loss_pct, $r.received, $r.sent, (P20-TextLatency $r), $caveat) `
                    -Remediation 'Investigue la calidad del enlace (interferencia Wi-Fi, errores de interfaz).'
            }
        }
        [void](Write-Evidence -Name 'latency.json' -Data $data)

        $inet = @($data | Where-Object { $_['label'] -eq 'internet' })
        if ($inet.Count -gt 0 -and $inet[0]['loss_pct'] -eq 100) {
            Add-Finding -Id 'NET-022' -Severity 'Medium' -Category 'Red' `
                -Title 'Sin salida a Internet por ICMP' `
                -Detail 'No hubo respuesta de 1.1.1.1. Puede ser un bloqueo legitimo de ICMP o falta de salida real.' `
                -Remediation 'Compruebe con una peticion TCP: Test-NetConnection 1.1.1.1 -Port 443'
        }
        elseif ($inet.Count -gt 0) {
            Add-Finding -Id 'NET-OK-03' -Severity 'Info' -Category 'Red' `
                -Title 'Latencia de salida medida' `
                -Detail ('1.1.1.1: {0}, perdida {1}%.' -f (P20-TextLatency $inet[0]), $inet[0]['loss_pct']) `
                -Remediation 'Ninguna.'
        }
    }

    # ================================================================ tabla ARP
    Invoke-Checked -Name 'NET-ARP' -Block {
        $arp = @()
        try {
            $arp = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.State -ne 'Unreachable' })
        }
        catch {
            try { $arp = @(Get-WmiObject -Class Win32_ARPEntry -ErrorAction Stop) } catch { }
        }

        $entries = @()
        $seenPair = @{}
        $incomplete = @()
        $macIps = @{}
        foreach ($a in $arp) {
            $ip = ''
            $mac = ''
            $state = ''
            try { $ip = [string]$a.IPAddress } catch { }
            try { $mac = [string]$a.LinkLayerAddress } catch {
                try { $mac = [string]$a.MACAddress } catch { }
            }
            try { $state = [string]$a.State } catch { }
            if (-not $ip) { continue }

            # Multicast, broadcast y direcciones no unicast comparten MAC entre
            # muchas IPs por diseno: no son evidencia de ARP spoofing y solo
            # generan ruido. Se excluyen del analisis de duplicados.
            $firstOctet = 0
            try { $firstOctet = [int]($ip.Split('.')[0]) } catch { $firstOctet = 0 }
            $isMulticast = ($firstOctet -ge 224 -and $firstOctet -le 239)
            $isBroadcast = ($ip -eq '255.255.255.255') -or ($ip -like '*.255') -or ($firstOctet -eq 0)
            if ($isMulticast -or $isBroadcast) { continue }

            $macNorm = ''
            if ($mac) { $macNorm = ($mac.ToUpper() -replace ':', '-') }

            # La misma pareja IP/MAC aparece una vez por interfaz; se colapsa.
            $pairKey = $ip + '|' + $macNorm
            if ($seenPair.ContainsKey($pairKey)) { continue }
            $seenPair[$pairKey] = $true

            $entries += @{ ip = $ip; mac = $macNorm; state = $state }

            if (-not $macNorm -or $macNorm -eq '00-00-00-00-00-00') {
                $incomplete += $ip
            }
            else {
                if ($macIps.ContainsKey($macNorm)) { $macIps[$macNorm] += $ip } else { $macIps[$macNorm] = @($ip) }
            }
        }

        [void](Write-Evidence -Name 'arp.json' -Data $entries)
        Add-Metric -Name 'arp_entries' -Value $entries.Count

        $dupList = @()
        foreach ($k in $macIps.Keys) {
            $ipsForMac = @($macIps[$k] | Select-Object -Unique)
            if ($ipsForMac.Count -gt 1) { $dupList += ('{0} -> {1}' -f $k, ($ipsForMac -join ', ')) }
        }

        if ($dupList.Count -gt 0) {
            Add-Finding -Id 'NET-030' -Severity 'Medium' -Category 'Red' `
                -Title 'MAC unica asociada a varias IP' `
                -Detail ('MACs con mas de una IP unicast: {0}. Puede indicar ARP spoofing, un proxy ARP legitimo o un balanceador.' -f ($dupList -join ' | ')) `
                -Remediation 'Compare la tabla MAC del switch con estas IP; si no corresponde a un proxy conocido, aísle el puerto.' `
                -Evidence 'arp.json'
        }
        if ($incomplete.Count -gt 0) {
            Add-Finding -Id 'NET-031' -Severity 'Low' -Category 'Red' `
                -Title 'Entradas ARP incompletas' `
                -Detail ('IPs sin MAC resuelta: {0}.' -f ($incomplete -join ', ')) `
                -Remediation 'Si persisten, confirme que el equipo de esa IP esta activo y que no hay conflictos de direccion.' `
                -Evidence 'arp.json'
        }
        if ($dupList.Count -eq 0 -and $incomplete.Count -eq 0) {
            Add-Finding -Id 'NET-OK-ARP' -Severity 'Info' -Category 'Red' `
                -Title 'Tabla ARP coherente' `
                -Detail ('{0} entradas unicast, sin MAC duplicada ni entradas incompletas.' -f $entries.Count) `
                -Remediation 'Ninguna.' `
                -Evidence 'arp.json'
        }
    }

    # ================================================================ puertos en escucha
    Invoke-Checked -Name 'NET-Puertos' -Block {
        $listeners = @()
        $usedFallback = $false
        try {
            $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
        }
        catch {
            $usedFallback = $true
            try {
                $lines = (netstat -ano -p tcp 2>$null) -split "`r?`n"
                foreach ($l in $lines) {
                    if ($l -match '^\s*TCP\s+(\S+):(\d+)\s+(\S+):(\d+)\s+LISTENING\s+(\d+)') {
                        $listeners += [PSCustomObject]@{
                            LocalAddress = $matches[1]
                            LocalPort    = [int]$matches[2]
                            OwningProcess = [int]$matches[5]
                        }
                    }
                }
            }
            catch { }
        }

        $criticalPorts = @(21, 23, 445, 3389, 5900, 6379, 27017, 9200, 11211, 1433, 3306, 5432, 2375)
        $mediumPorts   = @(135, 139, 2049, 5985, 5986)

        $exposed = @()
        $allPorts = @()
        $procCache = @{}

        # ¿El firewall bloquea la entrada por defecto en todos los perfiles?
        # Un puerto que escucha en 0.0.0.0 no es alcanzable si la politica por
        # defecto es Block y no hay regla de excepcion.
        $fwBlocksInbound = $false
        try {
            $fwp = @(Get-NetFirewallProfile -ErrorAction Stop)
            if ($fwp.Count -gt 0) {
                $fwBlocksInbound = (@($fwp | Where-Object { -not $_.Enabled -or [string]$_.DefaultInboundAction -ne 'Block' }).Count -eq 0)
            }
        }
        catch { $fwBlocksInbound = $false }
        Add-Metric -Name 'firewall_blocks_inbound' -Value $fwBlocksInbound

        foreach ($l in $listeners) {
            $addr = [string]$l.LocalAddress
            $port = [int]$l.LocalPort
            $procId = 0
            try { $procId = [int]$l.OwningProcess } catch { $procId = 0 }

            $isExternal = $false
            if ($addr -eq '0.0.0.0' -or $addr -eq '::' -or $addr -eq '::0') { $isExternal = $true }

            $procName = ''
            if ($procId -gt 0) {
                if ($procCache.ContainsKey($procId)) { $procName = $procCache[$procId] }
                else {
                    try {
                        $p = Get-Process -Id $procId -ErrorAction Stop
                        $procName = $p.ProcessName
                    }
                    catch { $procName = 'desconocido' }
                    $procCache[$procId] = $procName
                }
            }

            $allPorts += @{ address = $addr; port = $port; process = $procName; pid = $procId; external = $isExternal }

            if ($isExternal -and (($criticalPorts -contains $port) -or ($mediumPorts -contains $port))) {
                $exposed += @{ port = $port; address = $addr; process = $procName; pid = $procId }
            }
        }

        # Un mismo puerto suele escuchar en IPv4 (0.0.0.0) e IPv6 (::) a la vez:
        # se agrupa por puerto para emitir un unico hallazgo por servicio real.
        $byPort = @{}
        foreach ($e in $exposed) {
            if ($byPort.ContainsKey($e['port'])) {
                [void]$byPort[$e['port']].addresses.Add($e['address'])
                if ($byPort[$e['port']].process -ne $e['process']) { $byPort[$e['port']].process = $byPort[$e['port']].process + '/' + $e['process'] }
            }
            else {
                $byPort[$e['port']] = @{
                    process   = $e['process']
                    pid       = $e['pid']
                    addresses = (New-Object System.Collections.ArrayList)
                }
                [void]$byPort[$e['port']].addresses.Add($e['address'])
            }
        }

        foreach ($port in ($byPort.Keys | Sort-Object)) {
            $info = $byPort[$port]
            $addrs = (@($info.addresses | Select-Object -Unique) -join ', ')
            $procText = [string]$info['process']
            if ($criticalPorts -contains $port) { $sev = 'High' } else { $sev = 'Medium' }
            $idPrefix = 'NET-041'
            $titlePrefix = 'Puerto de administracion accesible en todas las interfaces'
            if ($criticalPorts -contains $port) {
                $idPrefix = 'NET-040'
                $titlePrefix = 'Puerto sensible accesible en todas las interfaces'
            }

            # El servicio escucha en todas las interfaces, pero eso no equivale a
            # estar alcanzable: si el firewall bloquea la entrada por defecto en
            # los tres perfiles, el riesgo real baja y el hallazgo lo dice.
            $mitigado = ''
            if ($fwBlocksInbound) {
                $sev = 'Low'
                $mitigado = ' Mitigado por firewall: DefaultInboundAction=Block en todos los perfiles activos; solo seria alcanzable mediante una regla de excepcion.'
            }
            else {
                $mitigado = ' El firewall no bloquea la entrada por defecto: revise las reglas activas.'
            }

            Add-Finding -Id ($idPrefix + '-' + $port) -Severity $sev -Category 'Red' `
                -Title ('{0}: {1}' -f $titlePrefix, $port) `
                -Detail ('{0} ({1}) escucha en {2} mediante {3} (PID {4}).{5}' -f $port, (P20-PortName $port), $addrs, $procText, $info['pid'], $mitigado) `
                -Remediation (P20-PortFix $port) `
                -Evidence 'ports.json'
        }

        [void](Write-Evidence -Name 'ports.json' -Data $allPorts)
        Add-Metric -Name 'listening_ports' -Value $allPorts.Count
        Add-Metric -Name 'listening_ports_external' -Value (@($allPorts | Where-Object { $_['external'] }).Count)

        if ($exposed.Count -eq 0) {
            Add-Finding -Id 'NET-OK-04' -Severity 'Info' -Category 'Red' `
                -Title 'Sin puertos sensibles expuestos' `
                -Detail ('{0} puertos en escucha; ninguno de la lista de riesgo escucha en todas las interfaces.{1}' -f $allPorts.Count, $(if ($usedFallback) { ' (via netstat)' } else { '' })) `
                -Remediation 'Ninguna.'
        }
    }

    # ================================================================ conexiones salientes
    Invoke-Checked -Name 'NET-Salientes' -Block {
        $conns = @()
        try { $conns = @(Get-NetTCPConnection -State Established -ErrorAction Stop) } catch { }

        $out = @()
        foreach ($c in $conns) {
            $rip = [string]$c.RemoteAddress
            if (-not $rip) { continue }
            if (P20-IsPrivate $rip) { continue }
            $procName = ''
            $procId = 0
            try { $procId = [int]$c.OwningProcess } catch { }
            if ($procId -gt 0) {
                try { $procName = (Get-Process -Id $procId -ErrorAction Stop).ProcessName } catch { $procName = '?' }
            }
            $out += @{ remote = $rip; port = [int]$c.RemotePort; process = $procName; pid = $procId }
        }

        $top = @($out | Select-Object -First 15)
        [void](Write-Evidence -Name 'connections.json' -Data $top)
        Add-Metric -Name 'outbound_public_conns' -Value $out.Count

        if ($top.Count -gt 0) {
            $lines = @()
            foreach ($c in $top) { $lines += ('{0}:{1} <- {2}' -f $c['remote'], $c['port'], $c['process']) }
            Add-Finding -Id 'NET-050' -Severity 'Info' -Category 'Red' `
                -Title ('Conexiones salientes a Internet: {0}' -f $out.Count) `
                -Detail ($lines -join ' | ') `
                -Remediation 'Verifique que cada proceso sea esperado.' `
                -Evidence 'connections.json'
        }
    }

    # ================================================================ recursos SMB
    Invoke-Checked -Name 'NET-SMB' -Block {
        $shares = @()
        try { $shares = @(Get-SmbShare -ErrorAction Stop) } catch { }

        $custom = @()
        foreach ($s in $shares) {
            $name = [string]$s.Name
            if ($name -like '*$') { continue }
            $custom += @{ name = $name; path = [string]$s.Path; description = [string]$s.Description }
        }

        [void](Write-Evidence -Name 'smb-shares.json' -Data $custom)
        Add-Metric -Name 'smb_shares_custom' -Value $custom.Count

        if ($custom.Count -gt 0) {
            $lines = @()
            foreach ($s in $custom) { $lines += ('{0} -> {1}' -f $s['name'], $s['path']) }
            Add-Finding -Id 'NET-060' -Severity 'Medium' -Category 'Red' `
                -Title ('Recursos SMB compartidos: {0}' -f $custom.Count) `
                -Detail ($lines -join ' | ') `
                -Remediation 'Revise los permisos NTFS y de recurso de cada uno (Get-SmbShareAccess <nombre>).' `
                -Evidence 'smb-shares.json'
        }
        else {
            Add-Finding -Id 'NET-OK-05' -Severity 'Info' -Category 'Red' `
                -Title 'Sin recursos SMB compartidos adicionales' `
                -Detail 'Solo comparticiones administrativas.' `
                -Remediation 'Ninguna.'
        }
    }

    # ================================================================ Wi-Fi
    Invoke-Checked -Name 'NET-Wifi' -Block {
        $profiles = @()
        try {
            $raw = (netsh wlan show profiles 2>$null)
            foreach ($line in ($raw -split "`r?`n")) {
                if ($line -match ':\s*(.+?)\s*$') {
                    $candidate = $matches[1].Trim()
                    if ($candidate -and $candidate -notmatch '(?i)perfiles de usuario|user profiles') {
                        if ($line -match '(?i)perfil|profile') { $profiles += $candidate }
                    }
                }
            }
        }
        catch { }

        $open = @()
        $wifiData = @()
        foreach ($p in $profiles) {
            $auth = ''
            try {
                $detail = (netsh wlan show profile name="$p" 2>$null)
                foreach ($line in ($detail -split "`r?`n")) {
                    if ($line -match '(?i)(autenticaci|authentication)\s*:\s*(.+?)\s*$') {
                        $auth = $matches[2].Trim()
                        break
                    }
                }
            }
            catch { }
            $wifiData += @{ ssid = $p; authentication = $auth }
            if ($auth -match '(?i)^(abierta|open|wep)') { $open += ('{0} ({1})' -f $p, $auth) }
        }

        [void](Write-Evidence -Name 'wifi.json' -Data $wifiData)
        Add-Metric -Name 'wifi_profiles' -Value $profiles.Count

        if ($open.Count -gt 0) {
            Add-Finding -Id 'NET-070' -Severity 'Medium' -Category 'Red' `
                -Title 'Perfiles Wi-Fi con cifrado debil o nulo' `
                -Detail ($open -join ' | ') `
                -Remediation 'Elimine el perfil: netsh wlan delete profile name="<SSID>"'
        }
    }

    Write-Log -Level OK -Message 'RED: diagnostico completado'
}

function P20-TextLatency {
    param($R)
    if ($null -eq $R['avg_ms']) { return 'sin respuesta' }
    return ('media {0} ms (min {1} / max {2})' -f $R['avg_ms'], $R['min_ms'], $R['max_ms'])
}

function P20-PortName {
    param([int] $Port)
    switch ($Port) {
        21 { return 'FTP' }
        23 { return 'Telnet' }
        135 { return 'RPC' }
        139 { return 'NetBIOS' }
        445 { return 'SMB' }
        1433 { return 'SQL Server' }
        2049 { return 'NFS' }
        2375 { return 'Docker API sin TLS' }
        3306 { return 'MySQL' }
        3389 { return 'RDP' }
        5432 { return 'PostgreSQL' }
        5900 { return 'VNC' }
        5985 { return 'WinRM HTTP' }
        5986 { return 'WinRM HTTPS' }
        6379 { return 'Redis' }
        9200 { return 'Elasticsearch' }
        11211 { return 'Memcached' }
        27017 { return 'MongoDB' }
        default { return 'servicio' }
    }
}

function P20-PortFix {
    param([int] $Port)
    switch ($Port) {
        21 { return 'Deshabilite el servidor FTP o restrinjala por firewall: New-NetFirewallRule -DisplayName "Bloquear FTP" -Direction Inbound -LocalPort 21 -Protocol TCP -Action Block' }
        23 { return 'Telnet transmite en claro. Deshabilite el servicio y bloquee el puerto 23.' }
        135 { return 'Restrinja RPC a la red de administracion con una regla de firewall de entrada acotada.' }
        139 { return 'Deshabilite NetBIOS sobre TCP/IP en las propiedades del adaptador.' }
        445 { return 'SMB no debe exponerse a Internet. Restrinja el puerto 445 a la LAN y revise Set-SmbServerConfiguration -RequireSecuritySignature $true.' }
        1433 { return 'No exponga SQL Server. Restrinja por firewall y exija autenticacion Windows.' }
        2375 { return 'El socket de Docker sin TLS equivale a root remoto. Use 2376 con TLS o no lo exponga.' }
        3306 { return 'Restrinja MySQL a localhost: bind-address = 127.0.0.1 en my.ini.' }
        3389 { return 'RDP expuesto. Cierre el puerto, exija NLA y use VPN o RD Gateway.' }
        5432 { return 'Restrinja PostgreSQL en postgresql.conf (listen_addresses) y en pg_hba.conf.' }
        5900 { return 'VNC expuesto. Use tunel SSH y deshabilite el acceso directo.' }
        5985 { return 'WinRM HTTP sin cifrar. Use 5986 con TLS o deshabilite WinRM.' }
        5986 { return 'Restrinja WinRM HTTPS a la red de administracion.' }
        6379 { return 'Redis sin autenticacion expuesto. Bind a 127.0.0.1 y exija requirepass.' }
        9200 { return 'Elasticsearch expuesto. Habilite seguridad (xpack.security) y restrinja por firewall.' }
        11211 { return 'Memcached expuesto permite amplificacion DDoS. Bind a localhost y bloquee UDP/11211.' }
        27017 { return 'MongoDB expuesto. Habilite autorizacion y bindIp a 127.0.0.1.' }
        default { return 'Restrinja el puerto con una regla de firewall de entrada acotada a la red de administracion.' }
    }
}
