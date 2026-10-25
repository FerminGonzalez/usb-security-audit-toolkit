<#
  P40-Hardening.ps1
  USB Security Audit Toolkit - hardening con verificacion y rollback
  Dueno: UNIDAD C | Version: 1.0.0
  PowerShell 5.1 compatible

  SIN -Apply: solo compara estado actual contra deseado. NO escribe nada.
  CON -Apply: aplica, vuelve a leer para verificar, y genera rollback.

  Nunca toca: BitLocker, cuentas de usuario, contrasenas, discos, VMs.
#>

function P40-GetAsrMap {
    $map = @{}
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $ids = @($pref.AttackSurfaceReductionRules_Ids)
        $acts = @($pref.AttackSurfaceReductionRules_Actions)
        for ($i = 0; $i -lt $ids.Count; $i++) {
            $a = ''
            if ($i -lt $acts.Count) { $a = [string]$acts[$i] }
            $map[([string]$ids[$i]).ToUpper()] = $a
        }
    }
    catch { }
    return $map
}

function Invoke-Hardening {
    param([Parameter(Mandatory = $true)] $Ctx)

    $apply = [bool]$Ctx.Apply
    if ($apply) {
        Write-Log -Level WARN -Message 'HARDENING: MODO APLICAR - se modificara la configuracion del sistema'
    }
    else {
        Write-Log -Level INFO -Message 'HARDENING: modo diagnostico (no se modifica nada)'
    }

    $skip = @()
    try { $skip = @($Ctx.Config['hardening']['skip_controls'] | Where-Object { $_ }) } catch { }
    $deep = ($Ctx.Mode -eq 'completo')

    $rollback = New-Object System.Collections.ArrayList
    $planRows = New-Object System.Collections.ArrayList
    $beforeRows = New-Object System.Collections.ArrayList
    $afterRows = New-Object System.Collections.ArrayList

    $asrGuids = @(
        'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550',
        'D4F940AB-401B-4EFC-AADC-AD5F3C50688A',
        '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC',
        '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B',
        '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2',
        'E6DB77E5-3DF2-4CF1-B95A-636979351E5B',
        'D1E49AAC-8F56-4280-B9BA-993A6D77406C',
        'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4'
    )

    # ================================================================ H01 Defender CloudBlockLevel
    # Se guarda el valor anterior: revertir a "Default" no devuelve el estado
    # original de un equipo que ya estaba en High.
    $cblPrev = $null
    try { $cblPrev = [int](Get-MpPreference -ErrorAction Stop).CloudBlockLevel } catch { $cblPrev = $null }
    $cblPrevJson = '{}'
    try { $cblPrevJson = (@{ v = $cblPrev } | ConvertTo-Json -Compress) } catch { }

    $c = @{
        Id = 'H01'; Name = 'Nivel de bloqueo en la nube de Defender'; Severity = 'Medium'; Category = 'Defender'; Reboot = $false
        Problem = 'Defender no usa el nivel de bloqueo en la nube mas estricto'
        Remediation = 'Set-MpPreference -CloudBlockLevel High'
        Check = {
            $v = 0
            try { $v = [int](Get-MpPreference -ErrorAction Stop).CloudBlockLevel } catch { return @{ Compliant = $false; Current = 'no consultable' } }
            return @{ Compliant = ($v -ge 2); Current = ('CloudBlockLevel={0}' -f $v) }
        }
        Apply = {
            Set-MpPreference -CloudBlockLevel High -ErrorAction Stop
            $v = [int](Get-MpPreference -ErrorAction Stop).CloudBlockLevel
            return @{ Ok = ($v -ge 2); Now = ('CloudBlockLevel={0}' -f $v) }
        }
        Revert = 'P40-RevertCloudBlockLevel'
        RevertData = $cblPrevJson
    }
    $controls = New-Object System.Collections.ArrayList
    [void]$controls.Add($c)

    # ================================================================ H02 Reglas ASR
    $asrPrev = P40-GetAsrMap
    $asrPrevJson = '{}'
    if ($asrPrev.Count -gt 0) {
        try { $asrPrevJson = ($asrPrev | ConvertTo-Json -Compress) } catch { $asrPrevJson = '{}' }
    }
    $asrGuidList = $asrGuids -join ','

    $c = @{
        Id = 'H02'; Name = 'Reglas ASR de Defender en modo Block (8)'; Severity = 'High'; Category = 'Defender'; Reboot = $false
        Problem = 'Faltan reglas ASR o no estan en modo bloqueo'
        Remediation = 'Add-MpPreference -AttackSurfaceReductionRules_Ids <guid> -AttackSurfaceReductionRules_Actions Enabled'
        Check = {
            $map = P40-GetAsrMap
            $missing = @()
            foreach ($g in $asrGuids) {
                $k = $g.ToUpper()
                if (-not $map.ContainsKey($k)) { $missing += $g }
                else {
                    $a = [string]$map[$k]
                    if ($a -ne '1' -and $a -ne 'Enabled') { $missing += ($g + '(' + $a + ')') }
                }
            }
            return @{ Compliant = ($missing.Count -eq 0); Current = $(if ($missing.Count -eq 0) { '8/8 reglas en Block' } else { ('{0}/8 conformes; faltan: {1}' -f (8 - $missing.Count), ($missing -join ', ')) }) }
        }
        Apply = {
            foreach ($g in $asrGuids) {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $g -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
            }
            $map = P40-GetAsrMap
            $bad = 0
            foreach ($g in $asrGuids) {
                $k = $g.ToUpper()
                if (-not $map.ContainsKey($k)) { $bad++ }
                else {
                    $a = [string]$map[$k]
                    if ($a -ne '1' -and $a -ne 'Enabled') { $bad++ }
                }
            }
            return @{ Ok = ($bad -eq 0); Now = ('{0}/8 reglas en Block' -f (8 - $bad)) }
        }
        Revert = "P40-RevertAsr"
        RevertData = $asrPrevJson
    }
    [void]$controls.Add($c)

    # ================================================================ H03 Firewall
    $fwPrev = @{}
    try {
        foreach ($p in @(Get-NetFirewallProfile -ErrorAction Stop)) {
            $fwPrev[[string]$p.Name] = @{ Inbound = [string]$p.DefaultInboundAction; LogBlocked = [bool]$p.LogBlocked }
        }
    }
    catch { }
    $fwPrevJson = '{}'
    if ($fwPrev.Count -gt 0) { try { $fwPrevJson = ($fwPrev | ConvertTo-Json -Compress -Depth 4) } catch { } }

    $c = @{
        Id = 'H03'; Name = 'Firewall: entrante bloqueado y registro activo'; Severity = 'High'; Category = 'Firewall'; Reboot = $false
        Problem = 'El firewall no bloquea el trafico entrante por defecto'
        Remediation = 'Set-NetFirewallProfile -All -DefaultInboundAction Block -LogBlocked True'
        Check = {
            $bad = @()
            try {
                foreach ($p in @(Get-NetFirewallProfile -ErrorAction Stop)) {
                    if (-not $p.Enabled) { $bad += ($p.Name + ':deshabilitado') }
                    elseif ([string]$p.DefaultInboundAction -ne 'Block') { $bad += ($p.Name + ':' + $p.DefaultInboundAction) }
                    elseif (-not $p.LogBlocked) { $bad += ($p.Name + ':sin-log') }
                }
            }
            catch { return @{ Compliant = $false; Current = 'no consultable' } }
            return @{ Compliant = ($bad.Count -eq 0); Current = $(if ($bad.Count -eq 0) { '3 perfiles: inbound Block + LogBlocked' } else { ($bad -join ', ') }) }
        }
        Apply = {
            Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -LogBlocked True -ErrorAction Stop
            $bad = 0
            foreach ($p in @(Get-NetFirewallProfile -ErrorAction Stop)) {
                if (-not $p.Enabled -or [string]$p.DefaultInboundAction -ne 'Block' -or -not $p.LogBlocked) { $bad++ }
            }
            return @{ Ok = ($bad -eq 0); Now = ('{0} perfil(es) fuera de politica' -f $bad) }
        }
        Revert = 'P40-RevertFirewall'
        RevertData = $fwPrevJson
    }
    [void]$controls.Add($c)

    # ================================================================ H04 SMB1 + firma
    $smbPrev = @{ EnableSMB1 = $null; RequireSign = $null }
    try {
        $sc = Get-SmbServerConfiguration -ErrorAction Stop
        $smbPrev.EnableSMB1 = [bool]$sc.EnableSMB1Protocol
        $smbPrev.RequireSign = [bool]$sc.RequireSecuritySignature
    }
    catch { }
    $smbPrevJson = '{}'
    if ($null -ne $smbPrev.EnableSMB1) { try { $smbPrevJson = ($smbPrev | ConvertTo-Json -Compress) } catch { } }

    $c = @{
        Id = 'H04'; Name = 'SMBv1 deshabilitado y firma SMB obligatoria'; Severity = 'High'; Category = 'Protocolos'; Reboot = $false
        Problem = 'SMBv1 habilitado o firma SMB no obligatoria'
        Remediation = 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true -Force'
        Check = {
            try {
                $sc = Get-SmbServerConfiguration -ErrorAction Stop
            }
            catch { return @{ Compliant = $false; Current = 'no consultable (requiere admin)' } }
            $bad = @()
            if ($sc.EnableSMB1Protocol) { $bad += 'SMB1=True' }
            if (-not $sc.RequireSecuritySignature) { $bad += 'FirmaSMB=False' }
            return @{ Compliant = ($bad.Count -eq 0); Current = $(if ($bad.Count -eq 0) { 'SMB1 off, firma on' } else { ($bad -join ', ') }) }
        }
        Apply = {
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true -Force -ErrorAction Stop
            $sc = Get-SmbServerConfiguration -ErrorAction Stop
            return @{ Ok = ((-not $sc.EnableSMB1Protocol) -and $sc.RequireSecuritySignature); Now = ('SMB1={0}, firma={1}' -f $sc.EnableSMB1Protocol, $sc.RequireSecuritySignature) }
        }
        Revert = 'P40-RevertSmb'
        RevertData = $smbPrevJson
    }
    [void]$controls.Add($c)

    # ================================================================ H05 RDP + Asistencia remota
    $rdpPrev = @{ Rdp = $null; RA = $null }
    $rdpPrev.Rdp = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Default $null
    $rdpPrev.RA  = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Default $null
    $rdpPrevJson = '{}'
    try { $rdpPrevJson = ($rdpPrev | ConvertTo-Json -Compress) } catch { }

    $c = @{
        Id = 'H05'; Name = 'RDP y Asistencia remota deshabilitados'; Severity = 'Medium'; Category = 'Acceso remoto'; Reboot = $false
        Problem = 'RDP o Asistencia remota permiten acceso remoto entrante'
        Remediation = 'Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" fDenyTSConnections 1'
        Check = {
            $rdp = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Default 1
            $ra  = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Default 0
            $bad = @()
            if ([int]$rdp -eq 0) { $bad += 'RDP habilitado' }
            if ([int]$ra -eq 1) { $bad += 'Asistencia remota habilitada' }
            return @{ Compliant = ($bad.Count -eq 0); Current = $(if ($bad.Count -eq 0) { "RDP off (fDenyTSConnections=$rdp), RA off" } else { ($bad -join ', ') }) }
        }
        Apply = {
            [void](Set-RegValueChecked -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1 -Type DWord -ControlId 'H05')
            [void](Set-RegValueChecked -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value 0 -Type DWord -ControlId 'H05')
            $rdp = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Default 1
            $ra  = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Default 0
            return @{ Ok = (([int]$rdp -eq 1) -and ([int]$ra -eq 0)); Now = ('fDenyTSConnections={0}, fAllowToGetHelp={1}' -f $rdp, $ra) }
        }
        Revert = 'P40-RevertRdp'
        RevertData = $rdpPrevJson
    }
    [void]$controls.Add($c)

    # ================================================================ H06 AutoRun / AutoPlay
    $autorunPrev = @{}
    foreach ($p in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
                     'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer')) {
        $autorunPrev[$p] = Get-RegValue -Path $p -Name 'NoDriveTypeAutoRun' -Default $null
    }
    # NoAutorun tambien se escribe en Apply: si ya existia hay que restaurar su
    # valor, no borrarlo. Antes la reversion lo eliminaba siempre y dejaba el
    # equipo distinto de como estaba.
    $autorunPrev['__NoAutorun'] = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutorun' -Default $null
    $autorunPrevJson = '{}'
    try { $autorunPrevJson = ($autorunPrev | ConvertTo-Json -Compress) } catch { }

    $c = @{
        Id = 'H06'; Name = 'AutoRun y AutoPlay deshabilitados'; Severity = 'Medium'; Category = 'Protocolos'; Reboot = $false
        Problem = 'AutoRun/AutoPlay no esta bloqueado en todas las unidades'
        Remediation = 'Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" NoDriveTypeAutoRun 255'
        Check = {
            $hklm = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Default 0
            $hkcu = Get-RegValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Default 0
            $noAuto = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutorun' -Default 0
            $bad = @()
            if ([int]$hklm -ne 255) { $bad += ('HKLM NoDriveTypeAutoRun={0}' -f $hklm) }
            if ([int]$hkcu -ne 255) { $bad += ('HKCU NoDriveTypeAutoRun={0}' -f $hkcu) }
            if ([int]$noAuto -ne 1) { $bad += ('NoAutorun={0}' -f $noAuto) }
            return @{ Compliant = ($bad.Count -eq 0); Current = $(if ($bad.Count -eq 0) { 'AutoRun bloqueado en todos los tipos de unidad' } else { ($bad -join ', ') }) }
        }
        Apply = {
            [void](Set-RegValueChecked -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord -ControlId 'H06')
            [void](Set-RegValueChecked -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord -ControlId 'H06')
            [void](Set-RegValueChecked -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutorun' -Value 1 -Type DWord -ControlId 'H06')
            $hklm = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Default 0
            $hkcu = Get-RegValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Default 0
            return @{ Ok = (([int]$hklm -eq 255) -and ([int]$hkcu -eq 255)); Now = ('HKLM={0}, HKCU={1}' -f $hklm, $hkcu) }
        }
        Revert = 'P40-RevertAutorun'
        RevertData = $autorunPrevJson
    }
    [void]$controls.Add($c)

    # ================================================================ H07 Registro de PowerShell
    $psLogPrev = @{}
    $sbPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $mlPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    $psLogPrev['sb'] = Get-RegValue -Path $sbPath -Name 'EnableScriptBlockLogging' -Default $null
    $psLogPrev['ml'] = Get-RegValue -Path $mlPath -Name 'EnableModuleLogging' -Default $null
    $psLogPrevJson = '{}'
    try { $psLogPrevJson = ($psLogPrev | ConvertTo-Json -Compress) } catch { }

    $c = @{
        Id = 'H07'; Name = 'Registro de bloques de script y modulos'; Severity = 'Medium'; Category = 'Registro'; Reboot = $false
        Problem = 'El registro de PowerShell (script blocks y modulos) esta incompleto'
        Remediation = 'Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" EnableScriptBlockLogging 1'
        Check = {
            $sb = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Default 0
            $ml = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -Default 0
            $bad = @()
            if ([int]$sb -ne 1) { $bad += ('ScriptBlockLogging={0}' -f $sb) }
            if ([int]$ml -ne 1) { $bad += ('ModuleLogging={0}' -f $ml) }
            return @{ Compliant = ($bad.Count -eq 0); Current = $(if ($bad.Count -eq 0) { 'ambos registros activos' } else { ($bad -join ', ') }) }
        }
        Apply = {
            [void](Set-RegValueChecked -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord -ControlId 'H07')
            [void](Set-RegValueChecked -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -Value 1 -Type DWord -ControlId 'H07')
            $sb = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Default 0
            $ml = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -Default 0
            return @{ Ok = (([int]$sb -eq 1) -and ([int]$ml -eq 1)); Now = ('ScriptBlock={0}, Module={1}' -f $sb, $ml) }
        }
        Revert = 'P40-RevertPsLog'
        RevertData = $psLogPrevJson
    }
    [void]$controls.Add($c)

    # ================================================================ H08 SmartScreen
    $ssPrev = @{}
    $ssPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
    $ssPol  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
    $ssPrev['enabled'] = Get-RegValue -Path $ssPath -Name 'SmartScreenEnabled' -Default $null
    $ssPrev['policy']  = Get-RegValue -Path $ssPol -Name 'EnableSmartScreen' -Default $null
    $ssPrevJson = '{}'
    try { $ssPrevJson = ($ssPrev | ConvertTo-Json -Compress) } catch { }

    $c = @{
        Id = 'H08'; Name = 'SmartScreen en modo Warn'; Severity = 'Medium'; Category = 'Defender'; Reboot = $false
        Problem = 'SmartScreen no advierte sobre ejecutables no firmados'
        Remediation = 'Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" SmartScreenEnabled "Warn"'
        Check = {
            $v = [string](Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled' -Default '')
            $ok = ($v -eq 'Warn' -or $v -eq 'RequireAdmin')
            return @{ Compliant = $ok; Current = ('SmartScreenEnabled="{0}"' -f $v) }
        }
        Apply = {
            [void](Set-RegValueChecked -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled' -Value 'Warn' -Type String -ControlId 'H08')
            [void](Set-RegValueChecked -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen' -Value 1 -Type DWord -ControlId 'H08')
            [void](Set-RegValueChecked -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'ShellSmartScreenLevel' -Value 'Warn' -Type String -ControlId 'H08')
            $v = [string](Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled' -Default '')
            return @{ Ok = ($v -eq 'Warn'); Now = ('SmartScreenEnabled="{0}"' -f $v) }
        }
        Revert = 'P40-RevertSmartScreen'
        RevertData = $ssPrevJson
    }
    [void]$controls.Add($c)

    # ================================================================ H09 LLMNR
    $llmnrPrev = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Default $null
    $llmnrPrevJson = '{}'
    try { $llmnrPrevJson = (@{ v = $llmnrPrev } | ConvertTo-Json -Compress) } catch { }

    $c = @{
        Id = 'H09'; Name = 'LLMNR deshabilitado'; Severity = 'Medium'; Category = 'Red'; Reboot = $false
        Problem = 'LLMNR habilitado: permite suplantacion por broadcast'
        Remediation = 'Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" EnableMulticast 0'
        Check = {
            $v = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Default 1
            return @{ Compliant = ([int]$v -eq 0); Current = ('EnableMulticast={0}' -f $v) }
        }
        Apply = {
            [void](Set-RegValueChecked -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0 -Type DWord -ControlId 'H09')
            $v = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Default 1
            return @{ Ok = ([int]$v -eq 0); Now = ('EnableMulticast={0}' -f $v) }
        }
        Revert = 'P40-RevertLlmnr'
        RevertData = $llmnrPrevJson
    }
    [void]$controls.Add($c)

    # ================================================================ H10 UAC
    $uacPrev = @{}
    $uacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    foreach ($n in @('ConsentPromptBehaviorAdmin', 'PromptOnSecureDesktop')) {
        $uacPrev[$n] = Get-RegValue -Path $uacPath -Name $n -Default $null
    }
    $uacPrevJson = '{}'
    try { $uacPrevJson = ($uacPrev | ConvertTo-Json -Compress) } catch { }

    $c = @{
        Id = 'H10'; Name = 'UAC solicita consentimiento en escritorio seguro'; Severity = 'High'; Category = 'UAC'; Reboot = $false
        Problem = 'UAC no exige consentimiento en el escritorio seguro'
        Remediation = 'Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" ConsentPromptBehaviorAdmin 2'
        Check = {
            $consent = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Default 5
            $desk    = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Default 1
            $bad = @()
            if ([int]$consent -ne 2) { $bad += ('ConsentPromptBehaviorAdmin={0} (deseado 2)' -f $consent) }
            if ([int]$desk -ne 1) { $bad += ('PromptOnSecureDesktop={0} (deseado 1)' -f $desk) }
            return @{ Compliant = ($bad.Count -eq 0); Current = $(if ($bad.Count -eq 0) { 'ConsentPromptBehaviorAdmin=2, PromptOnSecureDesktop=1' } else { ($bad -join ', ') }) }
        }
        Apply = {
            [void](Set-RegValueChecked -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Type DWord -ControlId 'H10')
            [void](Set-RegValueChecked -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Value 1 -Type DWord -ControlId 'H10')
            $consent = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Default 5
            $desk    = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Default 1
            return @{ Ok = (([int]$consent -eq 2) -and ([int]$desk -eq 1)); Now = ('consent={0}, secureDesktop={1}' -f $consent, $desk) }
        }
        Revert = 'P40-RevertUac'
        RevertData = $uacPrevJson
    }
    [void]$controls.Add($c)

    # ================================================================ H11 WDigest
    $wdPrev = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Default $null
    $wdPrevJson = '{}'
    try { $wdPrevJson = (@{ v = $wdPrev } | ConvertTo-Json -Compress) } catch { }

    $c = @{
        Id = 'H11'; Name = 'WDigest no almacena credenciales en claro'; Severity = 'Critical'; Category = 'Credenciales'; Reboot = $false
        Problem = 'WDigest guarda contrasenas en texto claro en memoria'
        Remediation = 'Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" UseLogonCredential 0'
        Check = {
            $v = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Default 0
            return @{ Compliant = ([int]$v -eq 0); Current = ('UseLogonCredential={0}' -f $v) }
        }
        Apply = {
            [void](Set-RegValueChecked -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0 -Type DWord -ControlId 'H11')
            $v = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Default 0
            return @{ Ok = ([int]$v -eq 0); Now = ('UseLogonCredential={0}' -f $v) }
        }
        Revert = 'P40-RevertWdigest'
        RevertData = $wdPrevJson
    }
    [void]$controls.Add($c)

    # ================================================================ H12 LSA RunAsPPL
    $pplPrev = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Default $null
    $pplPrevJson = '{}'
    try { $pplPrevJson = (@{ v = $pplPrev } | ConvertTo-Json -Compress) } catch { }

    $c = @{
        Id = 'H12'; Name = 'LSASS protegido (RunAsPPL)'; Severity = 'High'; Category = 'Credenciales'; Reboot = $true
        Problem = 'LSASS no esta protegido como proceso ligero (RunAsPPL ausente): la memoria del proceso puede volcarse y extraerse con Mimikatz.'
        Remediation = 'Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" RunAsPPL 1 ; requiere reinicio'
        Check = {
            # 1 = con bloqueo UEFI, 2 = sin bloqueo UEFI; ambos activan PPL.
            $v = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Default 0
            return @{ Compliant = ([int]$v -ge 1); Current = ('RunAsPPL={0}' -f $v) }
        }
        Apply = {
            [void](Set-RegValueChecked -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1 -Type DWord -ControlId 'H12')
            $v = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Default 0
            return @{ Ok = ([int]$v -ge 1); Now = ('RunAsPPL={0} (efectivo tras reiniciar)' -f $v) }
        }
        Revert = 'P40-RevertRunAsPpl'
        RevertData = $pplPrevJson
    }
    [void]$controls.Add($c)

    # ================================================================ H13 AlwaysInstallElevated
    $aiePrev = @{}
    $aiePrev['hklm'] = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Default $null
    $aiePrev['hkcu'] = Get-RegValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Default $null
    $aiePrevJson = '{}'
    try { $aiePrevJson = ($aiePrev | ConvertTo-Json -Compress) } catch { }

    $c = @{
        Id = 'H13'; Name = 'AlwaysInstallElevated desactivado'; Severity = 'Critical'; Category = 'Credenciales'; Reboot = $false
        Problem = 'AlwaysInstallElevated permite instalar MSI con privilegios'
        Remediation = 'Elimine AlwaysInstallElevated en HKLM y HKCU bajo Policies\Microsoft\Windows\Installer'
        Check = {
            $hklm = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Default 0
            $hkcu = Get-RegValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Default 0
            $bad = @()
            if ([int]$hklm -ne 0) { $bad += ('HKLM={0}' -f $hklm) }
            if ([int]$hkcu -ne 0) { $bad += ('HKCU={0}' -f $hkcu) }
            return @{ Compliant = ($bad.Count -eq 0); Current = $(if ($bad.Count -eq 0) { 'HKLM=0, HKCU=0' } else { ($bad -join ', ') }) }
        }
        Apply = {
            [void](Set-RegValueChecked -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Value 0 -Type DWord -ControlId 'H13')
            [void](Set-RegValueChecked -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Value 0 -Type DWord -ControlId 'H13')
            $hklm = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Default 0
            $hkcu = Get-RegValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Default 0
            return @{ Ok = (([int]$hklm -eq 0) -and ([int]$hkcu -eq 0)); Now = ('HKLM={0}, HKCU={1}' -f $hklm, $hkcu) }
        }
        Revert = 'P40-RevertAie'
        RevertData = $aiePrevJson
    }
    [void]$controls.Add($c)

    # ================================================================ H14 AutoLogon (solo informe)
    $c = @{
        Id = 'H14'; Name = 'Sin contrasena de autologon en el registro'; Severity = 'Critical'; Category = 'Credenciales'; Reboot = $false
        Problem = 'Hay una contrasena de autologon en texto claro en el registro'
        Remediation = 'Elimine DefaultPassword de HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon o migre a Sysinternals Autologon.'
        Check = {
            $pwd = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultPassword' -Default ''
            $auto = [string](Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon' -Default '0')
            $has = [bool]$pwd
            $detail = 'DefaultPassword ausente'
            if ($has) { $detail = ('DefaultPassword PRESENTE (cuenta: {0}, AutoAdminLogon={1})' -f (Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultUserName' -Default '?'), $auto) }
            return @{ Compliant = (-not $has); Current = $detail }
        }
        Apply = $null       # se gestiona aparte: NUNCA se aplica automaticamente
        Revert = ''
        RevertData = ''
        NeverApply = $true
        SkipReason = 'Contiene una contrasena en claro: borrarla rompe el autologon. Requiere decision manual del operador.'
    }
    [void]$controls.Add($c)

    # ================================================================ H15 PowerShell v2
    # Estado previo de PSv2 sin DISM: la consulta oficial tarda minutos y puede
    # fallar incluso con elevacion. Get-PsV2State responde en milisegundos.
    $v2Prev = Get-PsV2State
    $v2PrevJson = '{}'
    try { $v2PrevJson = (@{ state = $v2Prev.State; source = $v2Prev.Source } | ConvertTo-Json -Compress) } catch { }

    $c = @{
        Id = 'H15'; Name = 'Motor PowerShell v2 deshabilitado'; Severity = 'Medium'; Category = 'Registro'; Reboot = $false
        Problem = 'El motor PowerShell 2.0 sigue instalado: permite ejecutar codigo evadiendo ScriptBlockLogging y las restricciones del motor actual.'
        Remediation = 'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart'
        Check = {
            $st = Get-PsV2State
            switch ($st.State) {
                'Enabled' { return @{ Compliant = $false; Current = ('MicrosoftWindowsPowerShellV2=Enabled ({0})' -f $st.Source) } }
                'Disabled' { return @{ Compliant = $true; Current = ('MicrosoftWindowsPowerShellV2=Disabled ({0})' -f $st.Source) } }
                'Absent' { return @{ Compliant = $true; Current = ('caracteristica no instalada ({0})' -f $st.Source) } }
            }
            return @{ Compliant = $null; Unknown = $true; Current = ('no verificable: {0}' -f $st.Source) }
        }
        Apply = {
            $st = Get-PsV2State
            if ($st.State -eq 'Disabled' -or $st.State -eq 'Absent') {
                return @{ Ok = $true; Now = ('nada que desinstalar: {0}' -f $st.State) }
            }
            # DISM solo se invoca aqui, cuando el operador pidio aplicar el control.
            Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart -ErrorAction Stop | Out-Null
            Reset-PsV2StateCache
            $now = Get-PsV2State
            return @{ Ok = ($now.State -ne 'Enabled'); Now = ('estado={0} ({1})' -f $now.State, $now.Source) }
        }
        Revert = 'P40-RevertPsV2'
        RevertData = $v2PrevJson
    }
    [void]$controls.Add($c)

    # ================================================================ H16 NBT-NS (solo completo)
    $nbtPrev = @{}
    $nbtBase = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
    try {
        foreach ($i in @(Get-ChildItem $nbtBase -ErrorAction Stop)) {
            $nbtPrev[$i.PSChildName] = Get-RegValue -Path $i.PSPath -Name 'NetbiosOptions' -Default $null
        }
    }
    catch { }
    $nbtPrevJson = '{}'
    try { $nbtPrevJson = ($nbtPrev | ConvertTo-Json -Compress) } catch { }

    $c = @{
        Id = 'H16'; Name = 'NetBIOS sobre TCP/IP deshabilitado por interfaz'; Severity = 'Low'; Category = 'Red'; Reboot = $false
        Problem = 'NetBIOS sobre TCP/IP activo: permite poisoning por NBT-NS'
        DeepOnly = $true
        Remediation = 'Set NetbiosOptions=2 en cada interfaz de HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
        Check = {
            $bad = @()
            try {
                foreach ($i in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction Stop)) {
                    $v = Get-RegValue -Path $i.PSPath -Name 'NetbiosOptions' -Default 0
                    if ([int]$v -ne 2) { $bad += $i.PSChildName }
                }
            }
            catch { return @{ Compliant = $false; Current = 'no consultable' } }
            return @{ Compliant = ($bad.Count -eq 0); Current = $(if ($bad.Count -eq 0) { 'NetBIOS deshabilitado en todas las interfaces' } else { ('interfaces con NetBIOS activo: {0}' -f ($bad -join ', ')) }) }
        }
        Apply = {
            $n = 0
            foreach ($i in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction Stop)) {
                [void](Set-RegValueChecked -Path $i.PSPath -Name 'NetbiosOptions' -Value 2 -Type DWord -ControlId 'H16')
                $n++
            }
            $bad = 0
            foreach ($i in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction Stop)) {
                $v = Get-RegValue -Path $i.PSPath -Name 'NetbiosOptions' -Default 0
                if ([int]$v -ne 2) { $bad++ }
            }
            return @{ Ok = ($bad -eq 0); Now = ('{0} interfaces revisadas, {1} fuera de politica' -f $n, $bad) }
        }
        Revert = 'P40-RevertNbt'
        RevertData = $nbtPrevJson
    }
    [void]$controls.Add($c)

    # ================================================================ EJECUCION
    $applied = New-Object System.Collections.ArrayList
    $skipped = New-Object System.Collections.ArrayList
    $pending = New-Object System.Collections.ArrayList
    $manual  = New-Object System.Collections.ArrayList
    $compliantCount = 0

    foreach ($ctl in $controls) {
        $id = $ctl.Id
        # El Name describe el estado deseado; el hallazgo debe enunciar el riesgo.
        $problemTitle = [string]$ctl.Name
        if ($ctl.ContainsKey('Problem') -and $ctl.Problem) { $problemTitle = [string]$ctl.Problem }

        # Saltos declarados por configuracion
        if ($skip -contains $id) {
            [void]$skipped.Add($id)
            [void]$planRows.Add(@{ id = $id; name = $ctl.Name; status = 'skipped'; reason = 'omitido por configuracion (skip_controls)'; compliant = $null })
            Write-Log -Level INFO -Message ('  {0}: OMITIDO por configuracion' -f $id)
            continue
        }

        # Solo modo completo
        if ($ctl.ContainsKey('DeepOnly') -and $ctl.DeepOnly -and -not $deep) {
            [void]$skipped.Add($id)
            [void]$planRows.Add(@{ id = $id; name = $ctl.Name; status = 'skipped'; reason = 'solo se evalua en modo completo'; compliant = $null })
            continue
        }

        # Controles que nunca se aplican automaticamente
        if ($ctl.ContainsKey('NeverApply') -and $ctl.NeverApply) {
            $st = $null
            $checkFn = $ctl.Check
            Invoke-Checked -Name ('HRD-' + $id + '-check') -Block {
                $script:P40TmpState = & $checkFn
            }
            $st = $script:P40TmpState
            $script:P40TmpState = $null

            [void]$beforeRows.Add(@{ id = $id; current = $st.Current; compliant = $st.Compliant })
            if (-not $st.Compliant) {
                [void]$skipped.Add($id)
                [void]$manual.Add($id)
                Add-Finding -Id ('HRD-' + $id) -Severity $ctl.Severity -Category $ctl.Category `
                    -Title ($problemTitle + ' (accion manual)') `
                    -Detail ($st.Current + '. ' + $ctl.SkipReason) `
                    -Remediation $ctl.Remediation `
                    -Evidence 'hardening-before.json'
                [void]$planRows.Add(@{ id = $id; name = $ctl.Name; status = 'manual'; reason = $ctl.SkipReason; compliant = $false })
            }
            else {
                $compliantCount++
                [void]$planRows.Add(@{ id = $id; name = $ctl.Name; status = 'compliant'; reason = ''; compliant = $true })
            }
            continue
        }

        $checkFn = $ctl.Check
        $applyFn = $ctl.Apply

        $state = $null
        Invoke-Checked -Name ('HRD-' + $id + '-check') -Block {
            $script:P40TmpState = & $checkFn
        }
        $state = $script:P40TmpState
        $script:P40TmpState = $null

        if ($null -eq $state) {
            [void]$planRows.Add(@{ id = $id; name = $ctl.Name; status = 'error'; reason = 'check no devolvio estado'; compliant = $null })
            continue
        }

        # "No verificable" no es "no conforme": sin elevacion no se puede
        # afirmar un incumplimiento. Se registra como Info y no puntua.
        if ($state.ContainsKey('Unknown') -and $state.Unknown) {
            Add-Finding -Id ('HRD-SKIP-' + $id) -Severity 'Info' -Category $ctl.Category `
                -Title ('Sin verificar: ' + $ctl.Name) `
                -Detail ($state.Current + '. Requiere privilegios de administrador para evaluarse.') `
                -Remediation 'Repita la auditoria elevada para obtener el estado real de este control.' `
                -Evidence 'hardening-before.json'
            [void]$beforeRows.Add(@{ id = $id; current = $state.Current; compliant = $null })
            [void]$planRows.Add(@{ id = $id; name = $ctl.Name; status = 'unknown'; reason = $state.Current; compliant = $null })
            continue
        }

        [void]$beforeRows.Add(@{ id = $id; current = $state.Current; compliant = $state.Compliant })

        if ($state.Compliant) {
            $compliantCount++
            [void]$planRows.Add(@{ id = $id; name = $ctl.Name; status = 'compliant'; reason = ''; compliant = $true })
            continue
        }

        # No conforme
        if (-not $apply) {
            [void]$pending.Add($id)
            Add-Finding -Id ('HRD-' + $id) -Severity $ctl.Severity -Category $ctl.Category `
                -Title $problemTitle `
                -Detail $state.Current `
                -Remediation $ctl.Remediation `
                -Evidence 'hardening-before.json'
            [void]$planRows.Add(@{ id = $id; name = $ctl.Name; status = 'pending'; reason = $state.Current; compliant = $false })
            continue
        }

        # Aplicar
        $result = $null
        Invoke-Checked -Name ('HRD-' + $id + '-apply') -Block {
            $script:P40TmpResult = & $applyFn
        }
        $result = $script:P40TmpResult
        $script:P40TmpResult = $null

        # Verificacion independiente: volver a leer
        $verify = $null
        Invoke-Checked -Name ('HRD-' + $id + '-verify') -Block {
            $script:P40TmpVerify = & $checkFn
        }
        $verify = $script:P40TmpVerify
        $script:P40TmpVerify = $null

        $ok = $false
        if ($null -ne $verify) { $ok = [bool]$verify.Compliant }

        [void]$afterRows.Add(@{ id = $id; current = $(if ($verify) { $verify.Current } else { 'no verificado' }); compliant = $ok })

        if ($ok) {
            [void]$applied.Add($id)
            Add-Finding -Id ('HRD-' + $id) -Severity 'Info' -Category $ctl.Category `
                -Title ('Aplicado: ' + $ctl.Name) `
                -Detail ('Estado previo: {0}. Estado actual: {1}.' -f $state.Current, $verify.Current) `
                -Remediation 'Ninguna.'
            [void]$planRows.Add(@{ id = $id; name = $ctl.Name; status = 'applied'; reason = ''; compliant = $true })
            Write-Log -Level OK -Message ('  {0}: APLICADO y verificado' -f $id)
        }
        else {
            Add-Finding -Id ('HRD-VERIFY-' + $id) -Severity 'High' -Category $ctl.Category `
                -Title ('Aplicado pero NO verificado: ' + $ctl.Name) `
                -Detail ('Se intento aplicar. Estado previo: {0}. Lectura posterior: {1}.' -f $state.Current, $(if ($verify) { $verify.Current } else { 'sin lectura' })) `
                -Remediation $ctl.Remediation
            [void]$planRows.Add(@{ id = $id; name = $ctl.Name; status = 'failed'; reason = 'no verificado tras aplicar'; compliant = $false })
            Write-Log -Level WARN -Message ('  {0}: aplicado pero NO verificado' -f $id)
        }

        # Entrada de rollback
        $prevEntry = $null
        if ($script:Ctx.Hardening.ContainsKey('Originals')) {
            foreach ($k in $script:Ctx.Hardening.Originals.Keys) {
                if ($k -like ($id + '|*')) { $prevEntry = $script:Ctx.Hardening.Originals[$k] }
            }
        }

        # Entrada de rollback.
        # Se guarda el NOMBRE de la funcion de reversion y su dato, no una
        # cadena de codigo: el JSON vive en el USB y el script de rollback se
        # ejecuta elevado. Guardar codigo obligaria a Invoke-Expression sobre
        # un archivo que un tercero puede haber modificado.
        [void]$rollback.Add(@{
            id          = $id
            name        = $ctl.Name
            category    = $ctl.Category
            requires_reboot = [bool]$ctl.Reboot
            previous    = $(if ($prevEntry) { $prevEntry.Value } else { $null })
            previous_existed = $(if ($prevEntry) { $prevEntry.Existed } else { $false })
            applied_at  = (Get-Date).ToString('o')
            verified    = $ok
            revert      = [string]$ctl.Revert
            data        = [string]$ctl.RevertData
        })
    }

    # ================================================================ SALIDAS
    [void](Write-Evidence -Name 'hardening-before.json' -Data $beforeRows)
    [void](Write-Evidence -Name 'hardening-plan.json' -Data $planRows)

    if ($apply -and $afterRows.Count -gt 0) {
        [void](Write-Evidence -Name 'hardening-after.json' -Data $afterRows)
    }

    if ($apply -and $rollback.Count -gt 0) {
        $rbName = 'rollback-' + $Ctx.Id + '.json'
        [void](Write-Evidence -Name $rbName -Data $rollback)
        $Ctx.Hardening['RollbackFile'] = $rbName
        P40-WriteRollbackScript -Ctx $Ctx -RollbackName $rbName
    }

    # ------------------------------------------------------------------ remediacion
    # Un .cmd con los comandos exactos para los controles que quedaron fuera de
    # politica. Sirve para aplicar sin -Apply, sin depender de este motor y en
    # equipos donde ejecutar PowerShell esta restringido por politica.
    $fixIds = @()
    if ($pending.Count -gt 0) { $fixIds = @($pending) }
    if ($apply) {
        $failedIds = @($planRows | Where-Object { $_.status -eq 'failed' } | ForEach-Object { [string]$_.id })
        if ($failedIds.Count -gt 0) { $fixIds = @($fixIds + $failedIds) }
    }
    if ($fixIds.Count -gt 0 -or $manual.Count -gt 0) {
        $remName = P40-WriteRemediationCmd -Ctx $Ctx -Ids $fixIds -ManualIds @($manual) -AsrGuids $asrGuids
        if ($remName) { $Ctx.Hardening['RemediationFile'] = [string]$remName }
    }

    $Ctx.Hardening['Applied'] = $applied
    $Ctx.Hardening['Skipped'] = $skipped
    $Ctx.Hardening['Pending'] = $pending

    Add-Metric -Name 'hardening_controls_total' -Value $controls.Count
    Add-Metric -Name 'hardening_compliant' -Value $compliantCount
    Add-Metric -Name 'hardening_applied' -Value $applied.Count
    Add-Metric -Name 'hardening_pending' -Value $pending.Count

    if (-not $apply) {
        if ($pending.Count -eq 0) {
            Add-Finding -Id 'HRD-OK-ALL' -Severity 'Info' -Category 'Hardening' `
                -Title 'Todos los controles evaluados ya cumplen' `
                -Detail ('{0} de {1} controles conformes.' -f $compliantCount, $controls.Count) `
                -Remediation 'Ninguna.'
        }
        else {
            $remFile = [string]$Ctx.Hardening['RemediationFile']
            $remHint = 'Ejecute INICIAR.cmd opcion 4 (rapido + aplicar hardening) o Audit-Windows.ps1 -Apply.'
            if ($remFile) { $remHint = 'Ejecute ' + $remFile + ' como administrador (esta en la carpeta de evidencia) para aplicar solo estos controles, o INICIAR.cmd opcion 4 para que el motor los aplique y verifique.' }
            $remEvidence = 'hardening-plan.json'
            if ($remFile) { $remEvidence = $remFile }
            Add-Finding -Id 'HRD-PEND' -Severity 'Info' -Category 'Hardening' `
                -Title ('Controles de hardening pendientes: {0}' -f $pending.Count) `
                -Detail ('Pendientes: {0}. Los comandos exactos estan en {1}.' -f ($pending -join ', '), $(if ($remFile) { $remFile } else { 'hardening-plan.json' })) `
                -Remediation $remHint `
                -Evidence $remEvidence
        }
    }
    else {
        Add-Finding -Id 'HRD-APPLIED' -Severity 'Info' -Category 'Hardening' `
            -Title ('Hardening aplicado: {0} control(es)' -f $applied.Count) `
            -Detail ('Aplicados y verificados: {0}. Omitidos: {1}. No verificados: {2}.' -f ($applied -join ', '), ($skipped -join ', '), (@($planRows | Where-Object { $_.status -eq 'failed' }).Count)) `
            -Remediation ('Rollback disponible en ' + [string]$Ctx.Hardening['RollbackFile']) `
            -Evidence 'hardening-plan.json'
    }

    $needReboot = @($controls | Where-Object { $_.Reboot -eq $true -and $applied -contains $_.Id })
    if ($needReboot.Count -gt 0) {
        Write-Log -Level WARN -Message ('  Reinicio necesario para que surtan efecto: {0}' -f (($needReboot | ForEach-Object { $_.Id }) -join ', '))
    }

    Write-Log -Level OK -Message ('HARDENING: {0} conformes, {1} aplicados, {2} pendientes' -f $compliantCount, $applied.Count, $pending.Count)
}

# ==================================================================== ROLLBACK

function P40-WriteRollbackScript {
    param($Ctx, [string] $RollbackName)

    $template = @'
<#
  Rollback-Hardening.ps1  (generado automaticamente)
  Revierte los cambios aplicados por el USB Security Audit Toolkit.

  Uso:
    powershell -NoProfile -ExecutionPolicy Bypass -File Rollback-Hardening.ps1
    powershell ... -File Rollback-Hardening.ps1 -WhatIf      (muestra sin aplicar)
    powershell ... -File Rollback-Hardening.ps1 -File <otro.json>
#>
[CmdletBinding()]
param(
    [string] $File = '__ROLLBACKFILE__',
    [switch] $WhatIf
)

$ErrorActionPreference = 'Continue'

# Las implementaciones van justo debajo. Este archivo no ejecuta codigo que
# provenga del JSON: solo llama a funciones de esta lista blanca.

'@

    $template = $template.Replace('__ROLLBACKFILE__', $RollbackName)

    $body = @'
# ------------------------------------------------------------------ implementaciones

function P40-RevertCloudBlockLevel {
    param([string]$PreviousJson)
    $v = $null
    if ($PreviousJson -and $PreviousJson -ne '{}') {
        try { $o = $PreviousJson | ConvertFrom-Json; $v = $o.v } catch { }
    }
    if ($null -eq $v) {
        if ($WhatIf) { Write-Host '  [WhatIf] CloudBlockLevel -> Default'; return }
        try { Set-MpPreference -CloudBlockLevel Default -ErrorAction SilentlyContinue } catch { }
        return
    }
    # Mapeo inverso de los valores numericos de CloudBlockLevel.
    $name = 'Default'
    switch ([int]$v) {
        2 { $name = 'High' }
        4 { $name = 'High' }
        6 { $name = 'Zero Tolerance' }
    }
    if ($WhatIf) { Write-Host ("  [WhatIf] CloudBlockLevel -> {0} ({1})" -f $name, $v); return }
    try { Set-MpPreference -CloudBlockLevel $name -ErrorAction SilentlyContinue } catch { }
}

function P40-RevertAsr {
    param([string]$PreviousJson)
    $prev = @{}
    if ($PreviousJson -and $PreviousJson -ne '{}') {
        try {
            $o = $PreviousJson | ConvertFrom-Json
            foreach ($p in $o.PSObject.Properties) { $prev[$p.Name.ToUpper()] = [string]$p.Value }
        } catch { }
    }
    $guids = @('BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550','D4F940AB-401B-4EFC-AADC-AD5F3C50688A','5BEB7EFE-FD9A-4556-801D-275E5FFC04CC','92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B','9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2','E6DB77E5-3DF2-4CF1-B95A-636979351E5B','D1E49AAC-8F56-4280-B9BA-993A6D77406C','B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4')
    foreach ($g in $guids) {
        $action = 'Disabled'
        $k = $g.ToUpper()
        if ($prev.ContainsKey($k)) {
            $a = [string]$prev[$k]
            if ($a -eq '1' -or $a -eq 'Enabled') { $action = 'Enabled' }
            elseif ($a -eq '2' -or $a -eq 'AuditMode') { $action = 'AuditMode' }
            elseif ($a -eq '6' -or $a -eq 'Warn') { $action = 'Warn' }
            else { $action = 'Disabled' }
        }
        if ($WhatIf) { Write-Host ("  [WhatIf] ASR {0} -> {1}" -f $g, $action) }
        else { try { Add-MpPreference -AttackSurfaceReductionRules_Ids $g -AttackSurfaceReductionRules_Actions $action -ErrorAction SilentlyContinue } catch { } }
    }
}

function P40-RevertFirewall {
    param([string]$PreviousJson)
    if ($PreviousJson -eq '{}' -or -not $PreviousJson) {
        if (-not $WhatIf) { Set-NetFirewallProfile -All -DefaultInboundAction Block -LogBlocked $false -ErrorAction SilentlyContinue }
        return
    }
    try {
        $o = $PreviousJson | ConvertFrom-Json
        foreach ($p in $o.PSObject.Properties) {
            $name = $p.Name
            $inbound = [string]$p.Value.Inbound
            $log = [bool]$p.Value.LogBlocked
            if ($WhatIf) { Write-Host ("  [WhatIf] Firewall {0}: inbound={1}, log={2}" -f $name, $inbound, $log) }
            else {
                if ($inbound -eq 'Block' -or $inbound -eq 'Allow' -or $inbound -eq 'NotConfigured') {
                    Set-NetFirewallProfile -Profile $name -DefaultInboundAction $inbound -LogBlocked $log -ErrorAction SilentlyContinue
                }
                else {
                    Set-NetFirewallProfile -Profile $name -LogBlocked $log -ErrorAction SilentlyContinue
                }
            }
        }
    } catch { Write-Host ('  No se pudo revertir el firewall: ' + $_.Exception.Message) }
}

function P40-RevertSmb {
    param([string]$PreviousJson)
    if (-not $PreviousJson -or $PreviousJson -eq '{}') { return }
    try {
        $o = $PreviousJson | ConvertFrom-Json
        if ($WhatIf) { Write-Host ("  [WhatIf] SMB1={0}, firma={1}" -f $o.EnableSMB1, $o.RequireSign); return }
        Set-SmbServerConfiguration -EnableSMB1Protocol ([bool]$o.EnableSMB1) -RequireSecuritySignature ([bool]$o.RequireSign) -Force -ErrorAction SilentlyContinue
    } catch { Write-Host ('  No se pudo revertir SMB: ' + $_.Exception.Message) }
}

function P40-RevertRdp {
    param([string]$PreviousJson)
    if (-not $PreviousJson -or $PreviousJson -eq '{}') { return }
    try {
        $o = $PreviousJson | ConvertFrom-Json
        $rdpVal = 1
        if ($null -ne $o.Rdp) { $rdpVal = [int]$o.Rdp }
        $raVal = 0
        if ($null -ne $o.RA) { $raVal = [int]$o.RA }
        if ($WhatIf) { Write-Host ("  [WhatIf] fDenyTSConnections={0}, fAllowToGetHelp={1}" -f $rdpVal, $raVal); return }
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value $rdpVal -ErrorAction SilentlyContinue
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value $raVal -ErrorAction SilentlyContinue
    } catch { }
}

function P40-RevertAutorun {
    param([string]$PreviousJson)
    if (-not $PreviousJson -or $PreviousJson -eq '{}') { return }
    try {
        $o = $PreviousJson | ConvertFrom-Json
        foreach ($p in $o.PSObject.Properties) {
            if ($p.Name -eq '__NoAutorun') { continue }
            $path = $p.Name
            $val = $p.Value
            if ($null -eq $val) {
                if ($WhatIf) { Write-Host ("  [WhatIf] {0} NoDriveTypeAutoRun -> (eliminar)" -f $path) }
                else { try { Remove-ItemProperty -LiteralPath $path -Name 'NoDriveTypeAutoRun' -Force -ErrorAction SilentlyContinue } catch { } }
            }
            else {
                if ($WhatIf) { Write-Host ("  [WhatIf] {0} NoDriveTypeAutoRun -> {1}" -f $path, $val) }
                else { New-ItemProperty -LiteralPath $path -Name 'NoDriveTypeAutoRun' -Value ([int]$val) -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null }
            }
        }
        # NoAutorun se restaura a su valor previo; solo se elimina si no existia.
        $prevNoAutorun = $null
        if ($null -ne $o.PSObject.Properties['__NoAutorun']) { $prevNoAutorun = $o.'__NoAutorun' }
        $noAutoPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        if ($null -eq $prevNoAutorun) {
            if ($WhatIf) { Write-Host '  [WhatIf] HKLM NoAutorun -> (eliminar)' }
            else { Remove-ItemProperty -LiteralPath $noAutoPath -Name 'NoAutorun' -Force -ErrorAction SilentlyContinue }
        }
        else {
            if ($WhatIf) { Write-Host ("  [WhatIf] HKLM NoAutorun -> {0}" -f $prevNoAutorun) }
            else { New-ItemProperty -LiteralPath $noAutoPath -Name 'NoAutorun' -Value ([int]$prevNoAutorun) -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null }
        }
    } catch { }
}

function P40-RevertPsLog {
    param([string]$PreviousJson)
    if (-not $PreviousJson -or $PreviousJson -eq '{}') { return }
    try {
        $o = $PreviousJson | ConvertFrom-Json
        $pairs = @(
            @{ p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; n = 'EnableScriptBlockLogging'; v = $o.sb },
            @{ p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging';      n = 'EnableModuleLogging';      v = $o.ml }
        )
        foreach ($e in $pairs) {
            if ($null -eq $e.v) {
                if (-not $WhatIf) { Remove-ItemProperty -LiteralPath $e.p -Name $e.n -Force -ErrorAction SilentlyContinue }
            }
            else {
                if (-not $WhatIf) { New-ItemProperty -LiteralPath $e.p -Name $e.n -Value ([int]$e.v) -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null }
            }
        }
    } catch { }
}

function P40-RevertSmartScreen {
    param([string]$PreviousJson)
    if (-not $PreviousJson -or $PreviousJson -eq '{}') { return }
    try {
        $o = $PreviousJson | ConvertFrom-Json
        if ($null -eq $o.enabled) {
            if (-not $WhatIf) { Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled' -Force -ErrorAction SilentlyContinue }
        }
        else {
            if (-not $WhatIf) { New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled' -Value ([string]$o.enabled) -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null }
        }
        if ($null -eq $o.policy) {
            if (-not $WhatIf) { Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen' -Force -ErrorAction SilentlyContinue }
        }
        else {
            if (-not $WhatIf) { New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen' -Value ([int]$o.policy) -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null }
        }
        if (-not $WhatIf) { Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'ShellSmartScreenLevel' -Force -ErrorAction SilentlyContinue }
    } catch { }
}

function P40-RevertLlmnr {
    param([string]$PreviousJson)
    $v = $null
    if ($PreviousJson -and $PreviousJson -ne '{}') {
        try { $o = $PreviousJson | ConvertFrom-Json; $v = $o.v } catch { }
    }
    if ($null -eq $v) {
        if (-not $WhatIf) { Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Force -ErrorAction SilentlyContinue }
    }
    else {
        if (-not $WhatIf) { New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value ([int]$v) -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null }
    }
}

function P40-RevertUac {
    param([string]$PreviousJson)
    if (-not $PreviousJson -or $PreviousJson -eq '{}') { return }
    try {
        $o = $PreviousJson | ConvertFrom-Json
        $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        if ($null -ne $o.ConsentPromptBehaviorAdmin) {
            if (-not $WhatIf) { New-ItemProperty -LiteralPath $path -Name 'ConsentPromptBehaviorAdmin' -Value ([int]$o.ConsentPromptBehaviorAdmin) -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null }
        }
        if ($null -ne $o.PromptOnSecureDesktop) {
            if (-not $WhatIf) { New-ItemProperty -LiteralPath $path -Name 'PromptOnSecureDesktop' -Value ([int]$o.PromptOnSecureDesktop) -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null }
        }
    } catch { }
}

function P40-RevertWdigest {
    param([string]$PreviousJson)
    $v = $null
    if ($PreviousJson -and $PreviousJson -ne '{}') { try { $o = $PreviousJson | ConvertFrom-Json; $v = $o.v } catch { } }
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
    if ($null -eq $v) {
        if (-not $WhatIf) { Remove-ItemProperty -LiteralPath $path -Name 'UseLogonCredential' -Force -ErrorAction SilentlyContinue }
    }
    else {
        if (-not $WhatIf) { New-ItemProperty -LiteralPath $path -Name 'UseLogonCredential' -Value ([int]$v) -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null }
    }
}

function P40-RevertRunAsPpl {
    param([string]$PreviousJson)
    $v = $null
    if ($PreviousJson -and $PreviousJson -ne '{}') { try { $o = $PreviousJson | ConvertFrom-Json; $v = $o.v } catch { } }
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    if ($null -eq $v) {
        if (-not $WhatIf) { Remove-ItemProperty -LiteralPath $path -Name 'RunAsPPL' -Force -ErrorAction SilentlyContinue }
    }
    else {
        if (-not $WhatIf) { New-ItemProperty -LiteralPath $path -Name 'RunAsPPL' -Value ([int]$v) -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null }
    }
    Write-Host '  RunAsPPL: el cambio es efectivo tras reiniciar.'
}

function P40-RevertAie {
    param([string]$PreviousJson)
    if (-not $PreviousJson -or $PreviousJson -eq '{}') { return }
    try {
        $o = $PreviousJson | ConvertFrom-Json
        $hk = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'
        $hc = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer'
        if ($null -eq $o.hklm) { if (-not $WhatIf) { Remove-ItemProperty -LiteralPath $hk -Name 'AlwaysInstallElevated' -Force -ErrorAction SilentlyContinue } }
        else { if (-not $WhatIf) { New-ItemProperty -LiteralPath $hk -Name 'AlwaysInstallElevated' -Value ([int]$o.hklm) -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null } }
        if ($null -eq $o.hkcu) { if (-not $WhatIf) { Remove-ItemProperty -LiteralPath $hc -Name 'AlwaysInstallElevated' -Force -ErrorAction SilentlyContinue } }
        else { if (-not $WhatIf) { New-ItemProperty -LiteralPath $hc -Name 'AlwaysInstallElevated' -Value ([int]$o.hkcu) -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null } }
    } catch { }
}

function P40-RevertPsV2 {
    param([string]$PreviousJson)
    $state = ''
    if ($PreviousJson -and $PreviousJson -ne '{}') { try { $o = $PreviousJson | ConvertFrom-Json; $state = [string]$o.state } catch { } }
    if ($state -eq 'Enabled') {
        if ($WhatIf) { Write-Host '  [WhatIf] habilitar PowerShell v2'; return }
        try { Enable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2' -NoRestart -ErrorAction SilentlyContinue | Out-Null } catch { }
    }
    else {
        Write-Host ('  PowerShell v2 ya estaba deshabilitado antes del cambio ({0}); no se altera.' -f $state)
    }
}

function P40-RevertNbt {
    param([string]$PreviousJson)
    if (-not $PreviousJson -or $PreviousJson -eq '{}') { return }
    try {
        $o = $PreviousJson | ConvertFrom-Json
        $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
        foreach ($p in $o.PSObject.Properties) {
            $path = Join-Path $base $p.Name
            $v = $p.Value
            if ($null -eq $v) {
                if (-not $WhatIf) { Remove-ItemProperty -LiteralPath $path -Name 'NetbiosOptions' -Force -ErrorAction SilentlyContinue }
            }
            else {
                if (-not $WhatIf) { New-ItemProperty -LiteralPath $path -Name 'NetbiosOptions' -Value ([int]$v) -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null }
            }
        }
    } catch { }
}

# ------------------------------------------------------------------ ejecucion

Write-Host ''
Write-Host '=== ROLLBACK DEL HARDENING ===' -ForegroundColor Cyan
if ($WhatIf) { Write-Host 'MODO SIMULACION: no se modificara nada.' -ForegroundColor Yellow }

if (-not (Test-Path -LiteralPath $File)) {
    Write-Host ('No se encuentra el archivo de rollback: ' + $File) -ForegroundColor Red
    exit 1
}

$parsed = $null
try { $parsed = Get-Content -LiteralPath $File -Raw -Encoding UTF8 | ConvertFrom-Json }
catch {
    Write-Host ('El archivo de rollback no es JSON valido: ' + $_.Exception.Message) -ForegroundColor Red
    exit 1
}

# ConvertFrom-Json emite el array completo como UN unico objeto de pipeline.
# Si se envuelve con @() en la misma expresion, el resultado queda anidado y
# el script veria una sola entrada en lugar de N. Asignar primero y envolver
# despues desarma el array como corresponde.
$entries = @($parsed)

if ($entries.Count -eq 0) {
    Write-Host 'El archivo de rollback no contiene cambios.' -ForegroundColor Yellow
    exit 0
}

Write-Host ('Entradas a revertir: {0}' -f $entries.Count)
foreach ($e in $entries) {
    Write-Host ('  - {0} {1}' -f $e.id, $e.name)
}

if (-not $WhatIf) {
    $resp = Read-Host 'Confirma la reversion? (s/N)'
    if ($resp -ne 's' -and $resp -ne 'S') {
        Write-Host 'Cancelado. No se modifico nada.'
        exit 0
    }
}

$ok = 0
$fail = 0
$skip = 0
foreach ($e in $entries) {
    Write-Host ('-> Revirtiendo {0} ({1})' -f $e.id, $e.name) -ForegroundColor DarkGray
    try {
        # Lista blanca: el nombre de la funcion viene del JSON, asi que solo se
        # aceptan los controles conocidos. Un JSON manipulado no puede ejecutar
        # codigo arbitrario; como mucho pide un control inexistente y se ignora.
        switch ([string]$e.revert) {
            'P40-RevertCloudBlockLevel' { P40-RevertCloudBlockLevel -PreviousJson ([string]$e.data) }
            'P40-RevertAsr'             { P40-RevertAsr             -PreviousJson ([string]$e.data) }
            'P40-RevertFirewall'        { P40-RevertFirewall        -PreviousJson ([string]$e.data) }
            'P40-RevertSmb'             { P40-RevertSmb             -PreviousJson ([string]$e.data) }
            'P40-RevertRdp'             { P40-RevertRdp             -PreviousJson ([string]$e.data) }
            'P40-RevertAutorun'         { P40-RevertAutorun         -PreviousJson ([string]$e.data) }
            'P40-RevertPsLog'           { P40-RevertPsLog           -PreviousJson ([string]$e.data) }
            'P40-RevertSmartScreen'     { P40-RevertSmartScreen     -PreviousJson ([string]$e.data) }
            'P40-RevertLlmnr'           { P40-RevertLlmnr           -PreviousJson ([string]$e.data) }
            'P40-RevertUac'             { P40-RevertUac             -PreviousJson ([string]$e.data) }
            'P40-RevertWdigest'         { P40-RevertWdigest         -PreviousJson ([string]$e.data) }
            'P40-RevertRunAsPpl'        { P40-RevertRunAsPpl        -PreviousJson ([string]$e.data) }
            'P40-RevertAie'             { P40-RevertAie             -PreviousJson ([string]$e.data) }
            'P40-RevertPsV2'            { P40-RevertPsV2            -PreviousJson ([string]$e.data) }
            'P40-RevertNbt'             { P40-RevertNbt             -PreviousJson ([string]$e.data) }
            ''                          { Write-Host '   (sin reversion automatica definida)'; $skip++ }
            default                     { Write-Host ('   Reversion desconocida, se omite: ' + [string]$e.revert); $skip++ }
        }
        $ok++
    }
    catch {
        Write-Host ('   ERROR: ' + $_.Exception.Message) -ForegroundColor Red
        $fail++
    }
}

Write-Host ''
Write-Host ('Rollback completado: {0} procesados, {1} omitidos, {2} con error.' -f $ok, $skip, $fail) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Yellow' })
Write-Host 'Reinicie el equipo para que los cambios de LSA/Defender surtan efecto.'
Write-Host ''
'@

    $content = $template + $body
    $path = Join-Path $Ctx.EvidenceDir 'Rollback-Hardening.ps1'
    $enc = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::WriteAllText($path, $content, $enc)
    Write-Log -Level OK -Message ('  Script de rollback generado: {0}' -f $path)
    return $path
}

# ==================================================================== REMEDIACION

function P40-GetRemediationCommands {
    <#
      Tabla de comandos exactos para aplicar cada control desde CMD.

      Cada entrada tiene:
        Title  - texto que se imprime en consola antes del bloque
        Lines  - comandos en orden; las lineas que empiezan por 'rem' son notas
      Opcional:
        NoRedirect - no silenciar la salida (DISM necesita mostrar progreso)

      ASCII puro: el .cmd debe funcionar en consolas con cualquier pagina de
      codigo, y un acento mal codificado rompe un comando de `reg`.
    #>
    param([string[]] $AsrGuids = @())

    $m = @{}

    $m['H01'] = @{
        Title = 'Defender: nivel de bloqueo en la nube a High'
        Lines = @(
            'powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-MpPreference -CloudBlockLevel High -ErrorAction Stop"'
        )
    }

    $asr = New-Object System.Collections.ArrayList
    [void]$asr.Add('rem Reglas ASR de Defender en modo Block (8 reglas de Microsoft)')
    foreach ($g in $AsrGuids) {
        [void]$asr.Add('powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids ' + $g + ' -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop"')
    }
    $m['H02'] = @{ Title = 'Defender: reglas ASR en modo bloqueo'; Lines = $asr }

    $m['H03'] = @{
        Title = 'Firewall: 3 perfiles activos, entrante bloqueado, registro activo'
        Lines = @(
            'powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -LogBlocked True -ErrorAction Stop"'
        )
    }

    $m['H04'] = @{
        Title = 'SMB: SMBv1 deshabilitado y firma obligatoria'
        Lines = @(
            'powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true -Force -ErrorAction Stop"'
        )
    }

    $m['H05'] = @{
        Title = 'RDP y Asistencia remota deshabilitados'
        Lines = @(
            'rem Terminal Server: fDenyTSConnections=1 (RDP deshabilitado)'
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f'
            'rem Asistencia remota: fAllowToGetHelp=0'
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f'
        )
    }

    $m['H06'] = @{
        Title = 'AutoRun y AutoPlay deshabilitados'
        Lines = @(
            'rem AutoRun: NoDriveTypeAutoRun=255 en HKLM y HKCU (todos los tipos de unidad)'
            'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f'
            'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f'
            'rem AutoPlay: NoAutorun=1'
            'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutorun /t REG_DWORD /d 1 /f'
        )
    }

    $m['H07'] = @{
        Title = 'Registro de bloques de script y de modulos'
        Lines = @(
            'rem ScriptBlockLogging=1'
            'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f'
            'rem ModuleLogging=1'
            'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f'
        )
    }

    $m['H08'] = @{
        Title = 'SmartScreen en modo Warn'
        Lines = @(
            'rem SmartScreen del Explorador'
            'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d Warn /f'
            'rem Politica de SmartScreen'
            'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f'
            'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v ShellSmartScreenLevel /t REG_SZ /d Warn /f'
        )
    }

    $m['H09'] = @{
        Title = 'LLMNR deshabilitado'
        Lines = @(
            'rem EnableMulticast=0'
            'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f'
        )
    }

    $m['H10'] = @{
        Title = 'UAC: consentimiento en escritorio seguro'
        Lines = @(
            'rem ConsentPromptBehaviorAdmin=2 (pedir consentimiento) y escritorio seguro'
            'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f'
            'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f'
        )
    }

    $m['H11'] = @{
        Title = 'WDigest no almacena credenciales en claro'
        Lines = @(
            'rem UseLogonCredential=0'
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f'
        )
    }

    $m['H12'] = @{
        Title = 'LSASS protegido (RunAsPPL) - requiere reinicio'
        Lines = @(
            'rem RunAsPPL=1: surte efecto tras reiniciar'
            'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f'
        )
    }

    $m['H13'] = @{
        Title = 'AlwaysInstallElevated desactivado'
        Lines = @(
            'rem AlwaysInstallElevated=0 en HKLM y HKCU'
            'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f'
            'reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f'
        )
    }

    # DISM: se deja la salida visible porque el codigo de retorno necesita
    # interpretacion (0 ya desinstalado, 3010 requiere reinicio, 0x800f0805 la
    # caracteristica no estaba presente y tampoco es un fallo).
    $m['H15'] = @{
        Title = 'Motor PowerShell 2.0 fuera del sistema (DISM)'
        NoRedirect = $true
        Lines = @(
            'rem Codigos: 0 = hecho, 3010 = hecho y requiere reinicio,'
            'rem 0x800f0805 = la caracteristica no estaba presente (no es fallo)'
            'dism /online /disable-feature /featurename:MicrosoftWindowsPowerShellV2 /norestart'
        )
    }

    $m['H16'] = @{
        Title = 'NetBIOS sobre TCP/IP deshabilitado en cada interfaz'
        Lines = @(
            'rem NetbiosOptions=2 en todas las interfaces de NetBT'
            'powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem ''HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'' | ForEach-Object { New-ItemProperty -LiteralPath $_.PSPath -Name NetbiosOptions -Value 2 -PropertyType DWord -Force | Out-Null }"'
        )
    }

    return $m
}

function P40-WriteRemediationCmd {
    <#
      Genera remediacion.cmd en la carpeta de evidencia con los comandos
      exactos de los controles que quedaron fuera de politica.

      Devuelve el NOMBRE del archivo (no la ruta) para que el informe sea
      portable: la evidencia viaja en el USB y puede abrirse desde otra letra.

      Parametros:
        Ids       - controles a aplicar (pendientes o que fallaron al aplicar)
        ManualIds - controles que requieren accion humana (H14)
    #>
    param(
        $Ctx,
        [string[]] $Ids = @(),
        [string[]] $ManualIds = @(),
        [string[]] $AsrGuids = @()
    )

    $map = P40-GetRemediationCommands -AsrGuids $AsrGuids
    $order = @('H01', 'H02', 'H03', 'H04', 'H05', 'H06', 'H07', 'H08', 'H09', 'H10', 'H11', 'H12', 'H13', 'H15', 'H16')

    $b = New-Object System.Text.StringBuilder

    [void]$b.AppendLine('@echo off')
    [void]$b.AppendLine('setlocal')
    [void]$b.AppendLine('title Toolkit de auditoria - remediacion del hardening')
    [void]$b.AppendLine('rem ==============================================================')
    [void]$b.AppendLine('rem  remediacion.cmd   (generado por el toolkit; no editar a mano)')
    [void]$b.AppendLine('rem')
    [void]$b.AppendLine('rem  Equipo    : ' + [string]$env:COMPUTERNAME)
    [void]$b.AppendLine('rem  Evidencia : ' + [string]$Ctx.EvidenceDir)
    [void]$b.AppendLine('rem  Generado  : ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))

    $ctlList = ($Ids -join ', ')
    if ($ManualIds.Count -gt 0) {
        if ($ctlList) { $ctlList = $ctlList + ' | manual: ' + ($ManualIds -join ', ') }
        else { $ctlList = 'manual: ' + ($ManualIds -join ', ') }
    }
    [void]$b.AppendLine('rem  Controles : ' + $ctlList)
    [void]$b.AppendLine('rem')
    [void]$b.AppendLine('rem  Aplica SOLO los controles que la auditoria encontro fuera de')
    [void]$b.AppendLine('rem  politica. No toca BitLocker, cuentas, contrasenas ni discos.')
    [void]$b.AppendLine('rem  No registra los valores previos: si quiere reversion automatica,')
    [void]$b.AppendLine('rem  repita la auditoria con la opcion 4 de INICIAR.cmd (-Apply).')
    [void]$b.AppendLine('rem ==============================================================')
    [void]$b.AppendLine('')
    [void]$b.AppendLine('rem --- elevacion: fltmc solo responde a un administrador')
    [void]$b.AppendLine('fltmc >nul 2>&1')
    [void]$b.AppendLine('if not errorlevel 1 goto :elevado')
    [void]$b.AppendLine('echo.')
    [void]$b.AppendLine('echo  Se requieren privilegios de administrador. Solicitando elevacion...')
    [void]$b.AppendLine('powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath ''%~f0'' -WorkingDirectory ''%~dp0'' -Verb RunAs" >nul 2>&1')
    [void]$b.AppendLine('if errorlevel 1 goto :sin_elevacion')
    [void]$b.AppendLine('exit /b 0')
    [void]$b.AppendLine('')
    [void]$b.AppendLine(':sin_elevacion')
    [void]$b.AppendLine('echo.')
    [void]$b.AppendLine('echo  No se pudo elevar automaticamente.')
    [void]$b.AppendLine('echo  Cierre esta ventana, haga clic derecho en remediacion.cmd')
    [void]$b.AppendLine('echo  y elija "Ejecutar como administrador".')
    [void]$b.AppendLine('echo.')
    [void]$b.AppendLine('pause')
    [void]$b.AppendLine('exit /b 1')
    [void]$b.AppendLine('')
    [void]$b.AppendLine(':elevado')
    [void]$b.AppendLine('set FALLOS=0')
    [void]$b.AppendLine('')
    [void]$b.AppendLine('echo  ==============================================================')
    [void]$b.AppendLine('echo   REMEDIACION DEL HARDENING')
    [void]$b.AppendLine('echo  ==============================================================')

    $emitted = 0
    foreach ($id in $order) {
        if (-not ($Ids -contains $id)) { continue }
        if (-not $map.ContainsKey($id)) { continue }

        $e = $map[$id]
        $tail = ' >nul || set /a FALLOS+=1'
        if ($e.ContainsKey('NoRedirect') -and $e.NoRedirect) { $tail = ' || set /a FALLOS+=1' }

        [void]$b.AppendLine('')
        [void]$b.AppendLine('rem ---------------------------------------------------------------- ' + $id)
        [void]$b.AppendLine('echo.')
        [void]$b.AppendLine('echo  [' + $id + '] ' + [string]$e.Title)

        foreach ($ln in @($e.Lines)) {
            $s = [string]$ln
            if ($s -like 'rem*') {
                [void]$b.AppendLine($s)
                continue
            }
            [void]$b.AppendLine($s + $tail)
        }
        $emitted++
    }

    if ($ManualIds.Count -gt 0) {
        [void]$b.AppendLine('')
        [void]$b.AppendLine('rem ---------------------------------------------------------------- manual')
        [void]$b.AppendLine('echo.')
        [void]$b.AppendLine('echo  ACCION MANUAL PENDIENTE: ' + ($ManualIds -join ', '))
        [void]$b.AppendLine('rem  H14: hay una contrasena de autologon en texto claro.')
        [void]$b.AppendLine('rem  Nunca se aplica de forma automatica: borrarla rompe el inicio de sesion.')
        [void]$b.AppendLine('rem  Revise HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon')
        [void]$b.AppendLine('rem  (DefaultPassword, AutoAdminLogon, DefaultUserName) y decida.')
    }

    if ($emitted -eq 0 -and $ManualIds.Count -eq 0) {
        return ''
    }

    [void]$b.AppendLine('')
    [void]$b.AppendLine('echo.')
    [void]$b.AppendLine('echo  ==============================================================')
    [void]$b.AppendLine('if "%FALLOS%"=="0" echo   Resultado: todos los comandos terminaron sin error.')
    [void]$b.AppendLine('if not "%FALLOS%"=="0" echo   Resultado: %FALLOS% comando(s) con error. Revise las lineas anteriores.')
    [void]$b.AppendLine('echo.')
    [void]$b.AppendLine('echo  Reaudite para confirmar el cambio: INICIAR.cmd, opcion 1.')
    [void]$b.AppendLine('echo  Este archivo no altera BitLocker, cuentas ni discos.')
    [void]$b.AppendLine('echo.')
    [void]$b.AppendLine('pause')
    [void]$b.AppendLine('exit /b %FALLOS%')

    $text = $b.ToString()
    if ($text -match '[^\x00-\x7F]') {
        Write-Log -Level WARN -Message '  remediacion.cmd contiene caracteres no ASCII: se sustituyen por "?"'
    }

    $name = 'remediacion.cmd'
    $path = Join-Path $Ctx.EvidenceDir $name
    # ASCII sin BOM: un BOM al inicio convertiria '@echo off' en un comando
    # desconocido y el operador veria un error antes de cualquier salida util.
    $enc = New-Object System.Text.ASCIIEncoding
    [System.IO.File]::WriteAllText($path, $text, $enc)

    Write-Log -Level OK -Message ('  Remedacion por comandos generada: {0}' -f $path)
    Add-Metric -Name 'hardening_remediation_controls' -Value ($emitted + $ManualIds.Count)
    return $name
}
