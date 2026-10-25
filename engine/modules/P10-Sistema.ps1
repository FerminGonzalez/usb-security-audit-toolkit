<#
  P10-Sistema.ps1
  USB Security Audit Toolkit - diagnostico local del sistema
  Dueno: UNIDAD A | Version: 1.0.0
  PowerShell 5.1 compatible

  Solo LEE. Cada check va aislado en Invoke-Checked para que un fallo
  no detenga la auditoria.
#>

function Invoke-Sistema {
    param([Parameter(Mandatory = $true)] $Ctx)

    $deep = ($Ctx.Mode -eq 'completo')
    Write-Log -Level INFO -Message ('SISTEMA: diagnostico local (profundidad: {0})' -f $(if ($deep) { 'completa' } else { 'rapida' }))

    # ================================================================ SO y parches
    Invoke-Checked -Name 'SYS-Parches' -Block {
        $hotfixes = @()
        try {
            $hotfixes = @(Get-HotFix -ErrorAction Stop | Sort-Object { if ($_.InstalledOn) { $_.InstalledOn } else { [datetime]'1900-01-01' } } -Descending)
        }
        catch { }

        if ($hotfixes.Count -eq 0) {
            Add-Finding -Id 'SYS-001' -Severity 'Medium' -Category 'Sistema' `
                -Title 'No se pudieron enumerar actualizaciones instaladas' `
                -Detail 'Get-HotFix no devolvio resultados. Puede ser un equipo sin actualizaciones o una consulta bloqueada.' `
                -Remediation 'Verifique Windows Update manualmente (Configuracion > Windows Update).'
        }
        else {
            $latest = $hotfixes[0]
            $ageDays = -1
            if ($latest.InstalledOn) {
                $ageDays = [int]((Get-Date) - $latest.InstalledOn).TotalDays
            }
            Add-Metric -Name 'hotfix_count' -Value $hotfixes.Count
            Add-Metric -Name 'hotfix_latest_days' -Value $ageDays

            if ($ageDays -gt 60) {
                Add-Finding -Id 'SYS-002' -Severity 'Medium' -Category 'Sistema' `
                    -Title 'Actualizaciones desactualizadas' `
                    -Detail ('La ultima actualizacion ({0}) se instalo hace {1} dias.' -f $latest.HotFixID, $ageDays) `
                    -Remediation 'Ejecute Windows Update y aplique las actualizaciones pendientes.'
            }
            else {
                Add-Finding -Id 'SYS-OK-PATCH' -Severity 'Info' -Category 'Sistema' `
                    -Title 'Parches al dia' `
                    -Detail ('Ultima actualizacion: {0} (hace {1} dias). Total registradas: {2}.' -f $latest.HotFixID, $ageDays, $hotfixes.Count) `
                    -Remediation 'Ninguna.'
            }
        }

        # Reinicio pendiente
        $rebootReasons = @()
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $rebootReasons += 'CBS' }
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $rebootReasons += 'Windows Update' }
        $pfro = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations'
        if ($pfro) { $rebootReasons += 'PendingFileRenameOperations' }

        if ($rebootReasons.Count -gt 0) {
            Add-Finding -Id 'SYS-003' -Severity 'Low' -Category 'Sistema' `
                -Title 'Reinicio pendiente' `
                -Detail ('Motivos: {0}. Los parches no estan activos hasta reiniciar.' -f ($rebootReasons -join ', ')) `
                -Remediation 'Reinicie el equipo cuando sea posible.'
        }

        $hfData = @()
        foreach ($h in ($hotfixes | Select-Object -First 25)) {
            $hfData += @{
                id           = $h.HotFixID
                description  = $h.Description
                installed_on = $(if ($h.InstalledOn) { $h.InstalledOn.ToString('yyyy-MM-dd') } else { '' })
                installed_by = $h.InstalledBy
            }
        }
        [void](Write-Evidence -Name 'hotfixes.json' -Data $hfData)
    }

    # ================================================================ Defender
    Invoke-Checked -Name 'SYS-Defender' -Block {
        $mp = $null
        $status = $null
        try { $mp = Get-MpPreference -ErrorAction Stop } catch { $mp = $null }
        try { $status = Get-MpComputerStatus -ErrorAction Stop } catch { $status = $null }

        if ($null -eq $mp -and $null -eq $status) {
            Add-Finding -Id 'SYS-WARN-DEF' -Severity 'Info' -Category 'Defender' `
                -Title 'Defender no consultable' `
                -Detail 'Get-MpPreference y Get-MpComputerStatus fallaron. Puede haber un antivirus de terceros o una politica que bloquea la consulta.' `
                -Remediation 'Verifique el estado de la proteccion antimalware con el proveedor instalado.'
        }
        else {
            if ($null -ne $status) {
                Add-Metric -Name 'defender_rtp' -Value ([bool]$status.RealTimeProtectionEnabled)

                if (-not $status.RealTimeProtectionEnabled) {
                    Add-Finding -Id 'SYS-010' -Severity 'High' -Category 'Defender' `
                        -Title 'Proteccion en tiempo real desactivada' `
                        -Detail ('RealTimeProtectionEnabled={0}' -f $status.RealTimeProtectionEnabled) `
                        -Remediation 'Set-MpPreference -DisableRealtimeMonitoring $false'
                }

                if ($null -ne $status.IsTamperProtected -and -not $status.IsTamperProtected) {
                    Add-Finding -Id 'SYS-011' -Severity 'High' -Category 'Defender' `
                        -Title 'Proteccion contra manipulacion desactivada' `
                        -Detail 'IsTamperProtected=False. Un atacante con admin puede desactivar Defender por completo.' `
                        -Remediation 'Activar en Seguridad de Windows > Proteccion antivirus > Administrar la configuracion.'
                }

                if ($status.AntivirusSignatureLastUpdated) {
                    $sigDays = [int]((Get-Date) - $status.AntivirusSignatureLastUpdated).TotalDays
                    Add-Metric -Name 'defender_sig_days' -Value $sigDays
                    if ($sigDays -gt 3) {
                        Add-Finding -Id 'SYS-012' -Severity 'Medium' -Category 'Defender' `
                            -Title 'Firmas de antivirus desactualizadas' `
                            -Detail ('AntivirusSignatureLastUpdated hace {0} dias ({1}).' -f $sigDays, $status.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd')) `
                            -Remediation 'Update-MpSignature'
                    }
                }
            }

            if ($null -ne $mp) {
                $cbl = 0
                try { $cbl = [int]$mp.CloudBlockLevel } catch { $cbl = 0 }
                Add-Metric -Name 'defender_cloud_block_level' -Value $cbl
                if ($cbl -lt 2) {
                    Add-Finding -Id 'SYS-013' -Severity 'Medium' -Category 'Defender' `
                        -Title 'Nivel de bloqueo en la nube bajo' `
                        -Detail ('CloudBlockLevel={0} (recomendado: 2).' -f $cbl) `
                        -Remediation 'Set-MpPreference -CloudBlockLevel High'
                }

                # Reglas ASR
                $asrIds = @()
                $asrActs = @()
                try { $asrIds = @($mp.AttackSurfaceReductionRules_Ids) } catch { }
                try { $asrActs = @($mp.AttackSurfaceReductionRules_Actions) } catch { }
                $asrEnabled = 0
                foreach ($a in $asrActs) { if ([string]$a -eq '1' -or [string]$a -eq 'Enabled') { $asrEnabled++ } }
                Add-Metric -Name 'asr_rules' -Value $asrIds.Count
                Add-Metric -Name 'asr_enabled' -Value $asrEnabled
                if ($asrIds.Count -eq 0) {
                    Add-Finding -Id 'SYS-014' -Severity 'Medium' -Category 'Defender' `
                        -Title 'Sin reglas de reduccion de superficie de ataque' `
                        -Detail 'AttackSurfaceReductionRules_Ids esta vacio. Las tecnicas comunes de ejecucion (macros, scripts ofuscados, LSASS) no estan bloqueadas.' `
                        -Remediation 'Configure las reglas ASR recomendadas (ver control H02 del modulo de hardening).'
                }

                # Exclusiones: vector de ataque clasico.
                # Sin elevacion Get-MpPreference devuelve un marcador de texto
                # ("N/A: Must be an administrator...") que NO es una exclusion:
                # contarlo genera un falso positivo de severidad High.
                function P10-RealItems {
                    param($Items)
                    $out = @()
                    foreach ($i in @($Items)) {
                        if ($null -eq $i) { continue }
                        $s = [string]$i
                        if (-not $s.Trim()) { continue }
                        if ($s -match '(?i)^\s*N/?A\b|not\s+available|must\s+be\s+an\s+administrator|acceso\s+denegado|access\s+denied') { continue }
                        $out += $s
                    }
                    return $out
                }

                $exPaths = @(P10-RealItems $mp.ExclusionPath)
                $exExts  = @(P10-RealItems $mp.ExclusionExtension)
                $exProcs = @(P10-RealItems $mp.ExclusionProcess)
                $exIps   = @(P10-RealItems $mp.ExclusionIpAddress)

                $exTotal = $exPaths.Count + $exExts.Count + $exProcs.Count + $exIps.Count
                Add-Metric -Name 'defender_exclusions' -Value $exTotal

                if ($exTotal -gt 0) {
                    $parts = @()
                    if ($exPaths.Count -gt 0) { $parts += ('rutas: ' + ($exPaths -join ', ')) }
                    if ($exExts.Count -gt 0)  { $parts += ('extensiones: ' + ($exExts -join ', ')) }
                    if ($exProcs.Count -gt 0) { $parts += ('procesos: ' + ($exProcs -join ', ')) }
                    if ($exIps.Count -gt 0)   { $parts += ('IPs: ' + ($exIps -join ', ')) }
                    Add-Finding -Id 'SYS-015' -Severity 'High' -Category 'Defender' `
                        -Title 'Exclusiones configuradas en Defender' `
                        -Detail ('{0} exclusion(es): {1}. Un atacante con admin puede anadir exclusiones para dejar su payload sin escanear.' -f $exTotal, ($parts -join ' | ')) `
                        -Remediation 'Revise cada exclusion con Add-MpPreference/Remove-MpPreference y elimine las que no esten justificadas.'
                }
                elseif (-not (Test-Admin)) {
                    Add-Finding -Id 'SYS-015-NV' -Severity 'Info' -Category 'Defender' `
                        -Title 'Exclusiones de Defender no verificables' `
                        -Detail 'Sin elevacion, Get-MpPreference no revela las exclusiones configuradas: no se puede afirmar que no existan.' `
                        -Remediation 'Repita la auditoria como administrador para revisar la lista real.'
                }

                $defData = @{
                    cloud_block_level     = $cbl
                    asr_rules_total       = $asrIds.Count
                    asr_rules_enabled     = $asrEnabled
                    exclusion_path        = $exPaths
                    exclusion_extension   = $exExts
                    exclusion_process     = $exProcs
                    exclusion_ip          = $exIps
                }
                [void](Write-Evidence -Name 'defender.json' -Data $defData)
            }
        }
    }

    # ================================================================ Firewall
    Invoke-Checked -Name 'SYS-Firewall' -Block {
        $profiles = @()
        try { $profiles = @(Get-NetFirewallProfile -ErrorAction Stop) }
        catch {
            Add-Finding -Id 'SYS-020' -Severity 'Medium' -Category 'Firewall' `
                -Title 'Perfiles de firewall no consultables' `
                -Detail $_.Exception.Message `
                -Remediation 'Verifique el servicio BFE: Get-Service BFE'
            return
        }

        $disabled = @()
        $openInbound = @()
        $noLog = @()
        foreach ($p in $profiles) {
            if (-not $p.Enabled) { $disabled += $p.Name }
            if ([string]$p.DefaultInboundAction -ne 'Block') { $openInbound += ('{0}={1}' -f $p.Name, $p.DefaultInboundAction) }
            if (-not $p.LogBlocked) { $noLog += $p.Name }
        }

        Add-Metric -Name 'firewall_profiles' -Value $profiles.Count

        if ($disabled.Count -gt 0) {
            Add-Finding -Id 'SYS-021' -Severity 'High' -Category 'Firewall' `
                -Title 'Perfil de firewall desactivado' `
                -Detail ('Perfiles desactivados: {0}' -f ($disabled -join ', ')) `
                -Remediation 'Set-NetFirewallProfile -Profile <perfil> -Enabled True'
        }

        if ($openInbound.Count -gt 0) {
            Add-Finding -Id 'SYS-022' -Severity 'Medium' -Category 'Firewall' `
                -Title 'Entrante permitido por defecto' `
                -Detail ('Perfiles con DefaultInboundAction distinto de Block: {0}' -f ($openInbound -join ', ')) `
                -Remediation 'Set-NetFirewallProfile -All -DefaultInboundAction Block'
        }

        if ($noLog.Count -gt 0) {
            Add-Finding -Id 'SYS-023' -Severity 'Low' -Category 'Firewall' `
                -Title 'Registro de conexiones bloqueadas desactivado' `
                -Detail ('Perfiles sin LogBlocked: {0}' -f ($noLog -join ', ')) `
                -Remediation 'Set-NetFirewallProfile -All -LogBlocked True'
        }

        if ($disabled.Count -eq 0 -and $openInbound.Count -eq 0 -and $noLog.Count -eq 0) {
            Add-Finding -Id 'SYS-OK-FW' -Severity 'Info' -Category 'Firewall' `
                -Title 'Firewall correctamente configurado' `
                -Detail ('{0} perfiles activos, entrante bloqueado y registro habilitado.' -f $profiles.Count) `
                -Remediation 'Ninguna.'
        }

        $fwData = @()
        foreach ($p in $profiles) {
            $fwData += @{
                name = $p.Name; enabled = [bool]$p.Enabled
                default_inbound = [string]$p.DefaultInboundAction
                default_outbound = [string]$p.DefaultOutboundAction
                log_blocked = [bool]$p.LogBlocked
                log_allowed = [bool]$p.LogAllowed
            }
        }
        [void](Write-Evidence -Name 'firewall.json' -Data $fwData)
    }

    # ================================================================ Usuarios
    Invoke-Checked -Name 'SYS-Usuarios' -Block {
        $users = @()
        $usedLocal = $true
        try {
            $users = @(Get-LocalUser -ErrorAction Stop)
        }
        catch {
            $usedLocal = $false
            try {
                $users = @(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop)
            }
            catch {
                Add-Finding -Id 'SYS-030' -Severity 'Low' -Category 'Usuarios' `
                    -Title 'Usuarios locales no enumerables' `
                    -Detail $_.Exception.Message `
                    -Remediation 'Ejecute como administrador o verifique el servicio SAM.'
            }
        }

        $enabled = @()
        $noPassword = @()        # cuentas sin contrasena asignada nunca
        $blankAllowed = @()      # tienen contrasena, pero el flag permite vaciarla
        $neverExpires = @()
        $guestEnabled = $false
        $userData = @()

        foreach ($u in $users) {
            $name = [string]$u.Name
            $isEnabled = $false
            try { $isEnabled = [bool]$u.Enabled } catch { $isEnabled = $false }
            $pwdRequired = $true
            try { $pwdRequired = [bool]$u.PasswordRequired } catch { $pwdRequired = $true }
            $pwdExpires = $null
            try { $pwdExpires = $u.PasswordExpires } catch { }
            $pwdLastSet = $null
            try { $pwdLastSet = $u.PasswordLastSet } catch { }
            $source = ''
            try { $source = [string]$u.PrincipalSource } catch { }

            if ($isEnabled) {
                $enabled += $name
                $userData += @{
                    name              = $name
                    enabled           = $true
                    password_required = $pwdRequired
                    password_last_set = $(if ($pwdLastSet) { $pwdLastSet.ToString('yyyy-MM-dd') } else { $null })
                    principal_source  = $source
                    sid               = [string]$u.SID
                }
                if (-not $pwdRequired) {
                    # PasswordRequired=False es normal en cuentas vinculadas a una
                    # cuenta Microsoft (la credencial vive en la nube) y en cuentas
                    # con Windows Hello. Solo es grave si nunca hubo contrasena.
                    if ($source -eq 'MicrosoftAccount') {
                        Add-Finding -Id ('SYS-032-MSA-' + ($name -replace '[^A-Za-z0-9]', '')) -Severity 'Info' -Category 'Usuarios' `
                            -Title ('PasswordRequired=False esperado en cuenta Microsoft: {0}' -f $name) `
                            -Detail ('PrincipalSource={0}. La credencial se valida contra la cuenta Microsoft, no contra el SAM local.' -f $source) `
                            -Remediation 'Ninguna.'
                    }
                    elseif ($null -eq $pwdLastSet) {
                        $noPassword += $name
                    }
                    else {
                        $blankAllowed += $name
                    }
                }
                if ($null -eq $pwdExpires -and $source -ne 'MicrosoftAccount') { $neverExpires += $name }
            }
            if ($name -match '^(Guest|Invitado|DefaultAccount)$' -and $isEnabled) { $guestEnabled = $true }
        }

        Add-Metric -Name 'local_users_enabled' -Value $enabled.Count
        [void](Write-Evidence -Name 'users.json' -Data $userData)

        if ($guestEnabled) {
            Add-Finding -Id 'SYS-031' -Severity 'Critical' -Category 'Usuarios' `
                -Title 'Cuenta invitado o DefaultAccount habilitada' `
                -Detail ('Cuentas habilitadas: {0}. Permiten acceso sin credenciales validas o sesiones sin perfil.' -f (($enabled | Where-Object { $_ -match '^(Guest|Invitado|DefaultAccount)$' }) -join ', ')) `
                -Remediation 'Disable-LocalUser -Name "Guest" ; Disable-LocalUser -Name "DefaultAccount"'
        }

        if ($noPassword.Count -gt 0) {
            Add-Finding -Id 'SYS-032' -Severity 'High' -Category 'Usuarios' `
                -Title 'Cuentas sin contrasena asignada' `
                -Detail ('Cuentas habilitadas con PasswordRequired=False y sin PasswordLastSet: {0}. Pueden iniciar sesion sin credencial.' -f ($noPassword -join ', ')) `
                -Remediation 'net user <cuenta> /passwordreq:yes y asigne una contrasena.'
        }
        if ($blankAllowed.Count -gt 0) {
            Add-Finding -Id 'SYS-032-B' -Severity 'Low' -Category 'Usuarios' `
                -Title 'El flag de contrasena obligatoria esta desactivado' `
                -Detail ('Cuentas con contrasena asignada pero PasswordRequired=False: {0}. Hoy tienen credencial, pero el sistema permite dejarla vacia sin aviso.' -f ($blankAllowed -join ', ')) `
                -Remediation 'net user <cuenta> /passwordreq:yes'
        }

        if ($neverExpires.Count -gt 0) {
            Add-Finding -Id 'SYS-033' -Severity 'Low' -Category 'Usuarios' `
                -Title 'Cuentas con contrasena que nunca expira' `
                -Detail ('Cuentas: {0}' -f ($neverExpires -join ', ')) `
                -Remediation 'net user <cuenta> /expires:never  -> revise la politica de expiracion.'
        }

        # Miembros del grupo Administradores (por SID, independiente del idioma)
        try {
            $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
            $adminNames = @()
            foreach ($a in $admins) { $adminNames += ('{0} ({1})' -f $a.Name, $a.ObjectClass) }
            Add-Metric -Name 'admin_members' -Value $admins.Count
            Add-Finding -Id 'SYS-034' -Severity 'Info' -Category 'Usuarios' `
                -Title ('Miembros del grupo Administradores: {0}' -f $admins.Count) `
                -Detail ($adminNames -join ' | ') `
                -Remediation 'Revise que cada miembro sea necesario y nominal.'
            [void](Write-Evidence -Name 'administrators.json' -Data $adminNames)
        }
        catch {
            Write-Log -Level WARN -Message ('No se pudo enumerar el grupo Administradores: {0}' -f $_.Exception.Message)
        }
    }

    # ================================================================ Credenciales expuestas
    Invoke-Checked -Name 'SYS-Credenciales' -Block {
        # WDigest
        $wdigest = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Default 0
        Add-Metric -Name 'wdigest_use_logon_credential' -Value $wdigest
        if ([int]$wdigest -ne 0) {
            Add-Finding -Id 'SYS-040' -Severity 'Critical' -Category 'Credenciales' `
                -Title 'WDigest almacena credenciales en texto claro' `
                -Detail ('UseLogonCredential={0}. Las contrasenas quedan en memoria en claro y Mimikatz las extrae sin privilegios extra.' -f $wdigest) `
                -Remediation 'Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" UseLogonCredential 0 ; reiniciar'
        }

        # LSA RunAsPPL
        # 1 = habilitado con bloqueo UEFI, 2 = habilitado sin bloqueo UEFI.
        # Ambos protegen LSASS; solo 0 (ausente) es no conforme.
        $runAsPPL = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Default 0
        Add-Metric -Name 'lsa_runasppl' -Value $runAsPPL
        if ([int]$runAsPPL -lt 1) {
            Add-Finding -Id 'SYS-041' -Severity 'High' -Category 'Credenciales' `
                -Title 'LSASS sin proteccion RunAsPPL' `
                -Detail ('RunAsPPL={0}. LSASS puede volcarse con herramientas como procdump o Task Manager y extraerse con Mimikatz.' -f $runAsPPL) `
                -Remediation 'Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" RunAsPPL 1 ; requiere reinicio'
        }
        elseif ([int]$runAsPPL -eq 2) {
            Add-Finding -Id 'SYS-041-B' -Severity 'Low' -Category 'Credenciales' `
                -Title 'RunAsPPL activo sin bloqueo UEFI' `
                -Detail 'RunAsPPL=2. LSASS esta protegido como proceso ligero, pero el valor es reversible por un administrador sin cambiar la base de datos UEFI.' `
                -Remediation 'Opcional: fijar RunAsPPLBoot=1 con bloqueo UEFI para impedir la desactivacion silenciosa.'
        }
        else {
            Add-Finding -Id 'SYS-OK-CRED-PPL' -Severity 'Info' -Category 'Credenciales' `
                -Title 'LSASS protegido con RunAsPPL' `
                -Detail ('RunAsPPL={0} (con bloqueo UEFI).' -f $runAsPPL) `
                -Remediation 'Ninguna.'
        }

        # AutoLogon con contrasena
        $autoAdmin = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon' -Default '0'
        $defaultPwd = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultPassword' -Default ''
        if (([string]$autoAdmin -eq '1') -and $defaultPwd) {
            Add-Finding -Id 'SYS-042' -Severity 'Critical' -Category 'Credenciales' `
                -Title 'Credenciales de autologon en texto claro en el registro' `
                -Detail ('AutoAdminLogon=1 y DefaultPassword esta presente en HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon (cuenta: {0}). Cualquier lectura del registro revela la contrasena.' -f (Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultUserName' -Default '(desconocida)')) `
                -Remediation 'Elimine DefaultPassword y AutoAdminLogon, o migre a LSA secretos (Sysinternals Autologon).'
        }
        elseif (([string]$autoAdmin -eq '1')) {
            Add-Finding -Id 'SYS-042-B' -Severity 'Medium' -Category 'Credenciales' `
                -Title 'Autologon activo sin contrasena en el registro' `
                -Detail 'AutoAdminLogon=1 pero DefaultPassword no esta presente.' `
                -Remediation 'Revise si el autologon es necesario.'
        }

        # AlwaysInstallElevated
        $aieHklm = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Default 0
        $aieHkcu = Get-RegValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Default 0
        if ([int]$aieHklm -eq 1 -and [int]$aieHkcu -eq 1) {
            Add-Finding -Id 'SYS-043' -Severity 'Critical' -Category 'Credenciales' `
                -Title 'AlwaysInstallElevated habilitado' `
                -Detail 'HKLM y HKCU con AlwaysInstallElevated=1. Cualquier usuario puede instalar un MSI con privilegios SYSTEM (escalada trivial).' `
                -Remediation 'Elimine la clave AlwaysInstallElevated en HKLM y HKCU bajo Policies\Microsoft\Windows\Installer.'
        }
        elseif ([int]$aieHklm -eq 1 -or [int]$aieHkcu -eq 1) {
            Add-Finding -Id 'SYS-043-B' -Severity 'Medium' -Category 'Credenciales' `
                -Title 'AlwaysInstallElevated parcialmente configurado' `
                -Detail ('HKLM={0}, HKCU={1}. Se requiere 1 en ambas para la escalada, pero la configuracion es incorrecta.' -f $aieHklm, $aieHkcu) `
                -Remediation 'Deje ambos valores en 0 o elimine las claves.'
        }
        else {
            Add-Finding -Id 'SYS-OK-CRED' -Severity 'Info' -Category 'Credenciales' `
                -Title 'Sin vectores de robo de credenciales conocidos' `
                -Detail 'WDigest desactivado, RunAsPPL activo, sin credenciales de autologon y AlwaysInstallElevated apagado.' `
                -Remediation 'Ninguna.'
        }
    }

    # ================================================================ UAC
    Invoke-Checked -Name 'SYS-UAC' -Block {
        $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $enableLua   = Get-RegValue -Path $p -Name 'EnableLUA' -Default 1
        $consent     = Get-RegValue -Path $p -Name 'ConsentPromptBehaviorAdmin' -Default 5
        $secureDesk  = Get-RegValue -Path $p -Name 'PromptOnSecureDesktop' -Default 1
        $filterToken = Get-RegValue -Path $p -Name 'FilterAdministratorToken' -Default 0

        Add-Metric -Name 'uac_enablelua' -Value $enableLua
        Add-Metric -Name 'uac_consent_prompt' -Value $consent

        if ([int]$enableLua -eq 0) {
            Add-Finding -Id 'SYS-050' -Severity 'Critical' -Category 'UAC' `
                -Title 'UAC desactivado' `
                -Detail 'EnableLUA=0. Todo proceso corre con el token completo del usuario y no hay consentimiento para elevacion.' `
                -Remediation 'Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" EnableLUA 1 ; reiniciar'
        }
        elseif ([int]$consent -eq 0) {
            Add-Finding -Id 'SYS-051' -Severity 'High' -Category 'UAC' `
                -Title 'UAC eleva sin pedir consentimiento' `
                -Detail ('ConsentPromptBehaviorAdmin=0. Cualquier proceso puede elevarse sin aviso al usuario.' ) `
                -Remediation 'Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" ConsentPromptBehaviorAdmin 2'
        }
        elseif ([int]$consent -ge 3) {
            Add-Finding -Id 'SYS-052' -Severity 'Low' -Category 'UAC' `
                -Title 'UAC no solicita credenciales al elevar' `
                -Detail ('ConsentPromptBehaviorAdmin={0} (0-2: sin credenciales; 3-5: solicita credenciales).' -f $consent) `
                -Remediation 'Considere ConsentPromptBehaviorAdmin=2 en equipos de escritorio o 4 en servidores.'
        }

        if ([int]$secureDesk -ne 1) {
            Add-Finding -Id 'SYS-053' -Severity 'Medium' -Category 'UAC' `
                -Title 'UAC sin escritorio seguro' `
                -Detail ('PromptOnSecureDesktop={0}. Un malware puede simular el dialogo de UAC y capturar la aprobacion.' -f $secureDesk) `
                -Remediation 'Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" PromptOnSecureDesktop 1'
        }

        if ([int]$filterToken -ne 1) {
            Add-Finding -Id 'SYS-054' -Severity 'Low' -Category 'UAC' `
                -Title 'Cuenta Administrador integrada sin filtrado de token' `
                -Detail ('FilterAdministratorToken={0}.' -f $filterToken) `
                -Remediation 'Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" FilterAdministratorToken 1'
        }
    }

    # ================================================================ Protocolos heredados
    Invoke-Checked -Name 'SYS-SMB' -Block {
        $smb1 = $null
        try {
            $cfg = Get-SmbServerConfiguration -ErrorAction Stop
            $smb1 = [bool]$cfg.EnableSMB1Protocol
            Add-Metric -Name 'smb1_enabled' -Value $smb1

            if ($smb1) {
                Add-Finding -Id 'SYS-060' -Severity 'High' -Category 'Protocolos' `
                    -Title 'SMBv1 habilitado' `
                    -Detail 'EnableSMB1Protocol=True. Protocolo obsoleto con vulnerabilidades criticas (EternalBlue/WannaCry).' `
                    -Remediation 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force'
            }

            if (-not $cfg.RequireSecuritySignature) {
                Add-Finding -Id 'SYS-061' -Severity 'Medium' -Category 'Protocolos' `
                    -Title 'Firma SMB no obligatoria' `
                    -Detail 'RequireSecuritySignature=False. Permite ataques de retransmision/relay NTLM.' `
                    -Remediation 'Set-SmbServerConfiguration -RequireSecuritySignature $true -Force'
            }

            if ($cfg.EnableSMB2Protocol -eq $false) {
                Add-Finding -Id 'SYS-062' -Severity 'Medium' -Category 'Protocolos' `
                    -Title 'SMBv2 deshabilitado' `
                    -Detail 'EnableSMB2Protocol=False. Fuerza el uso de SMBv1 o rompe el acceso a recursos.' `
                    -Remediation 'Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force'
            }
        }
        catch {
            Add-Finding -Id 'SYS-063' -Severity 'Info' -Category 'Protocolos' `
                -Title 'Configuracion SMB no consultable' `
                -Detail $_.Exception.Message `
                -Remediation 'Ejecute elevado para consultar Get-SmbServerConfiguration.'
        }

        # Acceso invitado a recursos remotos
        $guestAuth = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'AllowInsecureGuestAuth' -Default 0
        if ([int]$guestAuth -eq 1) {
            Add-Finding -Id 'SYS-064' -Severity 'Medium' -Category 'Protocolos' `
                -Title 'Acceso invitado a recursos SMB permitido' `
                -Detail 'AllowInsecureGuestAuth=1. Permite conexiones a servidores sin credenciales.' `
                -Remediation 'Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" AllowInsecureGuestAuth 0'
        }
    }

    # ================================================================ Servicios remotos
    Invoke-Checked -Name 'SYS-Remotos' -Block {
        # RDP
        $rdp = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Default 1
        Add-Metric -Name 'rdp_enabled' -Value ([int]$rdp -eq 0)
        if ([int]$rdp -eq 0) {
            $nla = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Default 0
            $severity = 'Medium'
            $extra = ''
            if ([int]$nla -ne 1) { $severity = 'High'; $extra = ' Ademas, NLA (UserAuthentication) esta desactivado.' }
            Add-Finding -Id 'SYS-070' -Severity $severity -Category 'Acceso remoto' `
                -Title 'Escritorio remoto (RDP) habilitado' `
                -Detail ('fDenyTSConnections=0: RDP acepta conexiones.{0}' -f $extra) `
                -Remediation 'Si no se usa: Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" fDenyTSConnections 1. Si se usa, exija NLA y VPN.'
        }

        # Asistencia remota
        $ra = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Default 0
        if ([int]$ra -eq 1) {
            Add-Finding -Id 'SYS-071' -Severity 'Medium' -Category 'Acceso remoto' `
                -Title 'Asistencia remota habilitada' `
                -Detail 'fAllowToGetHelp=1. Permite invitaciones de escritorio remoto.' `
                -Remediation 'Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" fAllowToGetHelp 0'
        }

        # WinRM
        $winrm = Get-Service -Name WinRM -ErrorAction SilentlyContinue
        if ($winrm -and $winrm.Status -eq 'Running') {
            $listeners = @()
            try { $listeners = @(Get-ChildItem 'WSMan:\localhost\Listener' -ErrorAction Stop) } catch { }
            Add-Finding -Id 'SYS-072' -Severity 'Medium' -Category 'Acceso remoto' `
                -Title 'WinRM activo' `
                -Detail ('Servicio WinRM en ejecucion con {0} listener(s). Es la via de administracion remota de PowerShell y objetivo habitual de movimiento lateral.' -f $listeners.Count) `
                -Remediation 'Si no se usa: Stop-Service WinRM ; Set-Service WinRM -StartupType Disabled'
        }

        # Cola de impresion (PrintNightmare y superficie amplia)
        $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
        if ($spooler -and $spooler.Status -eq 'Running' -and $deep) {
            Add-Finding -Id 'SYS-073' -Severity 'Low' -Category 'Acceso remoto' `
                -Title 'Cola de impresion en ejecucion' `
                -Detail 'Servicio Spooler activo. Ha sido vector de escalada (PrintNightmare) y no es necesario en equipos sin impresoras.' `
                -Remediation 'Si no imprime: Stop-Service Spooler ; Set-Service Spooler -StartupType Disabled'
        }
    }

    # ================================================================ Resolucion de nombres
    Invoke-Checked -Name 'SYS-LLMNR' -Block {
        $llmnr = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Default 1
        Add-Metric -Name 'llmnr_enabled' -Value ([int]$llmnr -ne 0)
        if ([int]$llmnr -ne 0) {
            Add-Finding -Id 'SYS-080' -Severity 'Medium' -Category 'Red' `
                -Title 'LLMNR habilitado' `
                -Detail ('EnableMulticast={0}. LLMNR permite responder consultas de nombre por multicast; Responder/Inveigh capturan hashes NTLMv2.' -f $llmnr) `
                -Remediation 'Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" EnableMulticast 0'
        }

        if ($deep) {
            $nbts = @()
            $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
            try {
                foreach ($i in (Get-ChildItem $base -ErrorAction Stop)) {
                    $v = Get-RegValue -Path $i.PSPath -Name 'NetbiosOptions' -Default 0
                    if ([int]$v -ne 2) { $nbts += ('{0}={1}' -f $i.PSChildName, $v) }
                }
            }
            catch { }
            if ($nbts.Count -gt 0) {
                Add-Finding -Id 'SYS-081' -Severity 'Low' -Category 'Red' `
                    -Title 'NetBIOS sobre TCP/IP activo en alguna interfaz' `
                    -Detail ('Interfaces con NetbiosOptions distinto de 2 (deshabilitado): {0}' -f ($nbts -join ', ')) `
                    -Remediation 'Set NetbiosOptions=2 en cada interfaz o deshabilite NetBIOS en las propiedades del adaptador.'
            }
        }
    }

    # ================================================================ PowerShell
    Invoke-Checked -Name 'SYS-PowerShell' -Block {
        $sbLog = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Default 0
        $modLog = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -Default 0

        Add-Metric -Name 'ps_scriptblock_logging' -Value $sbLog
        if ([int]$sbLog -ne 1) {
            Add-Finding -Id 'SYS-090' -Severity 'Medium' -Category 'Registro' `
                -Title 'Registro de bloques de script desactivado' `
                -Detail ('EnableScriptBlockLogging={0}. Sin esto, la ejecucion de PowerShell ofuscado no deja rastro util para forense.' -f $sbLog) `
                -Remediation 'Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" EnableScriptBlockLogging 1'
        }
        if ([int]$modLog -ne 1) {
            Add-Finding -Id 'SYS-091' -Severity 'Low' -Category 'Registro' `
                -Title 'Registro de modulos PowerShell desactivado' `
                -Detail ('EnableModuleLogging={0}.' -f $modLog) `
                -Remediation 'Habilite ModuleLogging con los modulos de interes.'
        }

        $pol = @()
        try { $pol = @(Get-ExecutionPolicy -List -ErrorAction Stop) } catch { }
        $policies = @()
        $persistentPolicy = $null
        foreach ($p in $pol) {
            $policies += ('{0}={1}' -f $p.Scope, $p.ExecutionPolicy)
            # El ambito Process refleja el -ExecutionPolicy con el que se lanzo
            # esta auditoria (INICIAR.cmd usa Bypass): no es configuracion del
            # equipo y jamas debe reportarse como postura del sistema.
            if ([string]$p.Scope -ne 'Process' -and [string]$p.ExecutionPolicy -ne 'Undefined') {
                $persistentPolicy = [string]$p.ExecutionPolicy
            }
        }
        if (-not $persistentPolicy) { $persistentPolicy = 'Restricted (por defecto)' }
        Add-Metric -Name 'ps_execution_policy' -Value $persistentPolicy
        Add-Metric -Name 'ps_execution_policy_effective_this_process' -Value ([string](Get-ExecutionPolicy))

        if ($persistentPolicy -eq 'Unrestricted' -or $persistentPolicy -eq 'Bypass') {
            Add-Finding -Id 'SYS-092' -Severity 'Low' -Category 'Registro' `
                -Title ('Politica de ejecucion permisiva: {0}' -f $persistentPolicy) `
                -Detail ('Politicas por ambito: {0}. Bypass/Unrestricted no impide ejecutar scripts descargados.' -f ($policies -join ', ')) `
                -Remediation 'Set-ExecutionPolicy RemoteSigned -Scope LocalMachine'
        }
        else {
            Add-Finding -Id 'SYS-OK-EP' -Severity 'Info' -Category 'Registro' `
                -Title ('Politica de ejecucion persistente: {0}' -f $persistentPolicy) `
                -Detail ('Politicas por ambito: {0}. El ambito Process se ignora porque lo impone la propia auditoria.' -f ($policies -join ', ')) `
                -Remediation 'Ninguna.'
        }

        if ($deep) {
            # Sin DISM: la consulta oficial tarda minutos y puede fallar incluso
            # con elevacion. Get-PsV2State usa CIM y el registro.
            $v2 = Get-PsV2State
            if ($v2.State -eq 'Enabled') {
                Add-Finding -Id 'SYS-093' -Severity 'Medium' -Category 'Registro' `
                    -Title 'Motor PowerShell v2 disponible' `
                    -Detail ('MicrosoftWindowsPowerShellV2 esta habilitado ({0}). Permite ejecutar scripts evadiendo el registro de bloques de script (downgrade attack).' -f $v2.Source) `
                    -Remediation 'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart'
            }
        }
    }

    # ================================================================ Persistencia
    Invoke-Checked -Name 'SYS-Autoruns' -Block {
        $keys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        )
        $entries = @()
        foreach ($k in $keys) {
            if (-not (Test-Path -LiteralPath $k)) { continue }
            try {
                $item = Get-ItemProperty -LiteralPath $k -ErrorAction Stop
                foreach ($p in $item.PSObject.Properties) {
                    if ($p.Name -like 'PS*') { continue }
                    $entries += @{ key = $k; name = $p.Name; command = [string]$p.Value }
                }
            }
            catch { }
        }
        Add-Metric -Name 'autoruns' -Value $entries.Count
        [void](Write-Evidence -Name 'autoruns.json' -Data $entries)

        if ($entries.Count -gt 0) {
            $lines = @()
            foreach ($e in $entries) { $lines += ('{0} = {1}' -f $e['name'], $e['command']) }
            Add-Finding -Id 'SYS-100' -Severity 'Info' -Category 'Persistencia' `
                -Title ('Entradas de arranque automatico: {0}' -f $entries.Count) `
                -Detail ($lines -join ' | ') `
                -Remediation 'Revise que cada entrada corresponda a software instalado y conocido.' `
                -Evidence 'autoruns.json'
        }
    }

    # ================================================================ Tareas programadas
    if ($deep) {
        Invoke-Checked -Name 'SYS-Tareas' -Block {
            $tasks = @()
            try {
                $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
                    $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*'
                })
            }
            catch { }

            $suspicious = @()
            foreach ($t in $tasks) {
                $actions = @()
                try { $actions = @($t.Actions | ForEach-Object { [string]$_.Execute + ' ' + [string]$_.Arguments }) } catch { }
                $cmd = ($actions -join ' ')
                if ($cmd -match '(?i)(powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|bitsadmin|certutil|curl|wget)') {
                    $suspicious += ('{0}\{1} -> {2}' -f $t.TaskPath, $t.TaskName, $cmd.Trim())
                }
            }

            Add-Metric -Name 'scheduled_tasks_custom' -Value $tasks.Count
            [void](Write-Evidence -Name 'scheduled-tasks.json' -Data ($tasks | ForEach-Object { @{ path = $_.TaskPath; name = $_.TaskName; state = [string]$_.State } }))

            if ($suspicious.Count -gt 0) {
                Add-Finding -Id 'SYS-110' -Severity 'Medium' -Category 'Persistencia' `
                    -Title ('Tareas programadas con interpretes de comando: {0}' -f $suspicious.Count) `
                    -Detail ($suspicious -join ' | ') `
                    -Remediation 'Revise cada tarea con Get-ScheduledTaskInfo y deshabilite las que no reconozca.' `
                    -Evidence 'scheduled-tasks.json'
            }
        }
    }

    # ================================================================ Servicios riesgosos
    Invoke-Checked -Name 'SYS-Servicios' -Block {
        $services = @()
        try { $services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop) } catch { }

        $unquoted = @()
        $riskData = @()
        foreach ($s in $services) {
            $path = [string]$s.PathName
            if (-not $path) { continue }

            # Ruta sin comillas con espacios y .exe no en la primera posicion
            if ($path -notmatch '^\s*"') {
                if ($path -match '^(.+?\.exe)' ) {
                    $exePart = $matches[1]
                    if ($exePart -match '\s' -and ($path.Length -gt $exePart.Length)) {
                        $unquoted += ('{0} :: {1}' -f $s.Name, $path)
                        $riskData += @{ name = $s.Name; path = $path; issue = 'unquoted_service_path'; state = [string]$s.State }
                    }
                }
            }

            # Servicios con ruta en carpetas escribibles por usuarios
            if ($path -match '(?i)(\\Users\\Public\\|\\Temp\\|\\AppData\\Local\\Temp\\|\\ProgramData\\[^\\]+\\?$)') {
                $riskData += @{ name = $s.Name; path = $path; issue = 'path_in_writable_location'; state = [string]$s.State }
            }
        }

        [void](Write-Evidence -Name 'services-risk.json' -Data $riskData)
        Add-Metric -Name 'unquoted_service_paths' -Value $unquoted.Count

        if ($unquoted.Count -gt 0) {
            Add-Finding -Id 'SYS-120' -Severity 'High' -Category 'Servicios' `
                -Title ('Rutas de servicio sin comillas: {0}' -f $unquoted.Count) `
                -Detail ($unquoted -join ' | ') `
                -Remediation 'Entrecomille la ruta del binario en cada servicio afectado (sc qc <servicio> para verla).' `
                -Evidence 'services-risk.json'
        }
        else {
            Add-Finding -Id 'SYS-OK-SVC' -Severity 'Info' -Category 'Servicios' `
                -Title 'Sin rutas de servicio sin comillas' `
                -Detail ('Se revisaron {0} servicios.' -f $services.Count) `
                -Remediation 'Ninguna.'
        }
    }

    # ================================================================ Discos
    Invoke-Checked -Name 'SYS-Discos' -Block {
        $bad = @()
        try {
            foreach ($d in (Get-PhysicalDisk -ErrorAction Stop)) {
                if ([string]$d.HealthStatus -ne 'Healthy') {
                    $bad += ('{0} ({1})' -f $d.FriendlyName, $d.HealthStatus)
                }
            }
        }
        catch { }

        if ($bad.Count -gt 0) {
            Add-Finding -Id 'SYS-130' -Severity 'Medium' -Category 'Sistema' `
                -Title 'Discos con estado de salud degradado' `
                -Detail ($bad -join ' | ') `
                -Remediation 'Respalde los datos y revise el disco con el fabricante (SMART).'
        }

        $low = @()
        foreach ($d in @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue)) {
            if ($null -eq $d.Size -or $d.Size -le 0) { continue }
            $pct = ($d.FreeSpace / $d.Size) * 100
            if ($pct -lt 5) {
                Add-Finding -Id ('SYS-131-' + ($d.DeviceID -replace ':','')) -Severity 'High' -Category 'Sistema' `
                    -Title ('Disco {0} casi lleno' -f $d.DeviceID) `
                    -Detail ('Libre: {0} de {1} ({2}%).' -f (Format-Size ([long]$d.FreeSpace)), (Format-Size ([long]$d.Size)), [math]::Round($pct, 1)) `
                    -Remediation 'Libere espacio: un disco lleno impide actualizaciones, logs y puede corromper bases de datos.'
            }
            elseif ($pct -lt 10) {
                Add-Finding -Id ('SYS-132-' + ($d.DeviceID -replace ':','')) -Severity 'Medium' -Category 'Sistema' `
                    -Title ('Disco {0} con poco espacio' -f $d.DeviceID) `
                    -Detail ('Libre: {0} de {1} ({2}%).' -f (Format-Size ([long]$d.FreeSpace)), (Format-Size ([long]$d.Size)), [math]::Round($pct, 1)) `
                    -Remediation 'Planifique la limpieza antes de que baje del 5%.'
            }
        }
    }

    Write-Log -Level OK -Message 'SISTEMA: diagnostico completado'
}
