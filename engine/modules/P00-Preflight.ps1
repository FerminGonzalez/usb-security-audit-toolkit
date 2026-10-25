<#
  P00-Preflight.ps1
  USB Security Audit Toolkit - verificacion previa y snapshot inicial
  Dueno: UNIDAD A | Version: 1.0.0
  PowerShell 5.1 compatible
#>

function Invoke-Preflight {
    param([Parameter(Mandatory = $true)] $Ctx)

    Write-Log -Level INFO -Message 'PREFLIGHT: verificando entorno del operador'

    # ------------------------------------------------------------------ admin
    Invoke-Checked -Name 'PRE-Admin' -Block {
        $admin = Test-Admin
        if (-not $admin) {
            Add-Finding -Id 'PRE-001' -Severity 'High' -Category 'Preflight' `
                -Title 'Ejecucion sin privilegios de administrador' `
                -Detail 'El proceso no esta elevado. La mayoria de los checks de seguridad leen claves HKLM, servicios y Defender, que requieren elevacion. Varios resultados seran incompletos y el hardening no se puede aplicar.' `
                -Remediation 'Cierre y ejecute INICIAR.cmd aceptando el aviso de UAC, o abra PowerShell como administrador.'
        }
        else {
            Add-Finding -Id 'PRE-OK-01' -Severity 'Info' -Category 'Preflight' `
                -Title 'Ejecucion elevada' `
                -Detail 'El proceso corre con privilegios administrativos.' `
                -Remediation 'Ninguna.'
        }
    }

    # ------------------------------------------------------------------ version PS
    Invoke-Checked -Name 'PRE-PowerShell' -Block {
        $psv = $PSVersionTable.PSVersion
        $text = $psv.ToString()
        $clr = 'desconocido'
        try { $clr = $PSVersionTable.CLRVersion.ToString() } catch { }

        if ($psv.Major -lt 5) {
            Add-Finding -Id 'PRE-002' -Severity 'High' -Category 'Preflight' `
                -Title 'PowerShell obsoleto' `
                -Detail ('Version detectada: {0}. El toolkit requiere 5.1 o superior.' -f $text) `
                -Remediation 'Actualice PowerShell (WMF 5.1) antes de usar el toolkit.'
        }
        elseif ($psv.Major -eq 5 -and $psv.Minor -lt 1) {
            Add-Finding -Id 'PRE-003' -Severity 'Medium' -Category 'Preflight' `
                -Title 'PowerShell anterior a 5.1' `
                -Detail ('Version detectada: {0}.' -f $text) `
                -Remediation 'Instale WMF 5.1.'
        }
        else {
            Add-Finding -Id 'PRE-PS-OK' -Severity 'Info' -Category 'Preflight' `
                -Title 'Version de PowerShell adecuada' `
                -Detail ('PowerShell {0} (CLR {1}).' -f $text, $clr) `
                -Remediation 'Ninguna.'
        }
        Add-Metric -Name 'powershell_version' -Value $text
    }

    # ------------------------------------------------------------------ escritura real
    Invoke-Checked -Name 'PRE-Escritura' -Block {
        $probe = Join-Path $Ctx.EvidenceDir ('probe-' + [Guid]::NewGuid().ToString('N').Substring(0, 8) + '.tmp')
        $enc = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($probe, 'probe', $enc)
        $okWrite = Test-Path -LiteralPath $probe
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue

        # espacio libre en el volumen del USB
        $driveLetter = $null
        try {
            $qual = Split-Path -Qualifier $Ctx.RootPath
            if ($qual) { $driveLetter = $qual.TrimEnd(':', '\') }
        }
        catch { }
        $freeBytes = $null
        if ($driveLetter) {
            try {
                $vol = Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='{0}:'" -f $driveLetter) -ErrorAction Stop
                $freeBytes = [long]$vol.FreeSpace
            }
            catch { }
        }
        if ($null -ne $freeBytes) {
            Add-Metric -Name 'usb_free_bytes' -Value $freeBytes
            if ($freeBytes -lt 200MB) {
                Add-Finding -Id 'PRE-004' -Severity 'Medium' -Category 'Preflight' `
                    -Title 'Poco espacio libre en el USB' `
                    -Detail ('Libre: {0}. Una auditoria completa puede necesitar varios MB de evidencia.' -f (Format-Size $freeBytes)) `
                    -Remediation 'Libere espacio en la unidad USB antes de auditar.'
            }
        }

        if (-not $okWrite) {
            Add-Finding -Id 'PRE-005' -Severity 'High' -Category 'Preflight' `
                -Title 'La carpeta de evidencia no es escribible' `
                -Detail ('No se pudo escribir en {0}.' -f $Ctx.EvidenceDir) `
                -Remediation 'Verifique que el USB no este en modo solo lectura ni protegido por politica.'
        }
    }

    # ------------------------------------------------------------------ snapshot
    Invoke-Checked -Name 'PRE-Snapshot' -Block {
        $snap = @{}
        $snap['captured_at'] = (Get-Date).ToString('o')

        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $snap['os'] = @{
                caption        = $os.Caption
                version        = $os.Version
                build          = $os.BuildNumber
                architecture   = $os.OSArchitecture
                install_date   = $(if ($os.InstallDate) { $os.InstallDate.ToString('yyyy-MM-dd') } else { $null })
                last_boot      = $(if ($os.LastBootUpTime) { $os.LastBootUpTime.ToString('o') } else { $null })
                serial         = $os.SerialNumber
                locale         = $os.Locale
            }
            if ($os.LastBootUpTime) {
                $up = (Get-Date) - $os.LastBootUpTime
                $snap['uptime_hours'] = [math]::Round($up.TotalHours, 1)
            }
            $snap['memory'] = @{
                total_mb = [math]::Round($os.TotalVisibleMemorySize / 1024, 0)
                free_mb  = [math]::Round($os.FreePhysicalMemory / 1024, 0)
            }
        }
        catch {
            $snap['os'] = @{ caption = 'no disponible'; error = $_.Exception.Message }
        }

        try {
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            $snap['computer'] = @{
                manufacturer = $cs.Manufacturer
                model        = $cs.Model
                domain       = $cs.Domain
                part_of_domain = [bool]$cs.PartOfDomain
                total_ram_gb = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
            }
        }
        catch { }

        try {
            $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
            $snap['cpu'] = @{
                name  = $cpu.Name
                cores = $cpu.NumberOfCores
                logical = $cpu.NumberOfLogicalProcessors
                max_mhz = $cpu.MaxClockSpeed
            }
        }
        catch { }

        try {
            $disks = @()
            foreach ($d in (Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop)) {
                $item = @{
                    letter = $d.DeviceID
                    label  = $d.VolumeName
                    fs     = $d.FileSystem
                    total_gb = [math]::Round($d.Size / 1GB, 2)
                    free_gb  = [math]::Round($d.FreeSpace / 1GB, 2)
                }
                if ($d.Size -gt 0) {
                    $item['free_pct'] = [math]::Round(($d.FreeSpace / $d.Size) * 100, 1)
                }
                $disks += $item
            }
            $snap['disks'] = $disks
        }
        catch { }

        try {
            $tz = Get-CimInstance -ClassName Win32_TimeZone -ErrorAction Stop
            $snap['timezone'] = @{ caption = $tz.Caption; bias_min = $tz.Bias }
        }
        catch { }

        # Arranque seguro
        # Confirm-SecureBootUEFI exige elevacion y tarda en fallar; el registro
        # equivalente es legible por cualquier usuario y es instantaneo.
        $snap['secure_boot'] = $null
        $snap['secure_boot_source'] = ''
        if (Test-Admin) {
            try {
                $snap['secure_boot'] = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
                $snap['secure_boot_source'] = 'Confirm-SecureBootUEFI'
            }
            catch { }
        }
        if ($null -eq $snap['secure_boot']) {
            $sbReg = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name 'UEFISecureBootEnabled' -Default $null
            if ($null -ne $sbReg) {
                $snap['secure_boot'] = ([int]$sbReg -eq 1)
                $snap['secure_boot_source'] = 'registro UEFISecureBootEnabled'
            }
            else {
                $snap['secure_boot_note'] = 'No consultable (equipo BIOS/legacy o sin permisos)'
            }
        }

        # TPM y BitLocker: ambos exigen elevacion; sin ella se reporta como
        # no evaluado en lugar de gastar segundos en un acceso denegado.
        if (Test-Admin) {
            try {
                $tpm = Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop
                $snap['tpm'] = @{
                    present    = $true
                    enabled    = [bool]$tpm.IsEnabled_InitialValue
                    activated  = [bool]$tpm.IsActivated_InitialValue
                    spec       = $tpm.SpecVersion
                }
            }
            catch {
                $snap['tpm'] = @{ present = $false; note = 'No detectado o sin acceso' }
            }

            try {
                $bl = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop
                $snap['bitlocker'] = @{
                    mount   = 'C:'
                    status  = [string]$bl.ProtectionStatus
                    percent = $bl.EncryptionPercentage
                    method  = [string]$bl.EncryptionMethod
                }
            }
            catch {
                $snap['bitlocker'] = @{ mount = 'C:'; status = 'no consultable' }
            }
        }
        else {
            $snap['tpm'] = @{ present = $null; note = 'no evaluado: requiere elevacion' }
            $snap['bitlocker'] = @{ mount = 'C:'; status = 'no evaluado: requiere elevacion' }
        }

        [void](Write-Evidence -Name 'system-before.json' -Data $snap)
        Add-Metric -Name 'secure_boot' -Value $snap['secure_boot']

        $osInfo = $snap['os']
        $detail = 'Snapshot inicial capturado.'
        if ($osInfo -and $osInfo['caption']) {
            $detail = ('SO: {0} build {1}. Arranque seguro: {2}.' -f $osInfo['caption'], $osInfo['build'], (Get-PropText $snap['secure_boot']))
        }
        Add-Finding -Id 'PRE-OK-02' -Severity 'Info' -Category 'Preflight' `
            -Title 'Snapshot del sistema capturado' `
            -Detail $detail `
            -Remediation 'Ninguna.' `
            -Evidence 'system-before.json'
    }

    # ------------------------------------------------------------------ entorno del operador
    Invoke-Checked -Name 'PRE-Entorno' -Block {
        $envInfo = @{
            operator      = $Ctx.Operator
            elevated      = [bool]$Ctx.Elevated
            powershell    = $PSVersionTable.PSVersion.ToString()
            culture       = (Get-Culture).Name
            ui_culture    = (Get-UICulture).Name
            usb_root      = $Ctx.RootPath
            evidence_dir  = $Ctx.EvidenceDir
            mode          = $Ctx.Mode
            apply         = [bool]$Ctx.Apply
            tool_version  = $Ctx.ToolVersion
            captured_at   = (Get-Date).ToString('o')
        }
        [void](Write-Evidence -Name 'preflight.json' -Data $envInfo)
    }
}

function Get-PropText {
    param($Value)
    if ($null -eq $Value) { return 'no consultable' }
    if ($Value -eq $true) { return 'habilitado' }
    if ($Value -eq $false) { return 'deshabilitado' }
    return [string]$Value
}
