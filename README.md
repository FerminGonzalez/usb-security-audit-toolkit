# USB Security Audit Toolkit

Herramienta **defensiva** de auditoría y hardening para Windows y Linux, diseñada para ejecutarse desde un USB. Por defecto **solo lee**: no modifica el sistema salvo que se invoque explícitamente con `-Apply` / `--apply`.

> Todo lo que hace queda registrado en `engine.log` y en la carpeta de evidencia. No cifra, no exfiltra y no se oculta.

## Características

- **Auditoría Windows** (PowerShell 5.1): sistema, red, web (TLS, cabeceras, cookies), preflight de privilegios.
- **Auditoría Linux** (bash): sistema, red, web, servicios.
- **Auditoría web externa**: DNS, TLS, cabeceras de seguridad, cookies, info disclosure.
- **Hardening con verificación**: 16 controles (Defender, ASR, firewall, SMB, RDP, AutoRun, logging de PowerShell, SmartScreen, LLMNR, UAC, WDigest, LSA RunAsPPL, AlwaysInstallElevated, AutoLogon, PSv2, NBT-NS).
- **Remediación por comandos**: genera `evidencia\<ID>\remediacion.cmd` (ASCII sin BOM) con los comandos exactos para aplicar los controles pendientes manualmente, sin depender del motor.
- **Rollback automático**: cada control aplicado guarda su valor original y se puede revertir.
- **Informe HTML autocontenido** (sin JS ni fuentes remotas) + `findings.json` con esquema único para ambas plataformas.
- **Postura calibrada**: `100 − 20×Critical − 6×High − 3×Medium − 1×Low` (techo de grado C si hay algún Critical).

## Inicio rápido

### Windows
```cmd
INICIAR.cmd            # menú interactivo
INICIAR.cmd 1          # rápido (solo lectura)
INICIAR.cmd 2          # completo
INICIAR.cmd 3          # web (destinos de config\settings.json)
INICIAR.cmd 4          # rápido + aplicar hardening (eleva UAC)
INICIAR.cmd --help
```

### Linux
```bash
chmod +x INICIAR.sh linux/audit-linux.sh linux/modules/*.sh
./INICIAR.sh           # menú interactivo
./INICIAR.sh 1         # rápido
./INICIAR.sh 4         # rápido + aplicar hardening (pide sudo)
```

## Estructura

```
<USB>\
  INICIAR.cmd / INICIAR.sh
  CONTRATO.md              # especificación técnica vinculante
  LEEME.md                 # guía de uso
  autorun.inf              # inerte en Windows moderno
  PREPARAR-AUTORUN.ps1     # instalador OPCIONAL de tarea programada (requiere admin)
  engine\                  # motor Windows
    Audit-Windows.ps1
    lib\  (Common.ps1, Report-Html.ps1)
    modules\ (P00..P50)
    config\settings.json
  linux\                   # motor Linux
    audit-linux.sh
    lib\  (common.sh, report.sh)
    modules\ (l10..l40)
  report\Build-Report.ps1  # genera HTML desde cualquier evidencia
  evidencia\               # SALIDA (se crea en la primera ejecución)
```

## Documentación

- [LEEME.md](LEEME.md) — guía de uso, modos, rollback, límites conocidos.
- [CONTRATO.md](CONTRATO.md) — arquitectura, esquema de `findings.json`, controles H01–H16, contrato Linux.

## Seguridad y alcance

- **Solo lectura por defecto.** El hardening se aplica únicamente con `-Apply` / `--apply` explícito.
- **Nunca toca**: BitLocker, cuentas de usuario, contraseñas, unidades de disco, máquinas virtuales (VMware/Hyper-V/WSL).
- **BitLocker no es aplicable** en Windows 11 Home sin Modern Standby. El toolkit diagnostica TPM 2.0 / Secure Boot / UEFI / GPT y deja la decisión (Pro / VeraCrypt / aceptar riesgo) al operador.
- Payload script-only (sin ejecutables) para no disparar la regla ASR `B2B3F03D`.
- PowerShell 5.1 compatible (sin `?:`, `??`, `-Parallel`, clases, `-AsHashtable`).
- Codificación: `.cmd`/`.sh`/`autorun.inf` ASCII sin BOM; `.ps1` UTF-8 con BOM; JSON/HTML UTF-8 sin BOM.

## Licencia

MIT — uso educativo y defensivo. Utilícelo únicamente en equipos propios o con autorización escrita del responsable.