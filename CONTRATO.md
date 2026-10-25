# CONTRATO TECNICO — USB Security Audit Toolkit

Version: 1.0.0
Fecha: 2026-10-25
Destino final: raiz del USB (D:\), construido en C:\Users\Ghost\usb-audit

Herramienta DEFENSIVA de auditoria y hardening. Por defecto solo LEE.
Solo modifica el sistema con -Apply / --apply explicito.

---

## 1. ARQUITECTURA

```
<USB>\
  INICIAR.cmd                  # entrada Windows (doble clic, eleva UAC)
  INICIAR.sh                   # entrada Linux (chmod +x)
  LEEME.md                     # instrucciones
  autorun.inf                  # inerte en Windows moderno; presente para legado
  PREPARAR-AUTORUN.ps1         # instalador OPCIONAL de tarea programada (requiere admin)
  engine\
    Audit-Windows.ps1          # orquestador
    lib\
      Common.ps1               # contexto, logging, findings, evidencia
      Report-Html.ps1          # generador de informe HTML self-contained
    modules\
      P00-Preflight.ps1
      P10-Sistema.ps1
      P20-Red.ps1
      P30-Web.ps1
      P40-Hardening.ps1
      P50-Informe.ps1
    config\
      settings.json            # destinos web, umbrales, timeouts
  linux\
    audit-linux.sh             # orquestador
    lib\common.sh
    lib\report.sh              # genera findings.json + resumen .md
    modules\
      l10-system.sh
      l20-network.sh
      l30-web.sh
      l40-hardening.sh
    Rollback-Hardening.sh
  report\
    Build-Report.ps1           # genera HTML desde cualquier carpeta de evidencia (Win o Linux)
  evidencia\                   # SALIDA (se crea por ejecucion)
```

Sin binarios. Sin .exe. Sin dependencias externas.
Windows: PowerShell 5.1 nativo. Linux: bash 4+, coreutils, curl, openssl.

---

## 2. CONTRATO PowerShell (lib/Common.ps1)

Todas las funciones son de scope global. Los modulos las consumen sin dot-source
(el orquestador ya hizo dot-source de Common.ps1).

```powershell
# --- Contexto global ---
# $script:Ctx es un PSCustomObject con:
#   Id             string   'HOST-20261025-143012'
#   Host           string   nombre del equipo
#   Os             string   descripcion del SO
#   OsFamily       string   'Windows' | 'Linux'
#   Mode           string   'rapido' | 'completo' | 'web'
#   Apply          bool     $true solo si se paso -Apply
#   Started        datetime
#   RootPath       string   raiz del USB
#   EvidenceDir    string   <Root>\evidencia\<Id>
#   Findings       List[object]
#   Metrics        hashtable
#   Hardening      hashtable @{ Applied=@(); Skipped=@(); RollbackFile=''; RemediationFile='' }
#   ToolVersion    string   '1.0.0'

Initialize-AuditContext -Mode <string> -Apply <bool> -RootPath <string>  # devuelve $script:Ctx
Write-Log -Level <INFO|OK|WARN|ERROR|CHECK> -Message <string>            # consola + engine.log
Add-Finding -Id <string> -Severity <Critical|High|Medium|Low|Info> `
            -Category <string> -Title <string> -Detail <string> `
            -Remediation <string> [-Evidence <string>]
Test-Admin                                                              # bool
Invoke-Checked -Name <string> -Block <scriptblock>                      # nunca aborta; loguea duracion y error
Write-Evidence -Name <string> -Data <object>                            # JSON o texto -> EvidenceDir; devuelve ruta
Add-Metric -Name <string> -Value <object>
Get-RegValue  -Path <string> -Name <string> [-Default <object>]
Set-RegValueChecked -Path <string> -Name <string> -Value <object> -Type <DWord|String|QWord|ExpandString> `
                   -ControlId <string>                                  # registra rollback automatico
Get-HardeningOriginal -ControlId <string> -Path <string> -Name <string> -Kind <Reg|Service|Cmdlet> -Payload <hashtable>
Format-Size -Bytes <long>
New-TempFile -Suffix <string>
```

### Reglas de Add-Finding
- Id con prefijo de categoria y numero: `SYS-001`, `NET-004`, `WEB-002`, `HRD-011`, `LIN-003`.
- Id unico en toda la ejecucion. Si un check puede dispararse N veces, sufijar: `WEB-002-<slug>`.
- `Detail` debe incluir el valor observado concreto (no "esta mal" sino "PermitRootLogin=yes").
- `Remediation` debe ser accionable: comando o ruta exacta.
- `Evidence` es ruta RELATIVA a EvidenceDir o vacia.
- Todo check DEBE emitir al menos un finding Info con el resultado OK, para que el informe
  demuestre que se ejecuto. Id `SYS-OK-01`, etc.

### Reglas de Invoke-Checked
- Captura excepciones, las convierte en finding `Info` con prefijo `ERR-` y continua.
- Mide duracion y la guarda en Metrics como `<Name>_ms`.

---

## 3. ESQUEMA findings.json (compartido Windows/Linux)

```json
{
  "tool": { "name": "USB Security Audit Toolkit", "version": "1.0.0" },
  "audit": {
    "id": "HOST-20261025-143012",
    "host": "DESKTOP-X",
    "os": "Windows 11 Pro 23H2 (build 22631.4317)",
    "os_family": "Windows",
    "mode": "completo",
    "apply": false,
    "started": "2026-10-25T14:30:12Z",
    "finished": "2026-10-25T14:33:41Z",
    "duration_s": 209,
    "operator": "Ghost",
    "elevated": true
  },
  "score": { "value": 62, "grade": "D", "critical": 1, "high": 3, "medium": 7, "low": 12, "info": 18 },
  "findings": [
    {
      "id": "HRD-001",
      "severity": "High",
      "category": "Hardening",
      "title": "SMBv1 habilitado",
      "detail": "EnableSMB1Protocol=True",
      "remediation": "Set-SmbServerConfiguration -EnableSMB1Protocol $false",
      "evidence": "hardening-before.json",
      "status": "open"
    }
  ],
  "metrics": { "listening_ports": 24, "disk_free_pct": 37.6 },
  "hardening": { "applied": ["HRD-001"], "skipped": [], "rollback_file": "rollback-20261025-143012.json" }
}
```

### Scoring
Base 100. Restar: Critical 25, High 12, Medium 5, Low 1, Info 0. Suelo 0.
Grade: >=90 A, >=80 B, >=70 C, >=60 D, <60 F.

---

## 4. MODULOS WINDOWS

Cada archivo define UNA funcion `Invoke-<Nombre> -Ctx $ctx`.
Ningun modulo escribe findings.json; lo hace el orquestador al final.

### P00-Preflight.ps1 — `Invoke-Preflight`
- Verifica admin, version PS, espacio libre, escritura en EvidenceDir.
- Crea EvidenceDir. Snapshots iniciales: `system-before.json` via CIM (OS, CPU, RAM, disco).
- Si no hay admin: finding High `PRE-001`, sigue en modo solo-lectura.

### P10-Sistema.ps1 — `Invoke-Sistema`
Checks minimos (rapido) y profundos (completo):
- OS build, uptime, fecha instalacion, Secure Boot, TPM, BitLocker.
- Hotfix mas reciente + antiguedad en dias (>60 = Medium). Pending reboot (3 claves).
- Defender: RTP, tamper, edad firmas (>3 dias Medium), CloudBlockLevel, ASR count,
  **exclusiones configuradas** (cualquier exclusion = High, es vector de ataque).
- Firewall: 3 perfiles enabled, DefaultInboundAction, LogBlocked.
- Usuarios locales habilitados + miembros de Administradores + PasswordRequired=false + cuentas sin expiracion.
- Cuentas invitado/DefaultAccount habilitadas = Critical.
- WDigest UseLogonCredential=1 = Critical.
- LSA RunAsPPL=0 = High.
- AlwaysInstallElevated=1 en HKCU o HKLM = Critical.
- AutoLogon DefaultPassword presente = Critical.
- UAC: EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop.
- LLMNR/NBT-NS, SMB1, SMB signing, guest access.
- RDP (fDenyTSConnections), Remote Assistance, WinRM.
- PowerShell: ScriptBlockLogging, ModuleLogging, execution policy, PSv2 instalado.
- Servicios con ruta sin comillas (unquoted service path) — listar, High si hay.
- Tareas programadas no-Microsoft habilitadas.
- Autoruns Run/RunOnce (HKLM, HKLM\Wow6432Node, HKCU).
- Discos: HealthStatus != Healthy, free < 10% (Medium), < 5% (High).
Salidas: `system-before.json`, `users.json`, `autoruns.json`, `services-risk.json`.

### P20-Red.ps1 — `Invoke-Red`
- Adaptadores activos: IP, mascara, gateway, DNS, DHCP, MTU, velocidad, tipo.
- Rutas por defecto, tabla ARP (entradas incompletas/duplicadas).
- DNS: resolucion de 3 dominios conocidos, tiempos; fallo total = High.
- Latencia: 4 pings a gateway y a 1.1.1.1; perdida >20% = Medium, >50% = High.
- Puertos en escucha no-loopback con proceso dueno; marcar riesgosos
  (21,23,135,139,445,3389,5900,6379,27017,9200,11211) = Medium/High segun exposicion.
- Conexiones establecidas salientes a IPs publicas con puerto no estandar (top 15) = Info.
- Recursos SMB compartidos no administrativos = Medium.
- Proxy configurado, WinHTTP proxy.
- Wi-Fi: perfiles guardados con autenticacion abierta = Medium.
- IPv6 habilitado + Teredo/ISATAP = Info.
Salidas: `network.json`, `ports.json`.

### P30-Web.ps1 — `Invoke-Web`
Lee `$ctx.Config.web.targets` (array de URLs). Para cada destino:
- Resolucion DNS + IPs.
- TCP connect (tiempo).
- TLS via SslStream: protocolo negociado, cipher, cert Subject/Issuer/NotAfter/dias restantes/SAN count.
  - <15 dias = High, <30 = Medium, cadena invalida = Critical, TLS < 1.2 = High.
- HTTP(S) con HttpWebRequest: status, URL final, redirects, Server, X-Powered-By, X-AspNet-Version.
- Cabeceras de seguridad: HSTS (y max-age), CSP, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy, COOP, COEP, CORP.
  - Falta HSTS en HTTPS = Medium; falta CSP = Medium; falta X-Content-Type-Options = Low; resto Low.
- Info disclosure: Server con version concreta, X-Powered-By, X-AspNet-Version = Low.
- Cookies: Set-Cookie sin Secure en HTTPS = High; sin HttpOnly = Medium; sin SameSite = Low.
- HTTPS->HTTP downgrade o ausencia de redireccion a HTTPS = High.
- `/robots.txt` y `/.well-known/security.txt` (presencia = Info).
- Timeout 15s por peticion, max 10 redirects. Nunca lanzar excepcion al orquestador.
Salidas: `web.json`.

### P40-Hardening.ps1 — `Invoke-Hardening`
- Sin -Apply: solo compara estado actual vs deseado y emite findings + `hardening-plan.json`.
- Con -Apply: aplica, verifica releyendo, y escribe `rollback-<id>.json`.
- Idempotente: lo que ya esta bien no se toca.
- Controles (id estable):
  H01 Defender CloudBlockLevel=2
  H02 ASR 8 reglas en Block (BE9BA2D9, D4F940AB, 5BEB7EFE, 92E97FA1, 9E6C4E1F, E6DB77E5, D1E49AAC, B2B3F03D)
  H03 Firewall 3 perfiles inbound Block + LogBlocked
  H04 SMB1 off + signing required
  H05 RDP + Remote Assistance off
  H06 AutoRun/AutoPlay off (NoDriveTypeAutoRun=0xFF, NoAutorun=1)
  H07 ScriptBlockLogging + ModuleLogging
  H08 SmartScreen Warn
  H09 LLMNR off
  H10 UAC ConsentPromptBehaviorAdmin=2 + PromptOnSecureDesktop=1
  H11 WDigest UseLogonCredential=0
  H12 LSA RunAsPPL=1 (marcar requires_reboot)
  H13 AlwaysInstallElevated=0 (HKCU y HKLM)
  H14 AutoLogon DefaultPassword ausente (si existe: reportar, NO borrar sin -Apply explicito)
  H15 PSv2 deshabilitado
  H16 NBT-NS off por interfaz (solo modo completo)
- Nunca tocar: BitLocker, cuentas de usuario, contraseñas, unidades de disco.
- Cada control aplicado: re-leer y registrar `verified: true|false`.
- Si quedan controles fuera de politica (diagnostico o verificacion fallida), se genera
  `evidencia\<ID>\remediacion.cmd`: un .cmd ASCII sin BOM con los comandos exactos
  (reg add / powershell / dism) para aplicarlos manualmente como administrador,
  sin depender del motor. El nombre del archivo se expone en `Hardening.RemediationFile`
  y en el finding `HRD-PEND`. No registra valores previos: para rollback usar -Apply.

### P50-Informe.ps1 — `Invoke-Informe`
- Escribe `findings.json` (esquema seccion 3) desde $ctx.
- Llama a `New-HtmlReport -Ctx $ctx` de lib/Report-Html.ps1 -> `informe.html`.
- Escribe `resumen.txt` (10 lineas legibles).
- Copia `engine.log` al EvidenceDir.

### lib/Report-Html.ps1 — `New-HtmlReport`
- HTML5 self-contained: CSS inline, sin JS externo, sin fuentes remotas.
- Cabecera: host, SO, fecha, duracion, modo, elevado si/no, score y grade con color.
- Tarjetas por severidad (Critical/High/Medium/Low/Info).
- Tabla de findings ordenada por severidad, con filtro por category mediante <details>.
- Seccion de hardening: aplicado / pendiente / rollback.
- Seccion de metricas.
- Pie: version, aviso de uso autorizado.
- Codificacion UTF-8, escapado HTML obligatorio de todo dato dinamico.

---

## 5. CONTRATO LINUX (bash)

`linux/audit-linux.sh [--mode rapido|completo|web] [--apply] [--out DIR] [--no-color]`

- Funciones en common.sh: `log`, `ok`, `warn`, `err`, `section`, `add_finding`,
  `json_escape`, `have`, `need_root`, `metric`, `evidence_write`.
- Debe generar `<out>/findings.json` con el MISMO esquema de la seccion 3.
- Construccion de JSON a mano (printf) con escapado correcto; validar con
  `python3 -m json.tool` si existe, si no con `jq -e .` si existe, si no omitir.
- Modulos: l10-system, l20-network, l30-web, l40-hardening.
- l30-web usa curl + openssl; si falta openssl, degradar a solo HTTP y avisar.
- l40-hardening con --apply escribe `rollback-<id>.sh` ejecutable y reversible.
  Controles Linux: ufw/nftables activo, SSH PermitRootLogin no, PasswordAuthentication no,
  permisos de /etc/shadow y ~/.ssh, ip_forward, rp_filter, ASLR, SUID inusuales,
  docker group, fail2ban, auditd, unattended-upgrades, core dumps.
  NUNCA aplicar cambios de SSH sin --apply y sin aviso explicito de riesgo de lockout.
- `Rollback-Hardening.sh` lee el rollback y revierte.
- Salida tambien `resumen.md`.

---

## 6. ENTRADAS

### INICIAR.cmd
- Detecta su propia unidad, comprueba PowerShell, lanza `Audit-Windows.ps1`
  elevado via `Start-Process -Verb RunAs`, con ventana visible.
- Pregunta modo si no se pasa argumento: 1=rapido, 2=completo, 3=web, 4=rapido+aplicar hardening.
- Al terminar, abre `informe.html` en el navegador y hace `pause`.

### PREPARAR-AUTORUN.ps1
- Opcional, requiere admin. Registra una tarea programada que se dispara al insertar
  el USB (evento 2003 de Kernel-PnP) y ejecuta INICIAR.cmd en modo rapido.
- Deja `desinstalar-autorun.ps1` para revertir.
- Debe avisar: esto deja persistencia en el equipo auditado.

### config/settings.json
```json
{
  "tool_version": "1.0.0",
  "web": { "targets": ["https://example.com"], "timeout_s": 15 },
  "network": { "dns_test_hosts": ["www.google.com","www.cloudflare.com","www.microsoft.com"], "ping_count": 4 },
  "hardening": { "skip_controls": [] },
  "report": { "organization": "" }
}
```

---

## 7. RESTRICCIONES DURAS

1. PowerShell 5.1 compatible. Prohibido: `?:`, `??`, `-Parallel`, `ForEach-Object -Parallel`,
   clases, `using namespace`. Si dudas, usa `if/else` y `foreach`.
2. Sin dependencias externas ni descargas en tiempo de ejecucion.
3. Todo acceso a disco de salida dentro de EvidenceDir o RootPath.
4. Ningun modulo puede abortar la ejecucion completa: todo via Invoke-Checked.
5. Timeout por operacion de red. Sin bucles infinitos. Sin `Read-Host` dentro de modulos.
6. No tocar: LaboratorioIA, VM de Kali, VMnet, Hyper-V, discos, BitLocker, cuentas.
7. ASCII puro en .cmd y .sh (sin tildes/ñ, sin BOM). Los .ps1 pueden llevar tildes;
   el build los re-guarda en UTF-8 con BOM.
8. Idioma de la interfaz y del informe: espanol.
9. Todo texto dinamico en HTML debe pasar por escapado.
10. Cada script debe poder ejecutarse dos veces seguidas sin efectos duplicados.

---

## 8. CRITERIOS DE ACEPTACION

- `INICIAR.cmd` en un Windows 11 limpio: pregunta modo, eleva, corre y abre informe.html.
- Modo rapido < 90 s. Modo completo < 5 min (sin red externa).
- `Audit-Windows.ps1 -Mode rapido -Apply:$false` no modifica NI UN valor del sistema:
  verificable comparando snapshots before/after de las 16 claves del hardening.
- Con `-Apply`, los 16 controles quedan aplicados y verificados, y el rollback revierte
  exactamente a los valores previos.
- `bash audit-linux.sh --mode rapido` en Ubuntu/Debian genera findings.json valido.
- `Build-Report.ps1 -EvidenceDir <carpeta>` genera HTML identico en estructura al de Windows.
- Ningun archivo .exe en el USB. .ps1/.cmd/.sh/.json/.md/.html unicamente.

---

## 9. ADENDA 1.0.1 — cierre de huecos del contrato

Estas precisiones son vinculantes y corrigen omisiones de la seccion 2.

### 9.1 Propiedades adicionales de $script:Ctx

```powershell
#   Config      hashtable  contenido de engine/config/settings.json ya parseado
#                          (claves: web, network, hardening, report, tool_version)
#   Finished    datetime   se fija en P50
#   Score        int        se fija en P50
#   Elevated    bool       resultado de Test-Admin al inicio
#   Errors      int        contador de fallos capturados por Invoke-Checked
```

`Initialize-AuditContext` DEBE cargar `settings.json` desde `<RootPath>\engine\config\settings.json`
y dejarlo en `$Ctx.Config`. Si el archivo falta o es invalido, usar estos defaults y
emitir un finding Info `PRE-CFG` (no abortar nunca):

```json
{ "tool_version":"1.0.0",
  "web": { "targets": [], "timeout_s": 15 },
  "network": { "dns_test_hosts": ["www.google.com","www.cloudflare.com","www.microsoft.com"], "ping_count": 4 },
  "hardening": { "skip_controls": [] },
  "report": { "organization": "" } }
```

### 9.2 Score compartido — `Get-AuditScore`

Vive en `engine\lib\Report-Html.ps1` (unico dueno). Firma:

```powershell
Get-AuditScore -Findings <list>     # devuelve PSCustomObject @{ value; grade; critical; high; medium; low; info }
```

Formula: base 100, resta Critical 25 / High 12 / Medium 5 / Low 1 / Info 0, suelo 0.
Grade: >=90 A, >=80 B, >=70 C, >=60 D, <60 F.

Lo consumen P50 (para `findings.json`), `New-HtmlReport` y `Build-Report.ps1`.
Ningun otro archivo debe reimplementar la formula.

### 9.3 Orden de carga (Audit-Windows.ps1)

No hardcodear el orden. El orquestador debe:

```powershell
Get-ChildItem (Join-Path $PSScriptRoot 'lib')      -Filter *.ps1 | Sort-Object Name | ForEach-Object { . $_.FullName }
Get-ChildItem (Join-Path $PSScriptRoot 'modules')  -Filter *.ps1 | Sort-Object Name | ForEach-Object { . $_.FullName }
```

Asi `Common.ps1` y `Report-Html.ps1` cargan antes que `P00..P50` por nombre, y ningun
modulo puede romper el arranque por depender de otro.

### 9.4 Funciones helper dentro de modulos

Si un modulo necesita un helper no previsto, lo define en su propio archivo con prefijo
unico (`function P20-...`, `function P30-...`). **Prohibido** agregar funciones nuevas a
`Common.ps1` sin actualizar este contrato, para que los duenos de otros modulos no
queden desincronizados.

### 9.5 Prefijos de finding por dueno (evita colisiones de Id)

| Dueno | Archivos | Prefijos reservados |
|---|---|---|
| A | Common.ps1, Audit-Windows.ps1, P00, P10 | `PRE-`, `SYS-`, `ERR-` |
| B | P20, P30 | `NET-`, `WEB-` |
| C | P40, P50, Report-Html.ps1 | `HRD-`, `INF-` |
| D | linux/* | `LIN-`, `NET-`, `WEB-`, `HRD-` (namespace propio, no coexiste) |
| E | entradas, Build-Report.ps1, settings.json | ninguno |

### 9.6 New-HtmlReport — lectura defensiva

`New-HtmlReport -Ctx <object>` debe leer TODAS las propiedades con fallback
(`if ($Ctx.PSObject.Properties['Campo']) { ... } else { <default> }`), porque
`Build-Report.ps1` lo invoca desde un objeto distinto al de una auditoria viva.
Si recibe `Findings` y no `Score`, calcula el score con `Get-AuditScore`.

### 9.7 Fin del contrato

---

## 10. ADENDA 1.0.2 - escala de postura y lectura principal

Motivo: la formula del contrato (25/12/5/1) es una medida de **cumplimiento
estricto**, no de riesgo operativo. Con esa escala cualquier equipo real con dos
o tres hallazgos High cae por debajo de 60, incluidos equipos ya endurecidos, y
el numero deja de ser util para decidir. Se anade una segunda escala calibrada
sin tocar la primera.

### 10.1 Que NO cambia

- `score` conserva exactamente la formula de la seccion 3 y la de 9.2:
  base 100, Critical 25, High 12, Medium 5, Low 1, Info 0, suelo 0.
  Grado: >=90 A, >=80 B, >=70 C, >=60 D, <60 F.
- `score` se sigue publicando en `findings.json` y no se elimina de ningun sitio.
- `Get-AuditScore -Findings <list>` sigue devolviendo el score del contrato por
  defecto. Las llamadas existentes no requieren cambios.

### 10.2 Escala de postura

```
postura = max(0, 100 - 20*Critical - 6*High - 3*Medium - 1*Low)
grado   = >=90 A, >=80 B, >=70 C, >=60 D, <60 F
techo   = si Critical > 0, el grado no puede ser A ni B (maximo C)
```

El techo evita que un unico Critical, que solo resta 20 puntos, se lea como una
B. La severidad manda sobre la aritmetica.

### 10.3 Donde se publica

```json
"posture": {
  "host": { "value": 74, "grade": "C", "critical": 0, "high": 2, "medium": 4, "low": 2, "info": 19 },
  "web":  [ { "target": "https://ejemplo.com", "value": 87, "grade": "B", "critical": 0, "high": 0, "medium": 2, "low": 7 } ],
  "note": "..."
}
```

- `posture.host`: hallazgos del equipo, **excluyendo** las categorias `Web` y
  `Preflight`. Es `null` en `--mode web` / `-Mode web`, porque ahi el equipo no
  se audita y cero hallazgos no significan conformidad.
- `posture.web[]`: una entrada por sitio, con la misma escala.
- `posture` es una propiedad **aditiva** del esquema: un consumidor que solo
  conozca `score` sigue funcionando.

### 10.4 Lectura principal en los informes

El badge del HTML y la primera linea del resumen muestran **postura**. El score
del contrato aparece como dato secundario, etiquetado como cumplimiento. En modo
web la postura principal es la de los sitios (el peor de ellos en el resumen de
Linux), nunca la del equipo no auditado.

### 10.5 Implementacion (un solo dueno por plataforma)

Windows - `engine\lib\Report-Html.ps1`:

```powershell
Get-AuditScore -Findings <list> [-Formula contract|posture] [-ExcludeCategories <list>]
```

Linux - `linux\lib\common.sh`:

```sh
score_from_counts c h m l            # contrato 25/12/5/1
posture_from_counts c h m l          # postura 20/6/3/1
posture_grade_from_counts c h m l    # grado de postura con techo C
```

Ningun otro archivo reimplementa ninguna de las dos escalas.
