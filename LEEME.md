# USB Security Audit Toolkit — Manual del operador

Versión 1.0.0 · Auditoría defensiva de Windows y Linux desde un USB

---

## 1. Qué hace y qué NO hace

**Qué hace**

- Audita la configuración de seguridad de un equipo Windows o Linux: sistema, red, servicios en escucha, cabeceras TLS/HTTP de sitios web y estado de endurecimiento.
- Produce evidencia reproducible en `evidencia\<ID>\`: datos crudos en JSON, un `findings.json` con esquema único para ambas plataformas y un informe HTML autocontenido.
- Opcionalmente aplica 16 controles de *hardening* en Windows (y un conjunto equivalente en Linux) **solo** si se pide explícitamente el modo 4 / `--apply`.
- Genera un archivo de rollback antes de tocar nada, para poder revertir cada control aplicado.

**Qué NO hace**

- No explota vulnerabilidades, no lanza fuerza bruta, no hace *pivoting* ni post-explotación. No es un pentest.
- No envía datos a Internet. El único tráfico de red saliente son las peticiones a los destinos web que usted configure y las pruebas de DNS/ping.
- No instala software, no descarga binarios, no modifica cuentas de usuario, contraseñas, BitLocker ni discos.
- No cifra, no exfiltra y no se oculta: todo lo que hace queda en `engine.log` y en la carpeta de evidencia.
- No sustituye a un análisis profesional. Es una foto del estado de configuración en un momento dado.

**Por defecto es solo lectura.** Ningún modo escribe en el registro, en servicios o en archivos del sistema salvo el modo 4 (o `--mode … --apply` en Linux), que lo hace de forma explícita, verificada y reversible.

---

## 2. Aviso legal

> **Use esta herramienta únicamente en equipos de su propiedad o en equipos para los que tenga autorización escrita y vigente del responsable.**
>
> Auditar, escanear o modificar un sistema sin autorización puede constituir un delito en su jurisdicción (por ejemplo, acceso no autorizado a sistemas informáticos, daños informáticos o interceptación de comunicaciones), incluso si no causa ningún daño aparente.
>
> El modo de *hardening* (opción 4) **modifica la configuración de seguridad del equipo** y puede romper aplicaciones heredadas, compartir archivos por SMB, impresoras en red o acceso remoto. Aplíquelo solo con ventana de mantenimiento y con un plan de reversión probado.
>
> La tarea programada opcional de `PREPARAR-AUTORUN.ps1` deja **persistencia** en el equipo auditado y es visible para cualquier análisis forense. Instálela solo con autorización explícita y documentándola en el alcance del trabajo.

El autor del toolkit no asume responsabilidad por el uso indebido.

---

## 3. Cómo usar en Windows

Requisitos: Windows 10 / 11 / Server 2016 o superior, PowerShell 5.1 (incluido en el sistema).

1. Conecte el USB.
2. Doble clic en **`INICIAR.cmd`**.
3. Acepte el aviso de UAC (se necesita elevación: sin administrador la mayoría de comprobaciones quedan fuera de alcance).
4. Elija un modo en el menú:

| Opción | Modo | Qué hace | Duración orientativa |
|---|---|---|---|
| **1** | Rápido | Comprobaciones esenciales: SO, Defender, firewall, UAC, SMB, LLMNR, usuarios, servicios de riesgo, puertos en escucha, DNS y latencia. | < 90 s |
| **2** | Completo | Todo lo del rápido más análisis profundo: TPM/Secure Boot/BitLocker, tareas programadas, autoruns, rutas de servicio sin comillas, Wi-Fi guardada, recursos SMB, IPv6/Teredo, plan de hardening completo. | 2–5 min |
| **3** | Web | TLS, certificados y caducidad, cabeceras de seguridad, cookies, redirecciones y divulgación de versiones de los destinos configurados. | 10–60 s por destino |
| **4** | Rápido + aplicar hardening | Ejecuta el modo rápido y después **modifica** el sistema para cumplir los 16 controles. Genera rollback. | 1–3 min + reinicio si aplica |
| **5** | Salir | No hace nada. | — |

Uso no interactivo (útil para guiones y para auditorías repetidas):

```bat
INICIAR.cmd 1
INICIAR.cmd 2
INICIAR.cmd 3
INICIAR.cmd 3 https://mi-sitio.com https://intranet.local
INICIAR.cmd 4
INICIAR.cmd --help
```

Al terminar, el script abre el informe en el navegador y muestra la ruta de `findings.json`. La ventana espera una tecla (`pause`) para que pueda leer los mensajes.

**Rutas con espacios** están soportadas: si el USB se monta como `E:\Mi USB\`, el script funciona sin cambios (`cd /d "%~dp0"` y todas las rutas van entre comillas).

Si el toolkit está incompleto (falta `engine\Audit-Windows.ps1` o la configuración), el script lo dice y sale sin ejecutar nada.

---

## 4. Cómo usar en Linux

Requisitos: bash 4+, `coreutils`, `curl`, `openssl`. Root recomendado.

```bash
# IMPORTANTE: FAT32/exFAT no guardan permisos de ejecución.
# Tras copiar el toolkit al USB o al disco, una sola vez:
chmod +x INICIAR.sh linux/audit-linux.sh linux/modules/*.sh

./INICIAR.sh            # menú interactivo
./INICIAR.sh 1          # rápido
./INICIAR.sh 2          # completo
./INICIAR.sh 3          # web (destinos de config/settings.json)
./INICIAR.sh 3 https://mi-sitio.com
./INICIAR.sh 4          # rápido + aplicar hardening (pide sudo)
./INICIAR.sh --help
```

Notas:

- El menú equivalente ofrece las mismas cinco opciones que en Windows.
- La opción 4 requiere root; si no lo es, el script se relanza con `sudo` cuando está disponible. **Aplicar hardening de SSH sin `--apply` consciente puede dejarlo fuera del servidor**: revise el plan antes de aplicarlo en un equipo remoto.
- El motor Linux escribe `findings.json`, `resumen.md` y, si aplica, `rollback-<id>.sh` dentro de `evidencia\<ID>\`.
- Para generar el informe HTML de una evidencia Linux puede hacerlo desde el propio Linux (con `pwsh`) o desde cualquier Windows:

```bash
pwsh -File report/Build-Report.ps1 -EvidenceDir evidencia/LIN-20261025-101500
```

```powershell
.\report\Build-Report.ps1 -EvidenceDir D:\evidencia\LIN-20261025-101500
```

Ese es el punto del diseño: **un solo generador de informes para ambas plataformas**, porque `findings.json` usa el mismo esquema.

---

## 5. Qué genera

Todo se escribe bajo `evidencia\`, una carpeta por ejecución. El identificador es `<HOST>-<AAAAMMDD>-<HHMMSS>` (por ejemplo `DESKTOP-X-20261025-143012`).

```
evidencia\
  DESKTOP-X-20261025-143012\
    findings.json          Datos completos de la auditoría (esquema único Win/Linux)
    informe.html           Informe navegable autocontenido (CSS inline, sin JS externo)
    resumen.txt            Resumen de 10 líneas, legible en cualquier editor
    engine.log             Registro cronológico de la ejecución y de cada check
    system-before.json     Instantánea inicial: SO, CPU, RAM, discos
    users.json             Usuarios locales, administradores, cuentas sin contraseña
    autoruns.json          Entradas Run/RunOnce y tareas programadas relevantes
    services-risk.json     Servicios y rutas de servicio potencialmente peligrosas
    network.json           Adaptadores, rutas, DNS, ARP, proxy, Wi-Fi
    ports.json             Puertos en escucha y proceso propietario
    web.json               Resultado por destino web (TLS, cabeceras, cookies)
    hardening-before.json  Estado de los 16 controles antes de aplicar
    hardening-plan.json    Diferencia entre estado actual y estado deseado
    rollback-<id>.json     Valores originales para revertir (solo con -Apply)
    remediacion.cmd        Comandos exactos para aplicar los controles pendientes (se genera solo
                           en modo diagnostico o si una aplicacion no se verifico; ejecutar como
                           administrador; no registra valores previos)
```

En Linux la estructura es la misma, con `resumen.md` adicional y `rollback-<id>.sh` en lugar del JSON de rollback.

Cosas prácticas:

- **No borre `engine.log`**: es la prueba de qué se ejecutó y qué falló.
- La carpeta `evidencia\` crece; archive las auditorías antiguas fuera del USB.
- Un mismo USB admite varias auditorías: nunca se sobrescriben porque el `ID` incluye fecha y hora.

---

## 6. Cómo leer el informe

**Score (0–100)** — empieza en 100 y resta por cada hallazgo: **Critical −25, High −12, Medium −5, Low −1, Info 0**. Suelo en 0. Un score alto significa "pocas cosas graves encontradas", no "equipo seguro".

**Grade** — A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F < 60.

**Severidades**

| Severidad | Significado | Qué hacer |
|---|---|---|
| **Critical** | Compromiso inmediato o casi seguro: cuenta invitado activa, `AlwaysInstallElevated=1`, contraseña de autologon en claro, certificado TLS inválido. | Corregir hoy, antes de seguir usando el equipo. |
| **High** | Debilidad explotable con esfuerzo bajo: SMBv1 activo, WDigest con credenciales en claro, exclusiones de Defender, cookies sin `Secure`, RDP expuesto. | Corregir en el mismo ciclo de trabajo. |
| **Medium** | Mala práctica con impacto condicionado: firmas de Defender antiguas, falta de HSTS o CSP, pérdida de paquetes > 20 %, servicios de riesgo en escucha local. | Planificar corrección en días. |
| **Low** | Higiene y divulgación de información: `Server` con versión, falta de `X-Content-Type-Options`, `SameSite` ausente. | Incluir en el próximo mantenimiento. |
| **Info** | Resultado correcto o dato de contexto. **No es un problema**: demuestra que el check se ejecutó. | Ninguna acción. |

**Cómo navegar**: las tarjetas superiores cuentan hallazgos por severidad; la tabla se ordena de más a menos grave y se agrupa por categoría con `<details>`. El pie indica versión del toolkit y el aviso de uso autorizado.

**Lea siempre el `Detail`**: incluye el valor observado concreto (por ejemplo `PermitRootLogin=yes`), no una descripción genérica. La columna `Remediation` da el comando o la ruta exacta para corregirlo.

---

## 7. Cómo revertir un hardening

### Windows

Cada ejecución con `-Apply` escribe `evidencia\<ID>\rollback-<ID>.json` con el valor original, el tipo y la ruta exacta de cada clave o servicio tocado. **Ese JSON es la fuente de verdad de la reversión.**

Si su copia del toolkit generó además el script autogenerado de reversión `Rollback-Hardening.ps1`, ejecútelo como administrador indicando el rollback de la ejecución que quiere deshacer:

```powershell
# Desde la raíz del toolkit, como administrador
powershell -NoProfile -ExecutionPolicy Bypass -File .\Rollback-Hardening.ps1 `
    -RollbackFile .\evidencia\DESKTOP-X-20261025-143012\rollback-DESKTOP-20261025-143012.json
```

El rollback restaura únicamente lo que el toolkit cambió; lo que ya estaba en el valor deseado no se toca. Algunos controles (por ejemplo `RunAsPPL`) requieren **reinicio** para surtir efecto o para revertirse.

### Aplicar sin -Apply (remediacion.cmd)

Si ejecutó la auditoría en modo diagnóstico (opción 1 o 3) y quiere aplicar solo los controles pendientes sin volver a correr el motor, la carpeta de evidencia contiene `remediacion.cmd`: un script `.cmd` ASCII (sin BOM) con los comandos exactos (`reg add`, `powershell`, `dism`) por control. Ejecútelo como administrador:

    evidencia\<ID>\remediacion.cmd

El script se eleva solo si es posible, cuenta los errores (`FALLOS`) y termina con `pause`. No registra los valores previos: para tener rollback automático use la opción 4 de `INICIAR.cmd` (-Apply). Tampoco toca BitLocker, cuentas ni discos.

Si su copia no incluye ese script, restaure a mano leyendo el JSON: cada entrada indica la ruta, el nombre del valor, el tipo y el valor anterior. Use `Set-ItemProperty` para claves del registro, `Set-Service` para servicios y el cmdlet correspondiente en los controles aplicados con cmdlets (`Set-SmbServerConfiguration`, `Disable-WindowsOptionalFeature`, etc.).

### Linux

Cada ejecución con `--apply` escribe `evidencia/<ID>/rollback-<ID>.sh`, ejecutable y reversible:

```bash
sudo bash evidencia/LIN-20261025-101500/rollback-LIN-20261025-101500.sh
```

Alternativamente, el toolkit incluye `linux/Rollback-Hardening.sh`, que localiza y aplica el rollback indicado:

```bash
sudo bash linux/Rollback-Hardening.sh evidencia/LIN-20261025-101500/rollback-LIN-20261025-101500.sh
```

> **Riesgo de bloqueo remoto**: revertir `PasswordAuthentication` o `PermitRootLogin` en un servidor al que solo accede por SSH puede dejarlo fuera. Pruebe el rollback en un equipo de laboratorio antes de confiar en él en producción.

---

## 8. Controles de hardening

### 8.1 Windows — 16 controles

| ID | Control | Qué cambia exactamente |
|---|---|---|
| **H01** | Defender CloudBlockLevel | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MAPS\CloudBlockLevel` = `2` (DWORD). Bloqueo "alto" de archivos desconocidos. |
| **H02** | ASR en bloqueo | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules` con 8 reglas = `1` (Block): `BE9BA2D9`, `D4F940AB`, `5BEB7EFE`, `92E97FA1`, `9E6C4E1F`, `E6DB77E5`, `D1E49AAC`, `B2B3F03D`. |
| **H03** | Firewall | Los 3 perfiles (`Domain`, `Private`, `Public`): `Enabled=True`, `DefaultInboundAction=Block`, `LogBlocked=True`. |
| **H04** | SMB | `Set-SmbServerConfiguration -EnableSMB1Protocol $false` y `-RequireSecuritySignature $true` (firma SMB obligatoria). |
| **H05** | Acceso remoto | `fDenyTSConnections=1` (RDP apagado) y `fAllowToGetHelp=0` (Asistencia remota apagada). |
| **H06** | AutoRun / AutoPlay | `HKLM\...\Explorer\NoDriveTypeAutoRun` = `0xFF`, `HKLM\...\Policies\Explorer\NoAutorun` = `1`, `NoDriveTypeAutoRun` = `0xFF` en política. |
| **H07** | Registro de PowerShell | `ScriptBlockLogging\EnableScriptBlockLogging` = `1` y `ModuleLogging\EnableModuleLogging` = `1` en `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell`. |
| **H08** | SmartScreen | `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableSmartScreen` = `1`, `ShellSmartScreenLevel` = `Warn`. |
| **H09** | LLMNR | `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast` = `0` (DWORD). |
| **H10** | UAC | `ConsentPromptBehaviorAdmin` = `2` (consentimiento en escritorio seguro) y `PromptOnSecureDesktop` = `1` en `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`. |
| **H11** | WDigest | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential` = `0`. Evita credenciales en claro en memoria. |
| **H12** | LSA Protection | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` = `1`. **Requiere reinicio.** |
| **H13** | AlwaysInstallElevated | `AlwaysInstallElevated` = `0` en `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer` **y** en `HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer`. |
| **H14** | AutoLogon | Detecta `HKLM\...\Winlogon\DefaultPassword`. Se **reporta** siempre; la contraseña solo se elimina con `-Apply` explícito, porque puede dejar el equipo inaccesible. |
| **H15** | PowerShell v2 | Deshabilita la característica opcional `MicrosoftWindowsPowerShellV2` (motor y bloque de características). Elimina el *downgrade* a PSv2 sin registro de eventos. |
| **H16** | NBT-NS | Por cada interfaz activa, `NetbiosOptions` = `2` (deshabilitado) en `...\Services\NetBT\Parameters\Interfaces\Tcpip_*`. Solo en modo completo. |

Todos son idempotentes: si el valor ya es el deseado, no se toca y se registra como *skipped*. Tras aplicar, se relee el valor y se marca `verified: true|false`.

**Nunca se toca**: BitLocker, cuentas de usuario, contraseñas, unidades de disco, Hyper-V, VMnet ni nada fuera del alcance de estos 16 controles.

### 8.2 Linux — controles equivalentes

| Control | Qué comprueba / qué cambia con `--apply` |
|---|---|
| Firewall | `ufw` activo o reglas `nftables`/`iptables` con política por defecto restrictiva. Con `--apply` solo reporta; no activa un firewall a ciegas para no cortar servicios. |
| SSH `PermitRootLogin` | Debe ser `no`. Con `--apply` escribe `PermitRootLogin no` en un drop-in de `sshd_config` y valida con `sshd -t`. |
| SSH `PasswordAuthentication` | Debe ser `no` (solo claves). Con `--apply` escribe el drop-in. **Riesgo de lockout**: hágalo solo con clave ya instalada. |
| Permisos de `/etc/shadow` | Esperado `640 root:shadow` (o `600 root:root`). Con `--apply` corrige modo y propietario. |
| Permisos de `~/.ssh` | Directorio `700`, `authorized_keys` `600`, `id_*` `600`. Con `--apply` ajusta los permisos. |
| `ip_forward` | `net.ipv4.ip_forward=0` salvo que sea router. Con `--apply` escribe en `sysctl.d` y aplica. |
| `rp_filter` | `net.ipv4.conf.all.rp_filter=1` (protección contra *spoofing*). |
| ASLR | `kernel.randomize_va_space=2`. Con `--apply` lo fija en `sysctl.d` y en caliente. |
| SUID inusuales | Lista binarios SUID fuera de las rutas esperadas (`/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`). Solo reporta. |
| Grupo `docker` | Pertenecer a `docker` equivale a root. Solo reporta; nunca quita usuarios de grupos. |
| `fail2ban` | Servicio activo y con *jails* configurados. Solo reporta. |
| `auditd` | Servicio activo y con reglas. Solo reporta. |
| `unattended-upgrades` | Actualizaciones automáticas de seguridad activas. Solo reporta. |
| Core dumps | `fs.suid_dumpable=0` y límite `core 0` para evitar volcados con datos sensibles. |

Los controles que solo reportan están marcados así a propósito: aplicar cambios de red o de grupos sin contexto puede dejar el servidor inaccesible.

---

## 9. Limitaciones honestas

1. **AutoRun no funciona en Windows moderno.** `autorun.inf` está incluido por compatibilidad con equipos antiguos y para dar etiqueta e icono al volumen. Windows Vista y posteriores desactivan AutoRun en unidades extraíbles por política, y Windows 10/11 además exigen lista blanca. **No espere que se ejecute solo por insertar el USB.** Para eso existe la tarea programada opcional (`PREPARAR-AUTORUN.ps1`), que deja persistencia visible.
2. **Requiere administrador para el 90 % de los checks.** Sin elevación, el informe se llena de hallazgos "no verificable" y el score queda artificialmente bajo. El script eleva por UAC; si cancela, no se ejecuta nada.
3. **El modo rápido no audita web** salvo que se pasen destinos explícitamente. En modo rápido, `web.targets` se ignora para mantener el tiempo por debajo de 90 segundos.
4. **No sustituye a un pentest.** Comprueba configuración, no lógica de aplicación. Un score A no significa que el sistema sea inexpugnable.
5. **La foto caduca.** Un cambio de configuración posterior no aparece: repita la auditoría.
6. **El trigger de la tarea programada no filtra por letra de unidad.** Los eventos 2001/2003 de `Kernel-PnP` describen la configuración de un dispositivo, no el montaje de un volumen concreto. La tarea se dispara con cualquier dispositivo y la acción solo hace algo si `INICIAR.cmd` sigue existiendo en la ruta registrada. Si cambia la letra del USB, la tarea queda muerta (y es visible para un forense).
7. **En Linux, sin root, la mayoría de comprobaciones se omiten** (puertos, firewall, permisos de `/etc/shadow`, servicios). El propio script lo avisa.
8. **Rendimiento variable en redes lentas o con DNS roto.** Los timeouts están en `config\settings.json`; el modo completo puede acercarse a los 5 minutos en enlaces malos.
9. **El hardening puede romper cosas.** SMB1 apagado rompe equipos antiguos; RDP apagado corta el acceso remoto; `PasswordAuthentication no` corta el SSH con contraseña. Todo es reversible, pero solo si guarda el rollback.

---

## 10. Cómo añadir destinos web

Edite `config\settings.json` con cualquier editor de texto (Notepad, VS Code). El JSON no admite comentarios, así que los destinos reales van en el array `web.targets`; el valor `https://example.com` es solo un marcador de posición que debe sustituir.

```json
{
  "tool_version": "1.0.0",
  "web": {
    "targets": [
      "https://mi-sitio.com",
      "https://intranet.local:8443",
      "http://10.0.0.20"
    ],
    "timeout_s": 15
  },
  "network": {
    "dns_test_hosts": ["www.google.com", "www.cloudflare.com", "www.microsoft.com"],
    "ping_count": 4
  },
  "hardening": {
    "skip_controls": ["H12"]
  },
  "report": {
    "organization": "Nombre de su organizacion"
  }
}
```

Reglas:

- Use **URLs completas**, con esquema (`https://` o `http://`). Sin esquema el check puede fallar.
- Rutas con puerto están soportadas (`https://host:8443`).
- `timeout_s` es el tiempo máximo por petición; súbalo si audita destinos lentos.
- `hardening.skip_controls` permite excluir controles por ID (`H01`…`H16`). Útil en equipos donde un control rompe una aplicación concreta.
- `report.organization` aparece en la cabecera del informe HTML.
- Valide el JSON antes de usar: cualquier coma final o comilla suelta hará que el motor caiga a los valores por defecto y emita un hallazgo `PRE-CFG`.

Dos rutas, un solo archivo lógico: el toolkit se distribuye con `config\settings.json` en la raíz (la copia que usted edita), y el motor lee `engine\config\settings.json`. Si al arrancar `INICIAR.cmd` detecta que falta la copia del motor, la crea automáticamente a partir de la de la raíz. Si edita la configuración, edite **`config\settings.json`** y copie el archivo a `engine\config\` si ya existía.

También puede pasar destinos sin tocar el archivo:

```bat
INICIAR.cmd 3 https://mi-sitio.com https://otro-sitio.com
```

```bash
./INICIAR.sh 3 https://mi-sitio.com
```

Si pasa varios destinos por línea de comandos en Windows, `INICIAR.cmd` los entrega al motor como **una lista separada por comas** (`-Targets "url1,url2"`). Para un conjunto estable de destinos de auditoría recurrente es más claro mantenerlos en `config\settings.json`, que acepta un array JSON real.

---

## 11. Requisitos

| Plataforma | Requisitos |
|---|---|
| **Windows** | Windows 10, 11 o Server 2016+ (probado en x64). PowerShell 5.1 incluido en el sistema. Privilegios de administrador. `pwsh` 7 es opcional; el lanzador lo usa si está y cae a `powershell.exe` si no. |
| **Linux** | bash 4+, `coreutils`, `curl`, `openssl`. Root para la mayoría de checks y para `--apply`. Para el informe HTML desde Linux: PowerShell 7 (`pwsh`) o generar el HTML en un Windows. |
| **Almacenamiento** | Cualquier USB o carpeta. FAT32/exFAT funcionan, pero **no guardan permisos**: en Linux haga `chmod +x` tras copiar. |
| **Red** | Opcional. Sin red, la auditoría local funciona; los chequeos de DNS, latencia y web reportarán error (no abortan la ejecución). |
| **Dependencias externas** | Ninguna. Sin instaladores, sin binarios `.exe`, sin descargas en tiempo de ejecución. |

Estructura del toolkit para referencia rápida:

```
INICIAR.cmd              Entrada Windows (eleva por UAC, abre el informe)
INICIAR.sh               Entrada Linux
LEEME.md                 Este documento
autorun.inf              Inerte en Windows moderno; solo legado y etiqueta
PREPARAR-AUTORUN.ps1     Instalador opcional de tarea programada (admin)
config\settings.json     Configuracion editable (destinos, timeouts)
engine\                  Motor Windows (orquestador, lib, modulos)
linux\                   Motor Linux (bash)
report\Build-Report.ps1  Generador HTML para evidencia Windows o Linux
evidencia\               Salida (se crea en la primera ejecucion)
remediacion.cmd           (generado) Comandos para aplicar el hardening pendiente sin -Apply
```

---

*USB Security Audit Toolkit 1.0.0 — herramienta defensiva. Úsela solo con autorización.*
