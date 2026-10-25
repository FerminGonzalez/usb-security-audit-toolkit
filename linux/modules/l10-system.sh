#!/usr/bin/env bash
# USB Security Audit Toolkit - modulo l10: sistema, usuarios y configuracion base
# ASCII puro.

if [ -n "${AUDIT_L10_LOADED:-}" ]; then
    return 0
fi
AUDIT_L10_LOADED=1

# ---------------------------------------------------------------- utilidades
sysctl_get() {
    local key=$1
    local path="/proc/sys/${key//.//}"
    if [ -r "$path" ]; then
        tr -d '\n' < "$path"
        return 0
    fi
    if have sysctl; then
        sysctl -n "$key" 2>/dev/null
    fi
}

# Valor efectivo de sshd. sshd -T es la unica fuente fiable (aplica Includes,
# Match y valores por defecto); sin root se aproxima leyendo los archivos, y
# en ese caso se avisa en el propio hallazgo.
ssh_effective() {
    local key=$1
    if have sshd && need_root; then
        local v
        v=$(tmo 5 sshd -T 2>/dev/null | awk -v k="$key" 'tolower($1) == tolower(k) { print $2; exit }')
        if [ -n "$v" ]; then
            printf '%s' "$v"
            return 0
        fi
    fi
    local f
    for f in /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config; do
        [ -r "$f" ] || continue
        v=$(awk -v k="$key" '
            /^[[:space:]]*#/ { next }
            {
                if (tolower($1) == tolower(k)) { print $2; exit }
            }' "$f")
        if [ -n "$v" ]; then
            printf '%s' "$v"
            return 0
        fi
    done
    printf ''
}

# ---------------------------------------------------------------- sistema base
l10_system_os() {
    local os_text kernel uptime_days

    os_text="Linux"
    if [ -r /etc/os-release ]; then
        os_text=$(. /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-Linux}")
    fi
    kernel=$(uname -r 2>/dev/null)
    OS_TEXT="$os_text $kernel"

    local uptime_s
    uptime_s=$(awk '{ printf "%d", $1 }' /proc/uptime 2>/dev/null)
    uptime_days=$(( ${uptime_s:-0} / 86400 ))

    add_finding "LIN-OK-SYS" "Info" "Sistema" \
        "Sistema identificado" \
        "$OS_TEXT; arquitectura $(uname -m 2>/dev/null); encendido hace ${uptime_days} dia(s)." \
        "Ninguna."
    metric "uptime_days" "$uptime_days"

    # Disco: menos de 10% libre impide aplicar parches y registros.
    local worst_pct="" worst_mnt=""
    local mnt use pct
    while read -r mnt use; do
        pct=${use%\%}
        [ -n "$pct" ] || continue
        if [ -z "$worst_pct" ] || [ "$pct" -gt "$worst_pct" ]; then
            worst_pct=$pct
            worst_mnt=$mnt
        fi
    done <<EOF
$(df -P -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | awk 'NR > 1 { print $6, $5 }')
EOF

    if [ -n "$worst_pct" ]; then
        metric "disk_used_pct_max" "$worst_pct"
        if [ "$worst_pct" -ge 90 ]; then
            add_finding "LIN-010" "Medium" "Sistema" \
                "Poco espacio libre en $worst_mnt" \
                "Uso de disco al ${worst_pct}%. Por encima del 90% fallan las actualizaciones y los registros." \
                "Libere espacio con 'du -xh --max-depth=1 / | sort -h' y limpie cache de paquetes."
        else
            add_finding "LIN-OK-DISK" "Info" "Sistema" \
                "Espacio en disco suficiente" \
                "Particion mas llena: $worst_mnt al ${worst_pct}%." \
                "Ninguna."
        fi
    fi

    # Reinicio pendiente: los parches no estan activos hasta reiniciar.
    if [ -f /var/run/reboot-required ]; then
        add_finding "LIN-012" "Low" "Sistema" \
            "Reinicio pendiente" \
            "Existe /var/run/reboot-required: hay actualizaciones aplicadas que no estan activas." \
            "Programe un reinicio en ventana de mantenimiento."
    fi

    # Sincronizacion horaria: sin ella, TLS y los registros de auditoria mienten.
    local synced="desconocido"
    if have timedatectl; then
        synced=$(tmo 3 timedatectl show -p NTPSynchronized --value 2>/dev/null)
        [ -n "$synced" ] || synced="desconocido"
    elif have chronyc; then
        tmo 3 chronyc tracking >/dev/null 2>&1 && synced="yes" || synced="no"
    fi
    metric "time_synced" "$synced"
    if [ "$synced" = "no" ]; then
        add_finding "LIN-013" "Medium" "Sistema" \
            "Reloj sin sincronizar" \
            "timedatectl indica NTPSynchronized=no. Las marcas de tiempo de los registros y los certificados TLS dejan de ser fiables." \
            "systemctl enable --now systemd-timesyncd (o chrony)."
    fi
}

# ---------------------------------------------------------------- usuarios
l10_system_users() {
    local uid0="" extra_root="" empty="" sudoers="" no_shell="0" total="0"
    local passwd_ok=1

    if [ -r /etc/passwd ]; then
        while IFS=: read -r name _pass uid _gid _gecos _home shell; do
            [ "$uid" = "0" ] || continue
            total=$((total + 1))
            uid0="$uid0 $name"
            [ "$name" = "root" ] || extra_root="$extra_root $name"
            case "$shell" in
                */nologin|*/false|'') no_shell=$((no_shell + 1)) ;;
            esac
        done < /etc/passwd
    else
        passwd_ok=0
    fi

    metric "uid0_accounts" "$total"

    if [ "$passwd_ok" -eq 0 ]; then
        # Sin /etc/passwd legible no hay veredicto: afirmar "solo root tiene
        # UID 0" seria inventarse el resultado.
        add_finding "LIN-NV-UID0" "Info" "Usuarios" \
            "Cuentas UID 0 no verificables" \
            "No se pudo leer /etc/passwd. No se puede afirmar que solo root tenga UID 0." \
            "Ejecute la auditoria con sudo."
    elif [ -n "$extra_root" ]; then
        add_finding "LIN-020" "Critical" "Usuarios" \
            "Cuentas adicionales con UID 0" \
            "Ademas de root, tienen UID 0:$extra_root. Cualquiera de ellas es root con otro nombre y suele ser una puerta trasera." \
            "Verifique con 'getent passwd | awk -F: \"\$3==0\"' y deshabilite las que no esten justificadas."
    else
        add_finding "LIN-OK-UID0" "Info" "Usuarios" \
            "Solo root tiene UID 0" \
            "Se reviso /etc/passwd: no hay cuentas equivalentes a root." \
            "Ninguna."
    fi

    # Contrasenas vacias en /etc/shadow. Solo legible por root.
    if [ -r /etc/shadow ]; then
        empty=$(awk -F: '$2 == "" { printf "%s ", $1 }' /etc/shadow)
        if [ -n "$empty" ]; then
            add_finding "LIN-021" "Critical" "Usuarios" \
                "Cuentas con contrasena vacia" \
                "El campo de contrasena esta vacio en:$empty. Cualquier usuario local entra sin credencial." \
                "passwd -l <cuenta> para bloquearla o passwd <cuenta> para asignar una contrasena."
        else
            add_finding "LIN-OK-PWD" "Info" "Usuarios" \
                "Sin contrasenas vacias" \
                "Ninguna cuenta de /etc/shadow tiene el campo de contrasena vacio." \
                "Ninguna."
        fi
    else
        add_finding "LIN-NV-SHADOW" "Info" "Usuarios" \
            "Sin permiso para revisar /etc/shadow" \
            "Este check requiere root. No se puede afirmar que no existan contrasenas vacias." \
            "Repita la auditoria con sudo para obtener el resultado real."
    fi

    # Miembros de sudo/wheel: equivalen a root.
    local group
    for group in sudo wheel; do
        if have getent; then
            local members
            members=$(getent group "$group" 2>/dev/null | awk -F: '{ print $4 }')
            if [ -n "$members" ]; then
                sudoers="$sudoers $group:$members"
            fi
        fi
    done
    if [ -n "$sudoers" ]; then
        add_finding "LIN-022" "Info" "Usuarios" \
            "Miembros de grupos administrativos" \
            "Estos usuarios pueden escalar a root:$sudoers. Cada uno es una credencial critica." \
            "Revise 'getent group sudo' y elimine los que no necesiten privilegios."
    fi
}

# ---------------------------------------------------------------- SSH
l10_system_ssh() {
    if [ ! -r /etc/ssh/sshd_config ]; then
        add_finding "LIN-NV-SSH" "Info" "Acceso remoto" \
            "Sin servidor SSH" \
            "No existe /etc/ssh/sshd_config: este equipo no acepta conexiones SSH entrantes." \
            "Ninguna."
        return 0
    fi

    local root_login pass_auth x11 port proto
    root_login=$(ssh_effective "permitrootlogin")
    pass_auth=$(ssh_effective "passwordauthentication")
    x11=$(ssh_effective "x11forwarding")
    port=$(ssh_effective "port")
    proto=$(ssh_effective "protocol")

    metric "ssh_permitrootlogin" "${root_login:-desconocido}"
    metric "ssh_passwordauthentication" "${pass_auth:-desconocido}"
    metric "ssh_port" "${port:-22}"

    case "$root_login" in
        yes)
            add_finding "LIN-030" "High" "Acceso remoto" \
                "SSH permite acceso directo de root" \
                "PermitRootLogin=$root_login. Un atacante puede atacar la cuenta mas privilegiada por fuerza bruta, sin dejar rastro de un usuario intermedio." \
                "Edite /etc/ssh/sshd_config: PermitRootLogin prohibit-password ; systemctl reload sshd" \
                "ssh-effective.txt"
            ;;
        without-password|prohibit-password|forced-commands-only|no)
            add_finding "LIN-OK-ROOT" "Info" "Acceso remoto" \
                "SSH no permite root con contrasena" \
                "PermitRootLogin=$root_login." \
                "Ninguna."
            ;;
        *)
            add_finding "LIN-NV-ROOT" "Info" "Acceso remoto" \
                "PermitRootLogin no verificable" \
                "No se pudo leer el valor efectivo de PermitRootLogin (sin root o sin sshd)." \
                "Ejecute la auditoria con sudo."
            ;;
    esac

    case "$pass_auth" in
        yes)
            add_finding "LIN-031" "Medium" "Acceso remoto" \
                "SSH acepta autenticacion por contrasena" \
                "PasswordAuthentication=yes. Habilita ataques de fuerza bruta y reutilizacion de credenciales; con claves no hace falta." \
                "PasswordAuthentication no ; PubkeyAuthentication yes ; systemctl reload sshd"
            ;;
        no)
            add_finding "LIN-OK-PASSAUTH" "Info" "Acceso remoto" \
                "SSH solo con claves" \
                "PasswordAuthentication=no." \
                "Ninguna."
            ;;
        *)
            # Sin valor efectivo no se puede concluir nada: ni OK ni hallazgo.
            add_finding "LIN-NV-PASSAUTH" "Info" "Acceso remoto" \
                "PasswordAuthentication no verificable" \
                "No se pudo leer el valor efectivo de PasswordAuthentication (sin root o sin sshd). No se asume conformidad." \
                "Ejecute la auditoria con sudo para leer 'sshd -T'."
            ;;
    esac

    case "$x11" in
        yes)
            add_finding "LIN-032" "Low" "Acceso remoto" \
                "X11Forwarding habilitado" \
                "X11Forwarding=yes: reenvia el servidor X por el canal SSH y amplia la superficie de ataque." \
                "X11Forwarding no ; systemctl reload sshd"
            ;;
    esac

    case "$proto" in
        1)
            add_finding "LIN-033" "Critical" "Acceso remoto" \
                "SSH protocolo 1 habilitado" \
                "Protocol=1. El protocolo 1 esta roto criptograficamente desde 2001." \
                "Elimine la directiva Protocol o fije Protocol 2."
            ;;
    esac

    # Permisos de las claves autorizadas.
    local ak perms bad=""
    for ak in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
        [ -f "$ak" ] || continue
        perms=$(stat -c '%a' "$ak" 2>/dev/null)
        [ -n "$perms" ] || continue
        case "$perms" in
            600|640) ;;
            *) bad="$bad $ak($perms)" ;;
        esac
    done
    if [ -n "$bad" ]; then
        add_finding "LIN-034" "Medium" "Acceso remoto" \
            "Permisos laxos en authorized_keys" \
            "Archivos con permisos distintos de 600/640:$bad. sshd puede rechazarlos, y si los acepta, otro usuario local podria leer las claves." \
            "chmod 600 <archivo> && chown <usuario>:<usuario> <archivo>"
    fi
}

# ---------------------------------------------------------------- kernel
l10_system_kernel() {
    local aslr ipfwd rpf kptr dmesg suiddump

    aslr=$(sysctl_get "kernel.randomize_va_space")
    ipfwd=$(sysctl_get "net.ipv4.ip_forward")
    rpf=$(sysctl_get "net.ipv4.conf.all.rp_filter")
    kptr=$(sysctl_get "kernel.kptr_restrict")
    dmesg=$(sysctl_get "kernel.dmesg_restrict")
    suiddump=$(sysctl_get "fs.suid_dumpable")

    metric "aslr" "${aslr:-desconocido}"
    metric "ip_forward" "${ipfwd:-desconocido}"

    if [ -n "$aslr" ] && [ "$aslr" != "2" ]; then
        add_finding "LIN-040" "Medium" "Sistema" \
            "ASLR no esta en modo completo" \
            "kernel.randomize_va_space=$aslr (recomendado 2). Facilita tecnicas de explotacion con direcciones predecibles." \
            "sysctl -w kernel.randomize_va_space=2 y fije el valor en /etc/sysctl.d/99-hardening.conf"
    elif [ -n "$aslr" ]; then
        add_finding "LIN-OK-ASLR" "Info" "Sistema" \
            "ASLR activo" \
            "kernel.randomize_va_space=$aslr." \
            "Ninguna."
    fi

    if [ "$ipfwd" = "1" ]; then
        add_finding "LIN-041" "Low" "Red" \
            "Reenvio de paquetes IPv4 habilitado" \
            "net.ipv4.ip_forward=1. Un equipo que no es router no deberia reenviar trafico: permite usarlo como pivote." \
            "sysctl -w net.ipv4.ip_forward=0 si el equipo no enruta (contenedores y VPN lo necesitan)."
    fi

    if [ -n "$rpf" ] && [ "$rpf" != "1" ]; then
        add_finding "LIN-042" "Low" "Red" \
            "Filtro de ruta inversa desactivado" \
            "net.ipv4.conf.all.rp_filter=$rpf. Sin rp_filter se aceptan paquetes con origen falsificado." \
            "sysctl -w net.ipv4.conf.all.rp_filter=1"
    fi

    if [ "$kptr" = "0" ]; then
        add_finding "LIN-043" "Low" "Sistema" \
            "Direcciones del kernel visibles" \
            "kernel.kptr_restrict=0. Cualquier usuario local puede leer direcciones del kernel y derrotar ASLR." \
            "sysctl -w kernel.kptr_restrict=1"
    fi

    if [ "$dmesg" = "0" ]; then
        add_finding "LIN-044" "Low" "Sistema" \
            "Registro del kernel legible por cualquier usuario" \
            "kernel.dmesg_restrict=0. El buffer de dmesg filtra direcciones y detalles de hardware utiles para explotar." \
            "sysctl -w kernel.dmesg_restrict=1"
    fi

    if [ "$suiddump" = "2" ] || [ "$suiddump" = "1" ]; then
        add_finding "LIN-045" "Low" "Sistema" \
            "Volcados de memoria de procesos privilegiados" \
            "fs.suid_dumpable=$suiddump. Un core dump de un binario SUID puede contener credenciales en claro." \
            "sysctl -w fs.suid_dumpable=0"
    fi
}

# ---------------------------------------------------------------- permisos
l10_system_perms() {
    local mode

    if [ -e /etc/shadow ]; then
        mode=$(stat -c '%a' /etc/shadow 2>/dev/null)
        metric "etc_shadow_mode" "${mode:-desconocido}"
        if [ -z "$mode" ]; then
            # stat vacio = no se pudo leer el modo, no un modo incorrecto.
            add_finding "LIN-NV-SHADOWMODE" "Info" "Permisos" \
                "Permisos de /etc/shadow no verificables" \
                "stat no devolvio el modo de /etc/shadow (sin permiso o stat no compatible). No se asume conformidad." \
                "Ejecute 'stat -c %a /etc/shadow' con sudo."
        else
        case "$mode" in
            600|640|000|6000) ;;
            *)
                add_finding "LIN-050" "High" "Permisos" \
                    "Permisos incorrectos en /etc/shadow" \
                    "/etc/shadow tiene modo $mode (esperado 640 o 600). Los hashes de contrasena quedan expuestos a lectura local." \
                    "chmod 640 /etc/shadow && chown root:shadow /etc/shadow"
                ;;
        esac
        fi
    fi

    if [ -e /etc/passwd ]; then
        mode=$(stat -c '%a' /etc/passwd 2>/dev/null)
        if [ -n "$mode" ]; then
        case "$mode" in
            644) ;;
            *)
                add_finding "LIN-051" "Medium" "Permisos" \
                    "Permisos incorrectos en /etc/passwd" \
                    "/etc/passwd tiene modo $mode (esperado 644)." \
                    "chmod 644 /etc/passwd"
                ;;
        esac
        fi
    fi

    # Claves privadas legibles por otros usuarios.
    local k bad=""
    for k in /root/.ssh/id_* /home/*/.ssh/id_*; do
        [ -f "$k" ] || continue
        case "$k" in
            *.pub) continue ;;
        esac
        mode=$(stat -c '%a' "$k" 2>/dev/null)
        [ -n "$mode" ] || continue
        case "$mode" in
            600|400|640) ;;
            *) bad="$bad $k($mode)" ;;
        esac
    done
    if [ -n "$bad" ]; then
        add_finding "LIN-054" "High" "Permisos" \
            "Claves SSH privadas con permisos laxos" \
            "Claves legibles por terceros:$bad. Cualquier usuario local puede suplantar al propietario." \
            "chmod 600 <clave>; si estuvo expuesta, genere un par nuevo y retire la clave publica del servidor."
    fi

    # Directorios escribibles por todos dentro de /etc.
    local ww
    ww=$(tmo 10 find /etc -maxdepth 2 -type d -perm -0002 2>/dev/null | head -n 10)
    if [ -n "$ww" ]; then
        add_finding "LIN-052" "Medium" "Permisos" \
            "Directorios escribibles por todos en /etc" \
            "Cualquier usuario puede crear archivos en: $(printf '%s' "$ww" | tr '\n' ' ')" \
            "chmod o-w <directorio> tras confirmar que ningun servicio lo necesita."
    fi
}

# ---------------------------------------------------------------- actualizaciones
l10_system_updates() {
    local pending="" tool=""

    # La salida de apt se guarda en archivo para poder distinguir "cero
    # paquetes pendientes" de "apt-get fallo". Con una tuberia a grep -c ambos
    # casos dan 0 y el informe afirmaria que el sistema esta actualizado.
    if have apt-get; then
        tool="apt"
        local sim="${AUDIT_EVIDENCE_DIR:-/tmp}/apt-sim.txt"
        if tmo 30 apt-get -s -o Debug::NoLocking=true upgrade > "$sim" 2>/dev/null; then
            pending=$(grep -c '^Inst ' "$sim" 2>/dev/null)
        else
            pending=""
        fi
        rm -f "$sim" 2>/dev/null
    fi
    if [ -z "$pending" ]; then
        if have dnf; then
            tool="dnf"
            local out="${AUDIT_EVIDENCE_DIR:-/tmp}/dnf-sim.txt" drc
            tmo 30 dnf -q check-update > "$out" 2>/dev/null
            drc=$?
            # dnf devuelve 100 cuando hay actualizaciones y 0 cuando no hay
            # ninguna; cualquier otro codigo es un fallo de la consulta.
            if [ "$drc" -eq 0 ] || [ "$drc" -eq 100 ]; then
                pending=$(grep -c '^[a-zA-Z0-9]' "$out" 2>/dev/null)
            fi
            rm -f "$out" 2>/dev/null
        elif have yum; then
            tool="yum"
            local outy="${AUDIT_EVIDENCE_DIR:-/tmp}/yum-sim.txt" yrc
            tmo 30 yum -q check-update > "$outy" 2>/dev/null
            yrc=$?
            if [ "$yrc" -eq 0 ] || [ "$yrc" -eq 100 ]; then
                pending=$(grep -c '^[a-zA-Z0-9]' "$outy" 2>/dev/null)
            fi
            rm -f "$outy" 2>/dev/null
        fi
    fi

    if [ -z "$pending" ]; then
        add_finding "LIN-NV-UPD" "Info" "Sistema" \
            "Actualizaciones no verificables" \
            "No se encontro un gestor de paquetes compatible (apt/dnf/yum) o fallo la consulta." \
            "Compruebe 'apt list --upgradable' manualmente."
        return 0
    fi

    metric "pending_updates" "$pending"
    if [ "$pending" -gt 0 ]; then
        local sev="Medium"
        [ "$pending" -gt 50 ] && sev="High"
        add_finding "LIN-060" "$sev" "Sistema" \
            "Actualizaciones pendientes" \
            "$pending paquete(s) por actualizar segun $tool. Los parches de seguridad conocidos son el vector de entrada mas usado." \
            "sudo apt update && sudo apt upgrade  (o el equivalente de $tool)"
    else
        add_finding "LIN-OK-UPD" "Info" "Sistema" \
            "Sistema actualizado" \
            "$tool no reporta paquetes pendientes." \
            "Ninguna."
    fi

    # unattended-upgrades aplica parches de seguridad solo.
    local uu="no"
    if have systemctl; then
        uu=$(tmo 5 systemctl is-enabled unattended-upgrades 2>/dev/null)
        [ -n "$uu" ] || uu="no"
    fi
    metric "unattended_upgrades" "$uu"
    if [ "$uu" != "enabled" ] && [ "$tool" = "apt" ]; then
        add_finding "LIN-061" "Low" "Sistema" \
            "Actualizaciones automaticas desactivadas" \
            "unattended-upgrades no esta habilitado: los parches de seguridad dependen de que alguien los aplique a mano." \
            "sudo dpkg-reconfigure -plow unattended-upgrades"
    fi
}

# ---------------------------------------------------------------- defensas
l10_system_defenses() {
    # Firewall
    local fw="ninguno"
    if have ufw; then
        local st
        st=$(tmo 5 ufw status 2>/dev/null | head -n 1)
        case "$st" in
            *active*) fw="ufw" ;;
        esac
    fi
    if [ "$fw" = "ninguno" ] && have nft; then
        local rules
        rules=$(tmo 5 nft list ruleset 2>/dev/null | grep -c 'chain')
        [ "$rules" -gt 0 ] && fw="nftables"
    fi
    if [ "$fw" = "ninguno" ] && have iptables; then
        local rules
        rules=$(tmo 5 iptables -S 2>/dev/null | grep -vc '^-P .* ACCEPT$')
        [ "$rules" -gt 0 ] && fw="iptables"
    fi
    metric "firewall" "$fw"
    # l20 y l40 reutilizan esta deteccion para graduar la severidad de los
    # puertos expuestos y para no repetir la consulta.
    AUDIT_FW_MECHANISM="$fw"

    if [ "$fw" = "ninguno" ]; then
        add_finding "LIN-070" "High" "Firewall" \
            "Sin filtrado de red activo" \
            "No se detecto ufw, nftables ni reglas de iptables: todos los servicios en escucha son alcanzables desde la red." \
            "sudo ufw default deny incoming && sudo ufw default allow outgoing && sudo ufw enable"
    else
        add_finding "LIN-OK-FW" "Info" "Firewall" \
            "Filtrado de red activo" \
            "Mecanismo detectado: $fw." \
            "Ninguna."
    fi

    # fail2ban
    local f2b="no"
    have systemctl && f2b=$(tmo 5 systemctl is-active fail2ban 2>/dev/null)
    [ -n "$f2b" ] || f2b="no"
    metric "fail2ban" "$f2b"
    if [ "$f2b" != "active" ]; then
        add_finding "LIN-071" "Low" "Defensa" \
            "fail2ban inactivo" \
            "sin fail2ban no hay bloqueo automatico tras intentos fallidos de SSH o servicios web." \
            "sudo apt install fail2ban && sudo systemctl enable --now fail2ban"
    fi

    # auditd
    local ad="no"
    have systemctl && ad=$(tmo 5 systemctl is-active auditd 2>/dev/null)
    [ -n "$ad" ] || ad="no"
    metric "auditd" "$ad"
    if [ "$ad" != "active" ]; then
        add_finding "LIN-072" "Low" "Defensa" \
            "auditd inactivo" \
            "Sin auditd no queda registro de execve ni de cambios en archivos criticos." \
            "sudo apt install auditd && sudo systemctl enable --now auditd"
    fi

    # SELinux / AppArmor
    local mac="ninguno"
    if have getenforce; then
        mac="selinux:$(getenforce 2>/dev/null)"
    elif [ -d /sys/kernel/security/apparmor ]; then
        mac="apparmor"
        if have aa-status; then
            local n
            n=$(tmo 5 aa-status 2>/dev/null | awk '/profiles are in enforce mode/ { print $1; exit }')
            [ -n "$n" ] && mac="apparmor:$n perfiles"
        fi
    fi
    metric "mac_framework" "$mac"
    case "$mac" in
        selinux:Enforcing|apparmor*) ;;
        selinux:Permissive)
            add_finding "LIN-073" "Medium" "Defensa" \
                "SELinux en modo permisivo" \
                "SELinux esta en Permissive: registra violaciones pero no las bloquea." \
                "setenforce 1 y SELINUX=enforcing en /etc/selinux/config"
            ;;
        *)
            add_finding "LIN-073" "Medium" "Defensa" \
                "Sin control de acceso obligatorio" \
                "No se detecto SELinux ni AppArmor activos. Un fallo en un servicio queda contenido solo por los permisos UNIX." \
                "Habilite AppArmor (Ubuntu/Debian) o SELinux (RHEL/Fedora)."
            ;;
    esac

    # Grupo docker == root.
    if have getent; then
        local dmembers
        dmembers=$(getent group docker 2>/dev/null | awk -F: '{ print $4 }')
        if [ -n "$dmembers" ]; then
            add_finding "LIN-074" "Medium" "Permisos" \
                "Miembros del grupo docker" \
                "El grupo docker equivale a root: '$dmembers' puede montar el sistema de archivos del host en un contenedor." \
                "Elimine usuarios del grupo docker o use rootless docker / podman."
        fi
    fi
}

# ---------------------------------------------------------------- SUID
l10_system_suid() {
    local list unusual="" count=0 raw rc

    # -xdev evita cruzar sistemas de archivos montados; se poda /proc y /sys.
    # El resultado se guarda en disco para poder distinguir "no hay binarios"
    # de "el inventario se corto": un find truncado no es un equipo limpio.
    raw="${AUDIT_EVIDENCE_DIR:-/tmp}/suid.txt"
    tmo 20 find / -xdev \
        \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o \
        -type f -perm -4000 -print > "$raw" 2>/dev/null
    rc=$?

    if [ "$rc" -eq 124 ]; then
        add_finding "LIN-NV-SUID" "Info" "Permisos" \
            "Inventario SUID truncado por tiempo" \
            "El recorrido del sistema de archivos supero los 20 s y se interrumpio. No se puede afirmar que no existan binarios SUID inesperados." \
            "Repita la auditoria en un equipo con el disco mas rapido, o ejecute 'find / -xdev -type f -perm -4000' manualmente." \
            "suid.txt"
        SUID_COUNT=""
        SUID_UNUSUAL_COUNT=""
        return 0
    fi

    list=$(< "$raw")
    count=$(printf '%s\n' "$list" | grep -c .)
    metric "suid_binaries" "$count"

    local known="/usr/bin/sudo /usr/bin/su /usr/bin/passwd /usr/bin/newgrp /usr/bin/gpasswd /usr/bin/chsh /usr/bin/chfn /usr/bin/mount /usr/bin/umount /usr/bin/fusermount /usr/bin/fusermount3 /bin/su /bin/mount /bin/umount /bin/ping /usr/bin/ping /bin/ping6 /usr/lib/openssh/ssh-keysign /usr/lib/dbus-1.0/dbus-daemon-launch-helper /usr/lib/eject/dmcrypt-get-device /usr/lib/policykit-1/polkit-agent-helper-1 /usr/libexec/polkit-agent-helper-1 /usr/bin/pkexec"

    local f
    for f in $list; do
        case " $known " in
            *" $f "*) ;;
            *) unusual="$unusual $f" ;;
        esac
    done

    # l40 reutiliza el conteo para el control HL-09 sin repetir el find.
    SUID_COUNT="$count"
    SUID_UNUSUAL_COUNT=$(printf '%s' "$unusual" | wc -w | tr -d ' ')

    if [ -n "$unusual" ]; then
        add_finding "LIN-080" "Medium" "Permisos" \
            "Binarios SUID fuera de lo habitual" \
            "Ejecutables con bit SUID que no forman parte del conjunto estandar de la distribucion:$unusual. Un SUID inesperado suele ser una escalada de privilegios." \
            "Identifique el paquete con 'dpkg -S <ruta>' (o 'rpm -qf'); si no pertenece a ninguno, retirese el bit con chmod u-s." \
            "suid.txt"
    else
        add_finding "LIN-OK-SUID" "Info" "Permisos" \
            "Binarios SUID sin sorpresas" \
            "$count binario(s) SUID, todos dentro del conjunto conocido." \
            "Ninguna." \
            "suid.txt"
    fi
}

# ---------------------------------------------------------------- entrada
module_l10_system() {
    section "Sistema y usuarios"
    run_check "LIN-OS"      l10_system_os
    run_check "LIN-Users"   l10_system_users
    run_check "LIN-SSH"     l10_system_ssh
    run_check "LIN-Kernel"  l10_system_kernel
    run_check "LIN-Perms"   l10_system_perms
    run_check "LIN-Updates" l10_system_updates
    run_check "LIN-Defense" l10_system_defenses
    run_check "LIN-SUID"    l10_system_suid
    ok "Sistema: revision completada"
}
