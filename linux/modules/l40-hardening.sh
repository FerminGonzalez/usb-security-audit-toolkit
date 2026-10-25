#!/usr/bin/env bash
# USB Security Audit Toolkit - modulo l40: hardening Linux
# ASCII puro.
#
# Sin --apply este modulo SOLO diagnostica: lee el estado, lo reporta y no
# escribe una sola linea. Con --apply aplica, vuelve a leer para verificar y
# deja un rollback con el estado previo de cada control.
#
# El rollback no contiene codigo: guarda el nombre de una funcion de reversion
# y sus argumentos. Rollback-Hardening.sh despacha por lista blanca, de modo
# que un archivo manipulado no puede ejecutar nada que no este previsto.
#
# Los controles SSH nunca se aplican sin AUDIT_SSH_CONSENT=1, que el
# orquestador solo activa tras un aviso explicito de riesgo de lockout.

if [ -n "${AUDIT_L40_LOADED:-}" ]; then
    return 0
fi
AUDIT_L40_LOADED=1

SYSCTL_DROPIN_DIR=/etc/sysctl.d
SSH_DROPIN=/etc/ssh/sshd_config.d/99-usb-audit.conf

# ---------------------------------------------------------------- utilidades

hl_read_sysctl() {
    local key=$1
    local path="/proc/sys/${key//.//}"
    if [ -r "$path" ]; then
        tr -d '\n' < "$path"
        return 0
    fi
    have sysctl && sysctl -n "$key" 2>/dev/null
}

# Escribe una linea en el rollback. arg1..arg4 son posicionales y opcionales.
hl_rollback_add() {
    local id=$1 name=$2 revert=$3 a1=${4:-} a2=${5:-} a3=${6:-} a4=${7:-}
    [ -n "${AUDIT_ROLLBACK_TSV:-}" ] || return 0
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(tsv_field "$id")" "$(tsv_field "$name")" "$(tsv_field "$revert")" \
        "$(tsv_field "$a1")" "$(tsv_field "$a2")" "$(tsv_field "$a3")" "$(tsv_field "$a4")" \
        >> "$AUDIT_ROLLBACK_TSV"
}

hl_mark_applied() { list_add "${AUDIT_APPLIED_LIST:-}" "$1"; }
hl_mark_pending() { list_add "${AUDIT_PENDING_LIST:-}" "$1"; }
hl_mark_skipped() { list_add "${AUDIT_SKIPPED_LIST:-}" "$1"; }

hl_is_skipped() {
    local id=$1 f
    for f in ${AUDIT_SKIP_CONTROLS:-}; do
        [ "$f" = "$id" ] && return 0
    done
    return 1
}

# Aplica una clave sysctl de forma reversible. El valor previo se guarda para
# que el rollback devuelva el equipo exactamente a donde estaba.
hl_sysctl_apply() {
    local id=$1 name=$2 key=$3 target=$4 current=$5
    local file="$SYSCTL_DROPIN_DIR/99-usb-audit-$(printf '%s' "$key" | tr '.' '-').conf"

    if [ "${AUDIT_APPLY:-0}" -ne 1 ]; then
        return 1
    fi
    if ! need_root; then
        return 1
    fi
    if ! have sysctl; then
        return 1
    fi

    local created=0
    if [ ! -e "$file" ]; then
        created=1
    fi

    if ! sysctl -w "$key=$target" >/dev/null 2>&1; then
        return 1
    fi
    if [ -d "$SYSCTL_DROPIN_DIR" ] && [ -w "$SYSCTL_DROPIN_DIR" ]; then
        printf '# USB Security Audit Toolkit - control %s\n%s = %s\n' "$id" "$key" "$target" > "$file" 2>/dev/null || true
    fi

    hl_rollback_add "$id" "$name" "HL-RevertSysctl" "$key" "$current" "$file" "$created"
    return 0
}

# Verifica el estado de un servicio systemd.
hl_service_state() {
    local unit=$1
    if ! have systemctl; then
        printf 'unknown'
        return 0
    fi
    if ! systemctl list-unit-files "$unit.service" >/dev/null 2>&1; then
        printf 'absent'
        return 0
    fi
    local en
    en=$(tmo 5 systemctl is-enabled "$unit" 2>/dev/null)
    case "$en" in
        enabled|enabled-runtime) printf 'enabled' ;;
        '')                      printf 'unknown' ;;
        not-found)               printf 'absent' ;;
        *)                       printf '%s' "$en" ;;
    esac
}

hl_service_active() {
    local unit=$1
    have systemctl || { printf 'unknown'; return 0; }
    local st
    st=$(tmo 5 systemctl is-active "$unit" 2>/dev/null)
    [ -n "$st" ] || st="unknown"
    printf '%s' "$st"
}

# Hay servidor SSH atendiendo conexiones? Es la condicion que convierte un
# cambio de firewall en un posible lockout.
hl_ssh_listening() {
    local st unit
    for unit in sshd ssh; do
        st=$(hl_service_active "$unit")
        [ "$st" = "active" ] && return 0
    done
    if have ss; then
        tmo 5 ss -tln 2>/dev/null | awk '{ print $4 }' | grep -qE '(:|\.)22$' && return 0
    fi
    return 1
}

# ---------------------------------------------------------------- HL-01 firewall
hl_hl01() {
    local id="HL-01" name="Filtrado de red activo"
    local prev="absent" now="absent"

    if have ufw; then
        local st
        st=$(tmo 5 ufw status 2>/dev/null | head -n 1)
        case "$st" in
            *"Status: active"*) now="active" ;;
            *"Status: inactive"*) now="inactive" ;;
        esac
    fi
    if [ "$now" = "absent" ] && have nft; then
        local chains
        chains=$(tmo 5 nft list ruleset 2>/dev/null | grep -c 'chain')
        [ "$chains" -gt 0 ] && now="nftables"
    fi

    if [ "$now" = "active" ] || [ "$now" = "nftables" ]; then
        AUDIT_FW_MECHANISM="$now"
        metric "hardening_firewall" "$now"
        add_finding "HRD-L01-OK" "Info" "Hardening" \
            "Filtrado de red activo" \
            "Mecanismo detectado: $now." \
            "Ninguna."
        return 0
    fi

    add_finding "HRD-L01" "High" "Hardening" \
        "$name" \
        "No hay filtrado de red activo: todos los servicios en escucha son alcanzables desde la red." \
        "sudo ufw default deny incoming && sudo ufw default allow outgoing && sudo ufw enable"

    if [ "$now" = "inactive" ] && [ "${AUDIT_APPLY:-0}" -eq 1 ] && need_root; then
        # Activar un firewall con politica de entrada por defecto corta el
        # acceso remoto igual que tocar sshd_config. Si hay SSH atendiendo y no
        # hubo consentimiento explicito, no se aplica.
        if hl_ssh_listening && [ "${AUDIT_SSH_CONSENT:-0}" -ne 1 ]; then
            add_finding "HRD-L01-NOSSH" "Info" "Hardening" \
                "Control omitido por seguridad: $name" \
                "Hay un servidor SSH activo y activar ufw con politica de entrada por defecto podria cortar el acceso remoto. No se aplico sin consentimiento explicito." \
                "Repita con --apply --allow-ssh, o abra el puerto SSH antes de activar el firewall."
            hl_mark_skipped "$id"
            return 0
        fi
        if ufw --force enable >/dev/null 2>&1; then
            local verify
            verify=$(tmo 5 ufw status 2>/dev/null | head -n 1)
            case "$verify" in
                *"Status: active"*)
                    AUDIT_FW_MECHANISM="ufw"
                    hl_rollback_add "$id" "$name" "HL-RevertUfw" "inactive"
                    hl_mark_applied "$id"
                    add_finding "HRD-L01-APPLIED" "Info" "Hardening" \
                        "Aplicado: $name" \
                        "ufw quedo activo y verificado." \
                        "Revertir con Rollback-Hardening.sh"
                    return 0
                    ;;
            esac
        fi
        add_finding "HRD-L01-FAIL" "High" "Hardening" \
            "Aplicado pero NO verificado: $name" \
            "Se intento activar ufw pero la lectura posterior no confirma el estado activo." \
            "Revise 'ufw status' manualmente."
        hl_mark_pending "$id"
        return 0
    fi

    hl_mark_pending "$id"
}

# ---------------------------------------------------------------- HL-02/03 SSH
hl_ssh_apply() {
    local id=$1 name=$2 key=$3 target=$4

    if [ "${AUDIT_SSH_CONSENT:-0}" -ne 1 ]; then
        add_finding "HRD-${id}-NOSSH" "Info" "Hardening" \
            "Control SSH omitido por seguridad: $name" \
            "No se aplico el cambio de SSH porque no hubo consentimiento explicito. Un error en sshd_config puede dejar el equipo sin acceso remoto." \
            "Ejecute con --apply de forma interactiva y confirme el aviso de riesgo de lockout."
        hl_mark_skipped "$id"
        return 0
    fi

    if ! need_root; then
        hl_mark_pending "$id"
        return 0
    fi

    local dir backup=""
    dir=$(dirname "$SSH_DROPIN")
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir" 2>/dev/null || true
    fi

    if [ -e "$SSH_DROPIN" ]; then
        backup="$SSH_DROPIN.usb-bak"
        cp -f "$SSH_DROPIN" "$backup" 2>/dev/null || backup=""
    fi

    {
        printf '# USB Security Audit Toolkit - control %s\n' "$id"
        printf '%s no\n' "$key"
    } > "$SSH_DROPIN" 2>/dev/null || { hl_mark_pending "$id"; return 0; }

    # Valida la sintaxis antes de recargar: un sshd_config invalido al recargar
    # mantiene la sesion actual pero impide las siguientes.
    if have sshd; then
        if ! sshd -t >/dev/null 2>&1; then
            rm -f "$SSH_DROPIN" 2>/dev/null
            [ -n "$backup" ] && mv -f "$backup" "$SSH_DROPIN" 2>/dev/null
            add_finding "HRD-${id}-BADCFG" "High" "Hardening" \
                "Configuracion SSH rechazada por sshd: $name" \
                "sshd -t rechazo el drop-in generado, asi que se elimino y no se recargo nada. El acceso remoto queda intacto." \
                "Revise la directiva $key manualmente."
            hl_mark_pending "$id"
            return 0
        fi
    fi

    tmo 10 systemctl reload sshd >/dev/null 2>&1 || tmo 10 systemctl reload ssh >/dev/null 2>&1 || true

    local verify
    verify=$(ssh_effective "$key")
    case "$verify" in
        no|prohibit-password|without-password|forced-commands-only)
            hl_rollback_add "$id" "$name" "HL-RevertSshOpt" "$SSH_DROPIN" "$key" "$target" "$backup"
            hl_mark_applied "$id"
            add_finding "HRD-${id}-APPLIED" "Info" "Hardening" \
                "Aplicado: $name" \
                "$key quedo en 'no' y sshd lo confirma tras la recarga." \
                "Revertir con Rollback-Hardening.sh"
            ;;
        *)
            hl_rollback_add "$id" "$name" "HL-RevertSshOpt" "$SSH_DROPIN" "$key" "$target" "$backup"
            add_finding "HRD-${id}-FAIL" "High" "Hardening" \
                "Aplicado pero NO verificado: $name" \
                "El drop-in se escribio pero 'sshd -T' sigue reportando ${key}=${verify:-desconocido}. Puede haber una directiva de mayor precedencia." \
                "Revise el orden de Include en /etc/ssh/sshd_config."
            hl_mark_pending "$id"
            ;;
    esac
}

hl_hl02() {
    local id="HL-02" name="SSH no permite root"
    if [ ! -r /etc/ssh/sshd_config ]; then
        hl_mark_skipped "$id"
        return 0
    fi
    local v
    v=$(ssh_effective "permitrootlogin")
    case "$v" in
        no|prohibit-password|without-password|forced-commands-only)
            add_finding "HRD-L02-OK" "Info" "Hardening" \
                "SSH restringe el acceso de root" \
                "PermitRootLogin=$v." \
                "Ninguna."
            ;;
        yes)
            add_finding "HRD-L02" "High" "Hardening" \
                "$name" \
                "PermitRootLogin=yes. La cuenta mas privilegiada es atacable por fuerza bruta desde Internet." \
                "PermitRootLogin prohibit-password en /etc/ssh/sshd_config.d/"
            if [ "${AUDIT_APPLY:-0}" -eq 1 ]; then
                hl_ssh_apply "$id" "$name" "PermitRootLogin" "prohibit-password"
            else
                hl_mark_pending "$id"
            fi
            ;;
        *)
            add_finding "HRD-L02-NV" "Info" "Hardening" \
                "PermitRootLogin no verificable" \
                "Sin root o sin sshd no se puede leer el valor efectivo; no se asume conformidad." \
                "Ejecute con sudo."
            ;;
    esac
}

hl_hl03() {
    local id="HL-03" name="SSH no acepta contrasenas"
    if [ ! -r /etc/ssh/sshd_config ]; then
        hl_mark_skipped "$id"
        return 0
    fi
    local v
    v=$(ssh_effective "passwordauthentication")
    case "$v" in
        no)
            add_finding "HRD-L03-OK" "Info" "Hardening" \
                "SSH solo admite claves" \
                "PasswordAuthentication=no." \
                "Ninguna."
            ;;
        yes)
            add_finding "HRD-L03" "Medium" "Hardening" \
                "$name" \
                "PasswordAuthentication=yes. Habilita fuerza bruta y reutilizacion de credenciales." \
                "PasswordAuthentication no + PubkeyAuthentication yes"
            if [ "${AUDIT_APPLY:-0}" -eq 1 ]; then
                hl_ssh_apply "$id" "$name" "PasswordAuthentication" "no"
            else
                hl_mark_pending "$id"
            fi
            ;;
        *)
            add_finding "HRD-L03-NV" "Info" "Hardening" \
                "PasswordAuthentication no verificable" \
                "Sin root o sin sshd no se puede leer el valor efectivo." \
                "Ejecute con sudo."
            ;;
    esac
}

# ---------------------------------------------------------------- HL-04/05 permisos
hl_perm_apply() {
    local id=$1 name=$2 path=$3 mode=$4 current=$5

    if [ "${AUDIT_APPLY:-0}" -ne 1 ] || ! need_root; then
        hl_mark_pending "$id"
        return 0
    fi
    if ! chmod "$mode" "$path" 2>/dev/null; then
        hl_mark_pending "$id"
        return 0
    fi
    local verify
    verify=$(stat -c '%a' "$path" 2>/dev/null)
    if [ "$verify" = "$mode" ]; then
        hl_rollback_add "$id" "$name" "HL-RevertPerm" "$path" "$current"
        hl_mark_applied "$id"
        add_finding "HRD-${id}-APPLIED" "Info" "Hardening" \
            "Aplicado: $name" \
            "$path quedo en modo $mode." \
            "Revertir con Rollback-Hardening.sh"
    else
        add_finding "HRD-${id}-FAIL" "High" "Hardening" \
            "Aplicado pero NO verificado: $name" \
            "chmod no dejo $path en modo $mode (leido: ${verify:-desconocido})." \
            "Revise atributos inmutables con 'lsattr'."
        hl_mark_pending "$id"
    fi
}

hl_hl04() {
    local id="HL-04" name="Permisos de /etc/shadow"
    [ -e /etc/shadow ] || { hl_mark_skipped "$id"; return 0; }
    local mode
    mode=$(stat -c '%a' /etc/shadow 2>/dev/null)
    if [ -z "$mode" ]; then
        add_finding "HRD-L04-NV" "Info" "Hardening" \
            "$name no verificable" \
            "stat no devolvio el modo de /etc/shadow. Sin dato no hay veredicto." \
            "Ejecute con sudo o compruebe que 'stat -c' este disponible."
        hl_mark_skipped "$id"
        return 0
    fi
    case "$mode" in
        600|640|000)
            add_finding "HRD-L04-OK" "Info" "Hardening" \
                "Permisos correctos en /etc/shadow" \
                "Modo actual: $mode." \
                "Ninguna."
            ;;
        *)
            add_finding "HRD-L04" "High" "Hardening" \
                "$name" \
                "/etc/shadow tiene modo $mode; los hashes son legibles por usuarios que no deberian verlos." \
                "chmod 640 /etc/shadow && chown root:shadow /etc/shadow"
            hl_perm_apply "$id" "$name" "/etc/shadow" "640" "$mode"
            ;;
    esac
}

hl_hl05() {
    local id="HL-05" name="Permisos de ~/.ssh"
    local bad="" path mode target count=0

    for path in /root/.ssh /home/*/.ssh; do
        [ -d "$path" ] || continue
        mode=$(stat -c '%a' "$path" 2>/dev/null)
        [ -n "$mode" ] || continue
        case "$mode" in
            700|750) ;;
            *) bad="$bad $path($mode)" ;;
        esac
        local f
        for f in "$path"/authorized_keys "$path"/id_* "$path"/config "$path"/known_hosts; do
            [ -f "$f" ] || continue
            case "$f" in *.pub) continue ;; esac
            mode=$(stat -c '%a' "$f" 2>/dev/null)
            [ -n "$mode" ] || continue
            case "$mode" in
                600|400|640) ;;
                *) bad="$bad $f($mode)" ;;
            esac
        done
    done

    if [ -z "$bad" ]; then
        add_finding "HRD-L05-OK" "Info" "Hardening" \
            "Permisos de ~/.ssh correctos" \
            "Directorios en 700 y claves en 600/400." \
            "Ninguna."
        return 0
    fi

    add_finding "HRD-L05" "High" "Hardening" \
        "$name" \
        "Rutas con permisos laxos:$bad. Una clave privada legible por otro usuario local permite suplantar la identidad." \
        "chmod 700 <dir> && chmod 600 <archivo>"

    if [ "${AUDIT_APPLY:-0}" -eq 1 ] && need_root; then
        # Se corrige cada ruta con su propio registro de rollback.
        local entry
        for entry in $bad; do
            path=${entry%%(*}
            mode=$(printf '%s' "$entry" | sed -n 's/.*(\(.*\))/\1/p')
            if [ -d "$path" ]; then
                target=700
            else
                target=600
            fi
            hl_perm_apply "$id" "$name: $path" "$path" "$target" "$mode"
            count=$((count + 1))
        done
    else
        hl_mark_pending "$id"
    fi
}

# ---------------------------------------------------------------- HL-06/07/08/14 sysctl
hl_sysctl_control() {
    local id=$1 name=$2 key=$3 want=$4 severity=$5
    local current
    current=$(hl_read_sysctl "$key")

    if [ -z "$current" ]; then
        add_finding "HRD-${id}-NV" "Info" "Hardening" \
            "$name no verificable" \
            "No se pudo leer $key; no se asume conformidad." \
            "Compruebe que /proc/sys esta montado."
        return 0
    fi

    if [ "$current" = "$want" ]; then
        add_finding "HRD-${id}-OK" "Info" "Hardening" \
            "$name" \
            "$key=$current, ya conforme." \
            "Ninguna."
        return 0
    fi

    add_finding "HRD-$id" "$severity" "Hardening" \
        "$name" \
        "$key=$current (esperado $want)." \
        "sysctl -w $key=$want y fije el valor en /etc/sysctl.d/"

    if hl_sysctl_apply "$id" "$name" "$key" "$want" "$current"; then
        local verify
        verify=$(hl_read_sysctl "$key")
        if [ "$verify" = "$want" ]; then
            hl_mark_applied "$id"
            add_finding "HRD-${id}-APPLIED" "Info" "Hardening" \
                "Aplicado: $name" \
                "$key=$verify, verificado y persistido." \
                "Revertir con Rollback-Hardening.sh"
            return 0
        fi
        add_finding "HRD-${id}-FAIL" "High" "Hardening" \
            "Aplicado pero NO verificado: $name" \
            "sysctl -w acepto la orden pero la lectura posterior es ${verify:-vacia}." \
            "Puede estar fijado por otro archivo de /etc/sysctl.d con nombre posterior."
    fi
    hl_mark_pending "$id"
}

# ---------------------------------------------------------------- HL-11/12/13 servicios
hl_service_control() {
    local id=$1 name=$2 unit=$3 severity=$4
    local state active
    state=$(hl_service_state "$unit")

    if [ "$state" = "absent" ]; then
        add_finding "HRD-${id}-ABSENT" "Info" "Hardening" \
            "$name no instalado" \
            "No existe la unidad $unit.service. No es un incumplimiento: el componente no esta presente." \
            "Instalelo solo si lo necesita: apt install $unit"
        hl_mark_skipped "$id"
        return 0
    fi
    if [ "$state" = "unknown" ]; then
        add_finding "HRD-${id}-NV" "Info" "Hardening" \
            "$name no verificable" \
            "No se pudo consultar el estado de $unit." \
            "Ejecute con sudo o compruebe que systemd esta activo."
        return 0
    fi

    active=$(hl_service_active "$unit")
    if [ "$state" = "enabled" ] && [ "$active" = "active" ]; then
        add_finding "HRD-${id}-OK" "Info" "Hardening" \
            "$name" \
            "$unit esta habilitado y activo." \
            "Ninguna."
        return 0
    fi

    add_finding "HRD-$id" "$severity" "Hardening" \
        "$name" \
        "$unit: enabled=$state, active=$active." \
        "systemctl enable --now $unit"

    if [ "${AUDIT_APPLY:-0}" -eq 1 ] && need_root; then
        if tmo 30 systemctl enable --now "$unit" >/dev/null 2>&1; then
            local verify
            verify=$(hl_service_active "$unit")
            if [ "$verify" = "active" ]; then
                hl_rollback_add "$id" "$name" "HL-RevertService" "$unit" "$state"
                hl_mark_applied "$id"
                add_finding "HRD-${id}-APPLIED" "Info" "Hardening" \
                    "Aplicado: $name" \
                    "$unit habilitado y activo, verificado." \
                    "Revertir con Rollback-Hardening.sh"
                return 0
            fi
        fi
        add_finding "HRD-${id}-FAIL" "High" "Hardening" \
            "Aplicado pero NO verificado: $name" \
            "systemctl enable --now no dejo $unit activo. Revise 'systemctl status $unit'." \
            "Puede faltar configuracion o el servicio fallar al arrancar."
    fi
    hl_mark_pending "$id"
}

# ---------------------------------------------------------------- report-only
hl_hl09() {
    local id="HL-09" name="Binarios SUID fuera de lo habitual"

    # Un inventario truncado no es un equipo limpio: sin dato, no hay veredicto.
    if [ -z "${SUID_UNUSUAL_COUNT:-}" ]; then
        add_finding "HRD-L09-NV" "Info" "Hardening" \
            "$name no verificable" \
            "l10 no pudo completar el inventario SUID (recorrido truncado o sin permisos). No se asume conformidad." \
            "Ejecute 'find / -xdev -type f -perm -4000' con sudo y revise la lista a mano."
        hl_mark_skipped "$id"
        return 0
    fi

    if [ "$SUID_UNUSUAL_COUNT" -gt 0 ] 2>/dev/null; then
        add_finding "HRD-L09" "Medium" "Hardening" \
            "$name" \
            "$SUID_UNUSUAL_COUNT binario(s) SUID no estandar. Requiere criterio humano: retirar el bit puede romper paquetes legitimos." \
            "Identifique el dueno con 'dpkg -S <ruta>' antes de decidir. Este control NO se aplica automaticamente."
    else
        add_finding "HRD-L09-OK" "Info" "Hardening" \
            "SUID sin sorpresas" \
            "Ningun binario SUID fuera del conjunto conocido." \
            "Ninguna."
    fi
    hl_mark_skipped "$id"
}

hl_hl10() {
    local id="HL-10" name="Miembros del grupo docker"
    local members=""
    have getent && members=$(getent group docker 2>/dev/null | awk -F: '{ print $4 }')
    if [ -n "$members" ]; then
        add_finding "HRD-L10" "Medium" "Hardening" \
            "$name" \
            "$members puede montar el sistema de archivos del host mediante un contenedor. Requiere decision del operador: quitar el grupo rompe su flujo de trabajo." \
            "Use docker rootless o podman. Este control NO se aplica automaticamente."
    else
        add_finding "HRD-L10-OK" "Info" "Hardening" \
            "Grupo docker sin miembros" \
            "Ninguna cuenta pertenece al grupo docker." \
            "Ninguna."
    fi
    hl_mark_skipped "$id"
}

# ---------------------------------------------------------------- entrada
module_l40_hardening() {
    section "Hardening"

    if [ "${AUDIT_APPLY:-0}" -eq 1 ]; then
        if ! need_root; then
            err "Hardening con --apply requiere root. Se ejecuta en modo diagnostico."
            AUDIT_APPLY=0
        else
            warn "MODO APLICAR: se modificara la configuracion del sistema."
        fi
    else
        log "Hardening en modo diagnostico: no se modifica nada."
    fi

    local id
    for id in HL-01 HL-02 HL-03 HL-04 HL-05 HL-06 HL-07 HL-08 HL-09 HL-10 HL-11 HL-12 HL-13 HL-14; do
        if hl_is_skipped "$id"; then
            hl_mark_skipped "$id"
            log "  $id omitido por configuracion"
            continue
        fi
        run_check "HRD-$id" "hl_dispatch_$(printf '%s' "$id" | tr 'A-Z-' 'a-z_')"
    done

    local napp npend nskip
    napp=$(grep -c . "${AUDIT_APPLIED_LIST:-/dev/null}" 2>/dev/null)
    npend=$(grep -c . "${AUDIT_PENDING_LIST:-/dev/null}" 2>/dev/null)
    nskip=$(grep -c . "${AUDIT_SKIPPED_LIST:-/dev/null}" 2>/dev/null)
    metric "hardening_applied" "${napp:-0}"
    metric "hardening_pending" "${npend:-0}"

    ok "Hardening: ${napp:-0} aplicados, ${npend:-0} pendientes, ${nskip:-0} omitidos"
}

# Despacho explicito: run_check recibe el nombre de la funcion, no un ID.
hl_dispatch_hl_01() { hl_hl01; }
hl_dispatch_hl_02() { hl_hl02; }
hl_dispatch_hl_03() { hl_hl03; }
hl_dispatch_hl_04() { hl_hl04; }
hl_dispatch_hl_05() { hl_hl05; }
hl_dispatch_hl_06() { hl_sysctl_control "HL-06" "Reenvio de paquetes IPv4" "net.ipv4.ip_forward" "0" "Low"; }
hl_dispatch_hl_07() { hl_sysctl_control "HL-07" "Filtro de ruta inversa" "net.ipv4.conf.all.rp_filter" "1" "Low"; }
hl_dispatch_hl_08() { hl_sysctl_control "HL-08" "ASLR completo" "kernel.randomize_va_space" "2" "Medium"; }
hl_dispatch_hl_09() { hl_hl09; }
hl_dispatch_hl_10() { hl_hl10; }
hl_dispatch_hl_11() { hl_service_control "HL-11" "fail2ban activo" "fail2ban" "Low"; }
hl_dispatch_hl_12() { hl_service_control "HL-12" "auditd activo" "auditd" "Low"; }
hl_dispatch_hl_13() { hl_service_control "HL-13" "Actualizaciones automaticas" "unattended-upgrades" "Low"; }
hl_dispatch_hl_14() { hl_sysctl_control "HL-14" "Volcados de procesos privilegiados" "fs.suid_dumpable" "0" "Low"; }
