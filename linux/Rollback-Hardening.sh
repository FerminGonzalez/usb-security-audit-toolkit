#!/usr/bin/env bash
# USB Security Audit Toolkit - reversion del hardening Linux
#
#   Rollback-Hardening.sh [--data ARCHIVO] [--what-if] [--yes]
#
# Lee el archivo de rollback que dejo l40-hardening.sh con --apply y devuelve
# el equipo a su estado anterior.
#
# PRINCIPIO DE SEGURIDAD: este archivo no interpreta ni ejecuta nada que venga
# del archivo de datos. El campo 'revert' se compara contra una lista blanca
# con un case, y los argumentos son valores que se pasan a funciones de este
# mismo archivo. Un TSV manipulado solo puede pedir un control inexistente,
# que se omite, o pasar un valor raro a una funcion conocida.
#
# ASCII puro.

if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    printf '[ERR] Se requiere bash 4 o superior.\n' >&2
    exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

DATA=""
WHATIF=0
ASSUME_YES=0

usage() {
    cat <<'USO'
Rollback del hardening Linux

  Rollback-Hardening.sh [opciones]

Opciones:
  --data ARCHIVO   Archivo rollback-<id>.dat (por defecto: el unico del directorio)
  -n, --what-if    Muestra lo que haria sin modificar nada
  -y, --yes        No pide confirmacion
  -h, --help       Esta ayuda
USO
}

while [ $# -gt 0 ]; do
    case "$1" in
        --data)
            [ $# -ge 2 ] || { printf '[ERR] --data requiere un valor\n' >&2; exit 1; }
            DATA=$2; shift 2 ;;
        --data=*) DATA=${1#*=}; shift ;;
        -n|--what-if) WHATIF=1; shift ;;
        -y|--yes) ASSUME_YES=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) printf '[ERR] Opcion desconocida: %s\n' "$1" >&2; exit 1 ;;
    esac
done

if [ -z "$DATA" ]; then
    # Busqueda acotada al directorio del script: nada de recorrer el sistema.
    CANDIDATES=$(find "$SCRIPT_DIR" -maxdepth 1 -name 'rollback-*.dat' -type f 2>/dev/null)
    COUNT=$(printf '%s\n' "$CANDIDATES" | grep -c .)
    if [ "$COUNT" -eq 0 ]; then
        printf '[ERR] No hay ningun rollback-*.dat en %s\n' "$SCRIPT_DIR" >&2
        printf '      Indique el archivo con --data.\n' >&2
        exit 1
    fi
    if [ "$COUNT" -gt 1 ]; then
        printf '[ERR] Hay %s archivos de rollback. Indique cual con --data:\n' "$COUNT" >&2
        printf '%s\n' "$CANDIDATES" | sed 's/^/      /' >&2
        exit 1
    fi
    DATA=$CANDIDATES
fi

if [ ! -f "$DATA" ]; then
    printf '[ERR] No existe el archivo de rollback: %s\n' "$DATA" >&2
    exit 1
fi
if [ ! -s "$DATA" ]; then
    printf 'El archivo de rollback no contiene cambios.\n'
    exit 0
fi

TAB=$(printf '\t')

# --------------------------------------------------------------------- reversiones

rb_log() {
    if [ "$WHATIF" -eq 1 ]; then
        printf '  [WhatIf] %s\n' "$*"
    else
        printf '  %s\n' "$*"
    fi
}

rb_uif_active() {
    command -v ufw >/dev/null 2>&1 || return 1
    ufw status 2>/dev/null | head -n 1 | grep -q 'Status: active'
}

# HL-01: devuelve ufw al estado previo.
rb_ufw() {
    local prev=$1
    case "$prev" in
        inactive)
            if [ "$WHATIF" -eq 1 ]; then
                rb_log 'ufw -> disable'
                return 0
            fi
            ufw --force disable >/dev/null 2>&1
            if rb_uif_active; then
                printf '  ERROR: ufw sigue activo\n' >&2
                return 1
            fi
            ;;
        absent) rb_log 'ufw no estaba instalado; no hay nada que revertir' ;;
        *)      rb_log "estado previo '$prev' sin reversion automatica" ;;
    esac
}

# HL-02/03: retira la directiva del drop-in o restaura el respaldo.
rb_sshopt() {
    local file=$1 opt=$2 _val=$3 backup=$4

    if [ ! -e "$file" ] && { [ -z "$backup" ] || [ ! -f "$backup" ]; }; then
        rb_log "$file ya no existe; nada que revertir"
        return 0
    fi

    if [ "$WHATIF" -eq 1 ]; then
        if [ -n "$backup" ] && [ -f "$backup" ]; then
            rb_log "$file <- $backup"
        else
            rb_log "$file: quitar directiva $opt"
        fi
        return 0
    fi

    if [ -n "$backup" ] && [ -f "$backup" ]; then
        mv -f "$backup" "$file"
    else
        # Solo se elimina la linea de esa directiva; si el archivo queda sin
        # contenido util, se borra para no dejar un drop-in vacio.
        sed -i "/^[[:space:]]*${opt}[[:space:]]/Id" "$file" 2>/dev/null
        if ! grep -qv '^[[:space:]]*\(#.*\)\?$' "$file" 2>/dev/null; then
            rm -f "$file"
        fi
    fi

    # Validar antes de recargar: un sshd_config roto impide las conexiones nuevas.
    if command -v sshd >/dev/null 2>&1; then
        if ! sshd -t >/dev/null 2>&1; then
            printf '  ERROR: sshd -t falla tras revertir %s. No se recarga.\n' "$opt" >&2
            return 1
        fi
    fi
    systemctl reload sshd >/dev/null 2>&1 || systemctl reload ssh >/dev/null 2>&1 || true
}

# HL-04/05: devuelve el modo previo.
rb_perm() {
    local path=$1 mode=$2
    if [ ! -e "$path" ]; then
        rb_log "$path ya no existe; nada que revertir"
        return 0
    fi
    if [ "$WHATIF" -eq 1 ]; then
        rb_log "chmod $mode $path"
        return 0
    fi
    chmod "$mode" "$path" 2>/dev/null
}

# HL-06/07/08/14: devuelve el valor sysctl y limpia la persistencia.
rb_sysctl() {
    local key=$1 val=$2 file=$3 created=$4

    if [ "$WHATIF" -eq 1 ]; then
        rb_log "sysctl $key=$val"
        [ -n "$file" ] && rb_log "persistencia: quitar $file"
        return 0
    fi

    if command -v sysctl >/dev/null 2>&1; then
        sysctl -w "$key=$val" >/dev/null 2>&1 || \
            printf '  ERROR: no se pudo fijar %s=%s\n' "$key" "$val" >&2
    fi

    if [ -n "$file" ] && [ -e "$file" ]; then
        if [ "$created" = "1" ]; then
            rm -f "$file" 2>/dev/null
        else
            sed -i "/^[[:space:]]*${key//./\\.}[[:space:]]*=/d" "$file" 2>/dev/null
        fi
    fi
}

# HL-11/12/13: devuelve el servicio a su estado previo.
rb_service() {
    local unit=$1 prev=$2

    if ! command -v systemctl >/dev/null 2>&1; then
        rb_log "systemctl no disponible; se omite $unit"
        return 0
    fi

    case "$prev" in
        enabled|enabled-runtime)
            rb_log "$unit ya estaba habilitado; se deja como esta"
            ;;
        *)
            if [ "$WHATIF" -eq 1 ]; then
                rb_log "systemctl disable --now $unit"
                return 0
            fi
            systemctl disable --now "$unit" >/dev/null 2>&1 || true
            ;;
    esac
}

# --------------------------------------------------------------------- ejecucion

TOTAL=$(grep -c . "$DATA")
printf '\n=== ROLLBACK DEL HARDENING ===\n'
if [ "$WHATIF" -eq 1 ]; then
    printf 'MODO SIMULACION: no se modificara nada.\n'
fi
printf 'Archivo: %s\n' "$DATA"
printf 'Entradas a revertir: %s\n' "$TOTAL"

if [ "$WHATIF" -eq 0 ] && [ "$(id -u 2>/dev/null)" -ne 0 ]; then
    printf '[ERR] La reversion requiere root. Ejecute con sudo.\n' >&2
    exit 1
fi

if [ "$WHATIF" -eq 0 ] && [ "$ASSUME_YES" -eq 0 ]; then
    printf '\nSe revertiran los cambios de hardening listados arriba.\n'
    printf 'Confirma la reversion? (s/N) '
    read -r resp
    case "$resp" in
        s|S|si|SI) ;;
        *) printf 'Cancelado. No se modifico nada.\n'; exit 0 ;;
    esac
fi

OK=0
SKIP=0
FAIL=0

while IFS="$TAB" read -r id name revert a1 a2 a3 a4; do
    [ -n "$id" ] || continue
    printf -- '-> Revirtiendo %s (%s)\n' "$id" "$name"

    case "$revert" in
        HL-RevertUfw)     rb_ufw     "$a1" ;;
        HL-RevertSshOpt)  rb_sshopt  "$a1" "$a2" "$a3" "$a4" ;;
        HL-RevertPerm)    rb_perm    "$a1" "$a2" ;;
        HL-RevertSysctl)  rb_sysctl  "$a1" "$a2" "$a3" "$a4" ;;
        HL-RevertService) rb_service "$a1" "$a2" ;;
        '')
            printf '   (sin reversion automatica definida)\n'
            SKIP=$((SKIP + 1))
            continue
            ;;
        *)
            printf '   Reversion desconocida, se omite: %s\n' "$revert"
            SKIP=$((SKIP + 1))
            continue
            ;;
    esac

    if [ $? -eq 0 ]; then
        OK=$((OK + 1))
    else
        printf '   ERROR al revertir %s\n' "$id" >&2
        FAIL=$((FAIL + 1))
    fi
done < "$DATA"

printf '\nRollback completado: %s procesados, %s omitidos, %s con error.\n' "$OK" "$SKIP" "$FAIL"
if [ "$WHATIF" -eq 1 ]; then
    printf 'Simulacion: no se aplico ningun cambio.\n'
else
    printf 'Reinicie el equipo si revirtio controles de LSA o del nucleo.\n'
fi
printf '\n'

[ "$FAIL" -eq 0 ] || exit 1
exit 0
