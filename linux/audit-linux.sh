#!/usr/bin/env bash
# USB Security Audit Toolkit - orquestador del motor Linux
#
#   audit-linux.sh [--mode rapido|completo|web] [--apply] [--out DIR]
#                  [--target URL]... [--no-color] [--help]
#
# Genera en el directorio de salida:
#   findings.json    esquema de la seccion 3 del contrato
#   resumen.md       informe en texto
#   informe.html     informe autocontenido
#   rollback-<id>.dat / .json / .sh   solo si se aplico hardening
#
# ASCII puro. Sin dependencias obligatorias mas alla de coreutils y bash 4.

# bash 4 es obligatorio por 'declare -A'. Se comprueba antes de todo lo demas
# para no fallar a mitad de la auditoria con un error incomprensible.
if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    printf '[ERR] Se requiere bash 4 o superior (actual: %s).\n' "${BASH_VERSION:-desconocido}" >&2
    printf '      En macOS: brew install bash y ejecute con /usr/local/bin/bash.\n' >&2
    exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
START_EPOCH=$(date +%s)

# --------------------------------------------------------------------- argumentos
MODE=rapido
APPLY=0
OUT_DIR=""
TARGETS=()
SSH_CONSENT=0
QUIET_COLOR=0

usage() {
    cat <<'USO'
USB Security Audit Toolkit - auditoria Linux

  audit-linux.sh [opciones]

Opciones:
  --mode rapido|completo|web   Alcance de la auditoria (por defecto: rapido)
  --apply                      Aplica el hardening y genera rollback
  --out DIR                    Directorio de salida de la evidencia
  --target URL                 Sitio web a auditar; repetible
  --allow-ssh                  Autoriza aplicar cambios de SSH (riesgo de lockout)
  --no-color                   Sin colores ANSI
  -h, --help                   Esta ayuda

Modos:
  rapido    Sistema, red y hardening en modo diagnostico. Menos de 90 s.
  completo  Lo anterior mas auditoria web, TLS y cookies.
  web       Solo los sitios indicados con --target.

El hardening NUNCA se aplica sin --apply. Los cambios de SSH requieren ademas
--allow-ssh por el riesgo de perder el acceso remoto.

Codigos de salida:
  0  auditoria completada (con o sin hallazgos)
  1  error de uso o entorno
  2  la evidencia se genero pero el JSON no supero la validacion
USO
}

while [ $# -gt 0 ]; do
    case "$1" in
        --mode)
            [ $# -ge 2 ] || { printf '[ERR] --mode requiere un valor\n' >&2; exit 1; }
            MODE=$2; shift 2 ;;
        --mode=*) MODE=${1#*=}; shift ;;
        --apply) APPLY=1; shift ;;
        --out)
            [ $# -ge 2 ] || { printf '[ERR] --out requiere un valor\n' >&2; exit 1; }
            OUT_DIR=$2; shift 2 ;;
        --out=*) OUT_DIR=${1#*=}; shift ;;
        --target)
            [ $# -ge 2 ] || { printf '[ERR] --target requiere un valor\n' >&2; exit 1; }
            TARGETS+=("$2"); shift 2 ;;
        --target=*) TARGETS+=("${1#*=}"); shift ;;
        --allow-ssh) SSH_CONSENT=1; shift ;;
        --no-color) QUIET_COLOR=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *)
            printf '[ERR] Opcion desconocida: %s\n' "$1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

case "$MODE" in
    rapido|completo|web) ;;
    *) printf '[ERR] Modo invalido: %s (use rapido, completo o web)\n' "$MODE" >&2; exit 1 ;;
esac

if [ "$QUIET_COLOR" -eq 1 ]; then
    export NO_COLOR=1
fi

# --------------------------------------------------------------------- librerias
for lib in "$SCRIPT_DIR/lib/common.sh" "$SCRIPT_DIR/lib/report.sh"; do
    if [ ! -f "$lib" ]; then
        printf '[ERR] Falta %s. El toolkit esta incompleto.\n' "$lib" >&2
        exit 1
    fi
    . "$lib"
done

# Los modulos se cargan en orden por nombre, igual que en Windows: ningun
# modulo depende del orden de carga salvo que otro ya haya definido sus
# variables globales (LIN-*), y esos se cargan antes por nombre.
for mod in "$SCRIPT_DIR/modules"/l*.sh; do
    [ -f "$mod" ] || continue
    . "$mod"
done

# --------------------------------------------------------------------- configuracion
CONFIG_FILE=""
for candidate in \
    "$SCRIPT_DIR/config/settings.json" \
    "$SCRIPT_DIR/../config/settings.json" \
    "$SCRIPT_DIR/../engine/config/settings.json"
do
    if [ -f "$candidate" ]; then
        CONFIG_FILE="$candidate"
        break
    fi
done

# Lectura de settings.json. Sin python3 ni jq se usan los valores por defecto:
# el contrato prohibe descargar dependencias, no exigirlas.
cfg_list() {
    local path=$1
    [ -n "$CONFIG_FILE" ] || return 0
    if have python3; then
        python3 - "$CONFIG_FILE" "$path" <<'PY' 2>/dev/null
import json, sys
with open(sys.argv[1], encoding="utf-8") as h:
    data = json.load(h)
node = data
for part in sys.argv[2].split("."):
    if isinstance(node, dict):
        node = node.get(part)
    else:
        node = None
if isinstance(node, list):
    for item in node:
        print(item)
PY
    elif have jq; then
        jq -r --arg p "$path" 'getpath($p | split(".")) // [] | .[]?' "$CONFIG_FILE" 2>/dev/null
    fi
}

cfg_scalar() {
    local path=$1
    [ -n "$CONFIG_FILE" ] || return 0
    if have python3; then
        python3 - "$CONFIG_FILE" "$path" <<'PY' 2>/dev/null
import json, sys
with open(sys.argv[1], encoding="utf-8") as h:
    data = json.load(h)
node = data
for part in sys.argv[2].split("."):
    node = node.get(part) if isinstance(node, dict) else None
if node is not None and not isinstance(node, (list, dict)):
    print(node)
PY
    elif have jq; then
        jq -r --arg p "$path" 'getpath($p | split(".")) // empty' "$CONFIG_FILE" 2>/dev/null
    fi
}

if [ ${#TARGETS[@]} -eq 0 ]; then
    while IFS= read -r t; do
        [ -n "$t" ] && TARGETS+=("$t")
    done <<EOF
$(cfg_list "web.targets")
EOF
fi
AUDIT_WEB_TARGETS=("${TARGETS[@]}")

AUDIT_WEB_TIMEOUT=$(cfg_scalar "web.timeout_s")
[ -n "$AUDIT_WEB_TIMEOUT" ] || AUDIT_WEB_TIMEOUT=15

AUDIT_DNS_TEST_HOST=$(cfg_list "network.dns_test_hosts" | head -n 1)
AUDIT_PING_COUNT=$(cfg_scalar "network.ping_count")
[ -n "$AUDIT_PING_COUNT" ] || AUDIT_PING_COUNT=4

AUDIT_SKIP_CONTROLS=$(cfg_list "hardening.skip_controls" | tr '\n' ' ')

# --------------------------------------------------------------------- contexto
AUDIT_HOST=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || printf 'equipo')
AUDIT_HOST=${AUDIT_HOST%%.*}
STARTED=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
AUDIT_ID="${AUDIT_HOST}-$(date '+%Y%m%d-%H%M%S')"

if [ -z "$OUT_DIR" ]; then
    OUT_DIR="$SCRIPT_DIR/../evidencia/$AUDIT_ID"
fi
mkdir -p "$OUT_DIR" 2>/dev/null
if [ ! -d "$OUT_DIR" ]; then
    printf '[ERR] No se pudo crear el directorio de salida: %s\n' "$OUT_DIR" >&2
    exit 1
fi
AUDIT_EVIDENCE_DIR=$(cd "$OUT_DIR" && pwd)
STARTED=$STARTED

# Temporales dentro del directorio de evidencia: el contrato prohibe escribir
# fuera de EvidenceDir y del RootPath.
TMP="$AUDIT_EVIDENCE_DIR/.tmp"
mkdir -p "$TMP"
rm -f "$TMP"/* 2>/dev/null || true

AUDIT_FINDINGS_NDJSON="$TMP/findings.ndjson"
AUDIT_FINDINGS_TSV="$TMP/findings.tsv"
AUDIT_METRICS_TSV="$TMP/metrics.tsv"
AUDIT_APPLIED_LIST="$TMP/applied.txt"
AUDIT_PENDING_LIST="$TMP/pending.txt"
AUDIT_SKIPPED_LIST="$TMP/skipped.txt"
AUDIT_ROLLBACK_TSV="$TMP/rollback.tsv"
AUDIT_WEB_COUNTS_TSV="$TMP/web-counts.tsv"
AUDIT_WEB_POSTURE_TSV="$TMP/web-posture.tsv"
: > "$AUDIT_FINDINGS_NDJSON"
: > "$AUDIT_FINDINGS_TSV"
: > "$AUDIT_METRICS_TSV"
: > "$AUDIT_APPLIED_LIST"
: > "$AUDIT_PENDING_LIST"
: > "$AUDIT_SKIPPED_LIST"
: > "$AUDIT_ROLLBACK_TSV"
: > "$AUDIT_WEB_COUNTS_TSV"
: > "$AUDIT_WEB_POSTURE_TSV"

AUDIT_APPLY=$APPLY
AUDIT_MODE=$MODE
AUDIT_SSH_CONSENT=$SSH_CONSENT

if need_root; then
    ELEVATED=true
else
    ELEVATED=false
fi

OS_TEXT="Linux"
OS_FAMILY="Linux"

# --------------------------------------------------------------------- cabecera
printf '\n'
printf '  USB Security Audit Toolkit %s\n' "$AUDIT_TOOL_VERSION"
printf '  Equipo : %s\n' "$AUDIT_HOST"
printf '  Modo   : %s%s\n' "$MODE" "$( [ "$APPLY" -eq 1 ] && printf ' (APLICAR)' || printf ' (solo diagnostico)' )"
printf '  Salida : %s\n' "$AUDIT_EVIDENCE_DIR"
if [ "$ELEVATED" = "false" ]; then
    warn "Sin privilegios: /etc/shadow, sshd -T y el hardening quedan limitados."
fi
if [ -n "$CONFIG_FILE" ]; then
    log "Configuracion: $CONFIG_FILE"
else
    log "Sin settings.json: se usan valores por defecto."
    add_finding "PRE-CFG" "Info" "Preflight" \
        "Configuracion por defecto" \
        "No se encontro un settings.json utilizable; se aplicaron los valores por defecto del contrato." \
        "Cree config/settings.json con los objetivos web y los parametros de red."
fi

# --------------------------------------------------------------------- modulos
case "$MODE" in
    rapido)
        module_l10_system
        module_l20_network
        module_l40_hardening
        ;;
    completo)
        module_l10_system
        module_l20_network
        module_l30_web
        module_l40_hardening
        ;;
    web)
        module_l30_web
        ;;
esac

# --------------------------------------------------------------------- rollback
AUDIT_ROLLBACK_FILE=""
if [ -s "$AUDIT_ROLLBACK_TSV" ]; then
    RB_NAME="rollback-$AUDIT_ID"
    RB_DAT="$AUDIT_EVIDENCE_DIR/$RB_NAME.dat"
    RB_JSON="$AUDIT_EVIDENCE_DIR/$RB_NAME.json"
    RB_SH="$AUDIT_EVIDENCE_DIR/$RB_NAME.sh"

    cp -f "$AUDIT_ROLLBACK_TSV" "$RB_DAT"
    chmod 600 "$RB_DAT" 2>/dev/null || true

    # Vista JSON para el informe. Los datos operativos van en el TSV para que
    # el rollback no necesite un parser de JSON.
    {
        printf '[\n'
        awk -F'\t' '
            {
                if (n++) printf ",\n"
                printf "  {\"id\":\"%s\",\"name\":\"%s\",\"revert\":\"%s\",\"args\":[", $1, $2, $3
                m = 0
                for (i = 4; i <= 7; i++) {
                    if (m++) printf ","
                    printf "\"%s\"", $i
                }
                printf "]}"
            }
            END { if (n) printf "\n"; }
        ' "$RB_DAT"
        printf ']\n'
    } > "$RB_JSON" 2>/dev/null

    # Lanzador de dos lineas: no contiene logica. Toda la reversion vive en
    # Rollback-Hardening.sh, que despacha por lista blanca.
    {
        printf '#!/bin/sh\n'
        printf '# Lanzador generado por USB Security Audit Toolkit. No contiene logica.\n'
        printf 'exec "$(dirname "$0")/Rollback-Hardening.sh" --data "$(dirname "$0")/%s.dat" "$@"\n' "$RB_NAME"
    } > "$RB_SH" 2>/dev/null
    chmod 700 "$RB_SH" 2>/dev/null || true

    # En FAT32 (el USB) los permisos no existen: '-x' puede ser falso aunque el
    # archivo se pueda ejecutar con 'bash archivo'. Se comprueba solo contenido.
    if [ -s "$RB_SH" ] && [ -s "$RB_DAT" ]; then
        AUDIT_ROLLBACK_FILE="$RB_NAME.dat"
    fi
fi

# --------------------------------------------------------------------- postura
read -r N_CRIT N_HIGH N_MED N_LOW N_INFO <<EOF
$(severity_counts "$AUDIT_FINDINGS_NDJSON")
EOF

SCORE=$(score_from_counts "$N_CRIT" "$N_HIGH" "$N_MED" "$N_LOW")
GRADE=$(grade_from_score "$SCORE")

read -r HOST_CRIT HOST_HIGH HOST_MED HOST_LOW HOST_INFO <<EOF
$(severity_counts "$AUDIT_FINDINGS_NDJSON" "exclude")
EOF
HOST_SCORE=$(posture_from_counts "$HOST_CRIT" "$HOST_HIGH" "$HOST_MED" "$HOST_LOW")
HOST_GRADE=$(posture_grade_from_counts "$HOST_CRIT" "$HOST_HIGH" "$HOST_MED" "$HOST_LOW")

# En modo web no se audita el equipo: la ausencia de hallazgos de sistema no
# significa 100/100, significa que no se midio. Se marca como no auditado para
# que ni el JSON ni el informe afirmen una conformidad inexistente.
if [ "$MODE" = "web" ]; then
    HOST_AUDITED=0
else
    HOST_AUDITED=1
fi

# Un sitio sin fila en web-counts no se midio: no aparece en la postura.
while IFS="$TAB" read -r wurl wc wh wm wl; do
    [ -n "$wurl" ] || continue
    wscore=$(posture_from_counts "${wc:-0}" "${wh:-0}" "${wm:-0}" "${wl:-0}")
    wgrade=$(posture_grade_from_counts "${wc:-0}" "${wh:-0}" "${wm:-0}" "${wl:-0}")
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$wurl" "$wscore" "$wgrade" "${wc:-0}" "${wh:-0}" "${wm:-0}" "${wl:-0}" \
        >> "$AUDIT_WEB_POSTURE_TSV"
done < "$AUDIT_WEB_COUNTS_TSV"

# Lectura principal del informe: la postura. En modo web el equipo no se
# audita, asi que la lectura principal es la de los sitios (la peor, para no
# esconder el problema detras de una media).
PRIMARY_SCORE="$HOST_SCORE"
PRIMARY_GRADE="$HOST_GRADE"
PRIMARY_LABEL="Este equipo"
if [ "$HOST_AUDITED" -ne 1 ]; then
    PRIMARY_SCORE=""
    PRIMARY_GRADE=""
    PRIMARY_LABEL="Sitios web"
    while IFS="$TAB" read -r _wurl wscore wgrade _wc _wh _wm _wl; do
        [ -n "$_wurl" ] || continue
        if [ -z "$PRIMARY_SCORE" ] || [ "$wscore" -lt "$PRIMARY_SCORE" ]; then
            PRIMARY_SCORE="$wscore"
            PRIMARY_GRADE="$wgrade"
            PRIMARY_LABEL="Peor sitio auditado"
        fi
    done < "$AUDIT_WEB_POSTURE_TSV"
    # Sin sitios medidos no hay postura que mostrar: se declara, no se inventa.
    [ -n "$PRIMARY_SCORE" ] || { PRIMARY_SCORE="0"; PRIMARY_GRADE="?"; PRIMARY_LABEL="Sin medicion"; }
fi

# --------------------------------------------------------------------- findings.json
FINISHED=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
DURATION=$(( $(date +%s) - START_EPOCH ))

findings_json=$(awk '
    BEGIN { printf "[" }
    { if (n++) printf ","; printf "%s", $0 }
    END { printf "]" }
' "$AUDIT_FINDINGS_NDJSON")

metrics_json=$(awk -F'\t' '
    { if (!($1 in seen)) { order[++n] = $1; seen[$1] = 1 } last[$1] = $2 }
    END {
        printf "{"
        for (i = 1; i <= n; i++) {
            if (i > 1) printf ","
            printf "\"%s\":%s", order[i], last[order[i]]
        }
        printf "}"
    }
' "$AUDIT_METRICS_TSV")

# La postura web se serializa con json_escape: el objetivo viene de --target o
# de settings.json y podria contener comillas o barras invertidas. Construirlo
# con awk sin escapar producia un findings.json invalido.
: > "$TMP/web-posture.json"
while IFS="$TAB" read -r wurl wscore wgrade wc wh wm wl; do
    [ -n "$wurl" ] || continue
    wsep=""
    [ -s "$TMP/web-posture.json" ] && wsep=","
    printf '%s{"target":"%s","value":%s,"grade":"%s","critical":%s,"high":%s,"medium":%s,"low":%s}' \
        "$wsep" "$(json_escape "$wurl")" \
        "$wscore" "$wgrade" "${wc:-0}" "${wh:-0}" "${wm:-0}" "${wl:-0}" \
        >> "$TMP/web-posture.json"
done < "$AUDIT_WEB_POSTURE_TSV"
web_posture_json="[$(cat "$TMP/web-posture.json" 2>/dev/null)]"

applied_json=$(list_to_json "$AUDIT_APPLIED_LIST")
pending_json=$(list_to_json "$AUDIT_PENDING_LIST")
skipped_json=$(list_to_json "$AUDIT_SKIPPED_LIST")

{
    printf '{\n'
    printf '  "tool": { "name": "%s", "version": "%s" },\n' "$AUDIT_TOOL_NAME" "$AUDIT_TOOL_VERSION"
    printf '  "audit": {\n'
    printf '    "id": "%s",\n' "$(json_escape "$AUDIT_ID")"
    printf '    "host": "%s",\n' "$(json_escape "$AUDIT_HOST")"
    printf '    "os": "%s",\n' "$(json_escape "$OS_TEXT")"
    printf '    "os_family": "%s",\n' "$OS_FAMILY"
    printf '    "mode": "%s",\n' "$MODE"
    printf '    "apply": %s,\n' "$( [ "$APPLY" -eq 1 ] && printf 'true' || printf 'false' )"
    printf '    "started": "%s",\n' "$STARTED"
    printf '    "finished": "%s",\n' "$FINISHED"
    printf '    "duration_s": %s,\n' "$DURATION"
    printf '    "operator": "%s",\n' "$(json_escape "${USER:-$(id -un 2>/dev/null || printf 'operador')}")"
    printf '    "elevated": %s\n' "$ELEVATED"
    printf '  },\n'
    printf '  "score": { "value": %s, "grade": "%s", "critical": %s, "high": %s, "medium": %s, "low": %s, "info": %s },\n' \
        "$SCORE" "$GRADE" "$N_CRIT" "$N_HIGH" "$N_MED" "$N_LOW" "$N_INFO"
    printf '  "findings": %s,\n' "$findings_json"
    printf '  "metrics": %s,\n' "$metrics_json"
    printf '  "posture": {\n'
    if [ "$HOST_AUDITED" -eq 1 ]; then
        printf '    "host": { "value": %s, "grade": "%s", "critical": %s, "high": %s, "medium": %s, "low": %s, "info": %s },\n' \
            "$HOST_SCORE" "$HOST_GRADE" "$HOST_CRIT" "$HOST_HIGH" "$HOST_MED" "$HOST_LOW" "$HOST_INFO"
    else
        printf '    "host": null,\n'
    fi
    printf '    "web": %s,\n' "$web_posture_json"
    printf '    "note": "posture usa una escala calibrada para lectura operativa (100 - 20xCritical - 6xHigh - 3xMedium - 1xLow, techo C si hay Critical). score conserva la formula del contrato (25/12/5/1) sobre todos los hallazgos. posture.host excluye Web y Preflight; posture.web mide cada sitio."\n'
    printf '  },\n'
    printf '  "hardening": {\n'
    printf '    "applied": %s,\n' "$applied_json"
    printf '    "pending": %s,\n' "$pending_json"
    printf '    "skipped": %s,\n' "$skipped_json"
    printf '    "rollback_file": "%s"\n' "$(json_escape "$AUDIT_ROLLBACK_FILE")"
    printf '  }\n'
    printf '}\n'
} > "$AUDIT_EVIDENCE_DIR/findings.json"

# --------------------------------------------------------------------- informes
report_write_md "$AUDIT_EVIDENCE_DIR/resumen.md"
report_write_html "$AUDIT_EVIDENCE_DIR/informe.html"

# El TSV crudo se conserva: permite rehacer el informe sin repetir la auditoria.
cp -f "$AUDIT_FINDINGS_TSV" "$AUDIT_EVIDENCE_DIR/findings.tsv" 2>/dev/null || true

# --------------------------------------------------------------------- validacion
JSON_OK=1
if ! validate_json "$AUDIT_EVIDENCE_DIR/findings.json"; then
    JSON_OK=0
fi

# --------------------------------------------------------------------- salida
printf '\n'
printf '  --- Resultado ---\n'
printf '  Equipo     : %s\n' "$AUDIT_HOST"
printf '  Duracion   : %s s\n' "$DURATION"
printf '  Critico    : %s\n' "$N_CRIT"
printf '  Alto       : %s\n' "$N_HIGH"
printf '  Medio      : %s\n' "$N_MED"
printf '  Bajo       : %s\n' "$N_LOW"
printf '  Info       : %s\n' "$N_INFO"
if [ "$HOST_AUDITED" -eq 1 ]; then
    printf '  Postura    : %s/100 (grado %s) sin hallazgos web\n' "$HOST_SCORE" "$HOST_GRADE"
else
    printf '  Postura    : equipo no auditado en este modo\n'
fi
if [ -s "$AUDIT_WEB_POSTURE_TSV" ]; then
    while IFS="$TAB" read -r wurl wscore wgrade _; do
        printf '  Sitio      : %s -> %s/100 (%s)\n' "$wurl" "$wscore" "$wgrade"
    done < "$AUDIT_WEB_POSTURE_TSV"
fi
printf '  Cumplim.   : %s/100 (grado %s) formula del contrato\n' "$SCORE" "$GRADE"
printf '  Errores    : %s check(s) sin completar\n' "${AUDIT_CHECK_ERRORS:-0}"
printf '  Evidencia  : %s\n' "$AUDIT_EVIDENCE_DIR"
printf '  Informe    : %s\n' "$AUDIT_EVIDENCE_DIR/informe.html"
if [ -n "$AUDIT_ROLLBACK_FILE" ]; then
    printf '  Rollback   : %s\n' "$AUDIT_EVIDENCE_DIR/$AUDIT_ROLLBACK_FILE"
    printf '               ejecute Rollback-Hardening.sh para revertir\n'
fi
printf '\n'

if [ "$JSON_OK" -ne 1 ]; then
    err "El findings.json generado no supero la validacion. Revise el archivo antes de usarlo."
    rm -rf "$TMP"
    exit 2
fi

# Se borra al final: el resumen de consola y el informe leen el TSV de postura
# web desde $TMP. Borrarlo antes dejaba la linea "Sitio" fuera de la consola.
rm -rf "$TMP"

exit 0
