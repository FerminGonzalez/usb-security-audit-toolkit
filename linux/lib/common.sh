#!/usr/bin/env bash
# USB Security Audit Toolkit - funciones compartidas del motor Linux
# ASCII puro. Sin dependencias externas mas alla de coreutils.
# Se carga con "source"; no se ejecuta directamente.

if [ -n "${AUDIT_COMMON_LOADED:-}" ]; then
    return 0
fi
AUDIT_COMMON_LOADED=1

AUDIT_TOOL_NAME="USB Security Audit Toolkit"
AUDIT_TOOL_VERSION="1.0.0"

# --------------------------------------------------------------------- salida
AUDIT_USE_COLOR=1
[ -n "${NO_COLOR:-}" ] && AUDIT_USE_COLOR=0
[ -t 1 ] || AUDIT_USE_COLOR=0

_c() { if [ "$AUDIT_USE_COLOR" -eq 1 ]; then printf '\033[%sm' "$1"; fi; }
_r() { if [ "$AUDIT_USE_COLOR" -eq 1 ]; then printf '\033[0m'; fi; }

log()  { printf '%s [INFO] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
ok()   { _c '1;32'; printf '[OK] ';   _r; printf '%s\n' "$*"; }
warn() { _c '1;33'; printf '[WARN] '; _r; printf '%s\n' "$*"; }
err()  { _c '1;31'; printf '[ERR] ';  _r; printf '%s\n' "$*" >&2; }
section() { printf '\n'; _c '1;36'; printf '== %s\n' "$*"; _r; }

# --------------------------------------------------------------------- utilidades
have() { command -v "$1" >/dev/null 2>&1; }

need_root() { [ "$(id -u)" -eq 0 ]; }

# Milisegundos desde epoch. GNU date da %3N; en otros sistemas se degrada a
# segundos y se completa con ceros para no romper la aritmetica.
now_ms() {
    local t
    t=$(date +%s%3N 2>/dev/null)
    case "$t" in
        ''|*N*) printf '%s000' "$(date +%s)" ;;
        *)      printf '%s' "$t" ;;
    esac
}

# Ejecuta con limite de tiempo si existe timeout(1).
tmo() {
    local secs=$1
    shift
    if have timeout; then
        timeout "$secs" "$@"
    else
        "$@"
    fi
}

# Escapa una cadena para que sea un valor JSON valido entrecomillado.
json_escape() {
    local s=${1-}
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\t'/\\t}
    s=${s//$'\r'/\\r}
    s=${s//$'\n'/\\n}
    printf '%s' "$s"
}

# Aplana un valor para una celda TSV: sin tabuladores ni saltos de linea.
tsv_field() {
    local s=${1-}
    s=${s//$'\t'/ }
    s=${s//$'\r'/ }
    s=${s//$'\n'/ | }
    printf '%s' "$s"
}

# --------------------------------------------------------------------- findings
# Cada hallazgo se escribe como una linea JSON (NDJSON) y se ensambla al final.
# Asi el escapado se hace una sola vez por campo y no hay que reconstruir un
# documento gigante con comas condicionales.
# El registro de Ids evita duplicados. Requiere bash 4+ (el orquestador lo
# comprueba al arrancar y aborta con un mensaje claro si es anterior).
declare -A AUDIT_IDS=()

add_finding() {
    local id=$1 severity=$2 category=$3 title=$4 detail=$5 remediation=$6
    local evidence=${7:-}

    [ -n "${AUDIT_FINDINGS_NDJSON:-}" ] || return 0

    # Una severidad fuera de la escala rompe el recuento y el score sin dar
    # ningun error visible: severity_counts no la reconoceria y el hallazgo
    # puntuaria 0. Se normaliza aqui para que el fallo sea evidente y acotado.
    case "$severity" in
        Critical|High|Medium|Low|Info) ;;
        *)
            err "Severidad invalida '$severity' en el hallazgo $id; se registra como Info."
            severity="Info"
            ;;
    esac

    # El contrato exige Id unico en toda la ejecucion: si un check se dispara
    # varias veces se sufija con un contador en lugar de duplicar la entrada.
    local base=$id n
    if [ -n "${AUDIT_IDS[$id]:-}" ]; then
        n=2
        while [ -n "${AUDIT_IDS[$id-$n]:-}" ]; do
            n=$((n + 1))
        done
        id="$id-$n"
    fi
    AUDIT_IDS[$id]=1

    printf '{"id":"%s","severity":"%s","category":"%s","title":"%s","detail":"%s","remediation":"%s","evidence":"%s","status":"open"}\n' \
        "$(json_escape "$id")" \
        "$(json_escape "$severity")" \
        "$(json_escape "$category")" \
        "$(json_escape "$title")" \
        "$(json_escape "$detail")" \
        "$(json_escape "$remediation")" \
        "$(json_escape "$evidence")" >> "$AUDIT_FINDINGS_NDJSON"

    # Copia en texto plano para el informe. Reconstruir los campos desde el
    # JSON escapado con herramientas de shell es fragil; el TSV se genera en
    # el mismo punto donde los valores aun estan en crudo.
    if [ -n "${AUDIT_FINDINGS_TSV:-}" ]; then
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$(tsv_field "$id")" \
            "$(tsv_field "$severity")" \
            "$(tsv_field "$category")" \
            "$(tsv_field "$title")" \
            "$(tsv_field "$detail")" \
            "$(tsv_field "$remediation")" \
            "$(tsv_field "$evidence")" >> "$AUDIT_FINDINGS_TSV"
    fi
}

# --------------------------------------------------------------------- metricas
metric() {
    local name=$1 value=${2-}
    [ -n "${AUDIT_METRICS_TSV:-}" ] || return 0

    local v
    case "$value" in
        ''|null)
            v='null'
            ;;
        *)
            if printf '%s' "$value" | grep -Eq '^-?[0-9]+(\.[0-9]+)?$'; then
                v=$value
            else
                v="\"$(json_escape "$value")\""
            fi
            ;;
    esac
    printf '%s\t%s\n' "$name" "$v" >> "$AUDIT_METRICS_TSV"
}

# --------------------------------------------------------------------- evidencia
# Lee stdin y lo guarda como evidencia cruda del check.
evidence_write() {
    local name=$1
    if [ -z "${AUDIT_EVIDENCE_DIR:-}" ]; then
        cat > /dev/null
        return 0
    fi
    cat > "$AUDIT_EVIDENCE_DIR/$name"
    metric "evidence_$name" "ok"
}

# --------------------------------------------------------------------- checks
# Un modulo nunca aborta la ejecucion completa: cualquier check se lanza por
# aqui, se cronometra y, si falla, deja un hallazgo Info en vez de propagar el
# error. Los contadores viven en variables globales porque la funcion se llama
# en el mismo shell (nada de tuberias ni subshells).
AUDIT_CHECK_ERRORS=0

run_check() {
    local name=$1
    shift
    local t0 t1 rc
    t0=$(now_ms)
    "$@"
    rc=$?
    t1=$(now_ms)
    metric "${name}_ms" "$((t1 - t0))"

    if [ "$rc" -ne 0 ]; then
        AUDIT_CHECK_ERRORS=$((AUDIT_CHECK_ERRORS + 1))
        add_finding "ERR-$name" "Info" "Sistema" \
            "Check sin completar: $name" \
            "El check termino con codigo $rc; sus resultados pueden estar incompletos." \
            "Revise que las herramientas necesarias esten instaladas (ip, ss, curl, openssl)."
    fi
    return 0
}

# --------------------------------------------------------------------- conteo
# Una sola pasada de awk: devuelve "critical high medium low info".
# Con el segundo argumento "exclude" omite Web y Preflight, que describen
# objetos distintos del equipo auditado (misma regla que en Windows).
severity_counts() {
    local file=$1
    local mode=${2:-}
    if [ ! -f "$file" ]; then
        printf '0 0 0 0 0\n'
        return 0
    fi
    awk -v mode="$mode" '
        {
            sev = ""
            cat = ""
            if (match($0, /"severity":"[A-Za-z]+"/)) {
                sev = substr($0, RSTART + 12, RLENGTH - 13)
            }
            if (match($0, /"category":"[^"]*"/)) {
                cat = substr($0, RSTART + 12, RLENGTH - 13)
            }
            if (mode == "exclude" && (cat == "Web" || cat == "Preflight")) next
            c[sev]++
        }
        END {
            printf "%d %d %d %d %d\n", c["Critical"]+0, c["High"]+0, c["Medium"]+0, c["Low"]+0, c["Info"]+0
        }
    ' "$file"
}

# Base 100. Critical 25, High 12, Medium 5, Low 1. Suelo 0. (Contrato, secc. 3)
score_from_counts() {
    local c=$1 h=$2 m=$3 l=$4
    local v
    v=$((100 - c * 25 - h * 12 - m * 5 - l * 1))
    [ "$v" -lt 0 ] && v=0
    printf '%s' "$v"
}

grade_from_score() {
    local v=$1
    if   [ "$v" -ge 90 ]; then printf 'A'
    elif [ "$v" -ge 80 ]; then printf 'B'
    elif [ "$v" -ge 70 ]; then printf 'C'
    elif [ "$v" -ge 60 ]; then printf 'D'
    else                       printf 'F'
    fi
}

# Postura operativa (ADENDA 1.0.2). Escala calibrada para decidir, no para
# cumplir: base 100, Critical 20, High 6, Medium 3, Low 1, suelo 0.
# El score del contrato (25/12/5/1) se conserva intacto como dato aparte.
posture_from_counts() {
    local c=$1 h=$2 m=$3 l=$4
    local v
    v=$((100 - c * 20 - h * 6 - m * 3 - l * 1))
    [ "$v" -lt 0 ] && v=0
    printf '%s' "$v"
}

# Un Critical no puede producir un grado bueno aunque el numero salga alto:
# el techo es C. Sin este tope, un unico Critical (80 puntos) seria una B.
posture_grade_from_counts() {
    local c=$1 h=$2 m=$3 l=$4
    local v g
    v=$(posture_from_counts "$c" "$h" "$m" "$l")
    g=$(grade_from_score "$v")
    if [ "$c" -gt 0 ]; then
        case "$g" in
            A|B) g='C' ;;
        esac
    fi
    printf '%s' "$g"
}

# --------------------------------------------------------------------- listas
list_add() {
    local file=$1 value=$2
    [ -n "${file:-}" ] || return 0
    printf '%s\n' "$value" >> "$file"
}

# Convierte un archivo con un elemento por linea en un array JSON.
list_to_json() {
    local file=$1
    if [ ! -s "$file" ]; then
        printf '[]'
        return 0
    fi
    awk 'BEGIN { first = 1; printf "[" }
         {
            gsub(/\\/, "\\\\")
            gsub(/"/, "\\\"")
            if (!first) printf ", "
            first = 0
            printf "\"%s\"", $0
         }
         END { printf "]" }' "$file"
}

# --------------------------------------------------------------------- validacion
# El contrato pide validar el JSON generado si hay herramienta disponible.
validate_json() {
    local file=$1
    if have python3; then
        python3 -m json.tool "$file" > /dev/null 2>&1 && return 0
        return 1
    fi
    if have jq; then
        jq -e . "$file" > /dev/null 2>&1 && return 0
        return 1
    fi
    # Sin validador disponible: se comprueba al menos que abre y cierra.
    local first last
    first=$(head -c 1 "$file" 2>/dev/null)
    last=$(tail -c 2 "$file" 2>/dev/null | tr -d '\n')
    [ "$first" = "{" ] && [ "$last" = "}" ] && return 0
    return 1
}
