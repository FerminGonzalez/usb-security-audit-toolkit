#!/usr/bin/env bash
# USB Security Audit Toolkit - generacion de informes (motor Linux)
# Producen texto plano desde los TSV que escribe lib/common.sh.
# ASCII puro.

if [ -n "${AUDIT_REPORT_LOADED:-}" ]; then
    return 0
fi
AUDIT_REPORT_LOADED=1

TAB=$(printf '\t')

html_escape() {
    sed -e 's/&/\&amp;/g' \
        -e 's/</\&lt;/g' \
        -e 's/>/\&gt;/g' \
        -e 's/"/\&quot;/g'
}

# Quita las comillas de un valor JSON escalar guardado en el TSV de metricas.
metric_display() {
    sed -e 's/^"//' -e 's/"$//'
}

# Ordena los hallazgos por severidad y luego por Id.
sorted_findings() {
    local file=$1
    [ -f "$file" ] || return 0
    awk -F"$TAB" '
        BEGIN {
            rank["Critical"] = 0; rank["High"] = 1; rank["Medium"] = 2
            rank["Low"] = 3;      rank["Info"] = 4
        }
        { printf "%d\t%s\n", rank[$2] + 0, $0 }
    ' "$file" | sort -t"$TAB" -k1,1n -k2,2 | cut -f2-
}

severity_color() {
    case "$1" in
        Critical) printf '#8e2b0e' ;;
        High)     printf '#b03a2e' ;;
        Medium)   printf '#b9770e' ;;
        Low)      printf '#1f618d' ;;
        *)        printf '#5d6d7e' ;;
    esac
}

# --------------------------------------------------------------------- resumen.md
report_write_md() {
    local out=$1
    local file=${AUDIT_FINDINGS_TSV:-}

    {
        printf '# Informe de auditoria - %s\n\n' "$AUDIT_HOST"
        printf 'Generado por **%s** v%s.\n\n' "$AUDIT_TOOL_NAME" "$AUDIT_TOOL_VERSION"

        printf '## Datos de la ejecucion\n\n'
        printf '| Campo | Valor |\n|---|---|\n'
        printf '| Equipo | %s |\n' "$AUDIT_HOST"
        printf '| Sistema | %s |\n' "$OS_TEXT"
        printf '| Modo | %s |\n' "$MODE"
        printf '| Hardening aplicado | %s |\n' "$( [ "${APPLY:-0}" = "1" ] && printf 'si' || printf 'no (solo diagnostico)' )"
        printf '| Elevado | %s |\n' "$( [ "$ELEVATED" = "true" ] && printf 'si' || printf 'no' )"
        printf '| Inicio | %s |\n' "$STARTED"
        printf '| Fin | %s |\n' "$FINISHED"
        printf '| Duracion | %s s |\n' "$DURATION"
        if [ "${HOST_AUDITED:-1}" = "1" ]; then
            printf '| Postura del equipo | **%s/100 (grado %s)** |\n' "$HOST_SCORE" "$HOST_GRADE"
        else
            printf '| Postura del equipo | no auditado en este modo |\n'
        fi
        printf '| Cumplimiento (contrato) | %s/100 (grado %s) |\n' "$SCORE" "$GRADE"
        printf '\n'

        printf '## Hallazgos por severidad\n\n'
        printf '| Critical | High | Medium | Low | Info |\n|---|---|---|---|---|\n'
        printf '| %s | %s | %s | %s | %s |\n\n' "$N_CRIT" "$N_HIGH" "$N_MED" "$N_LOW" "$N_INFO"

        if [ "$N_CRIT" = "0" ] && [ "$N_HIGH" = "0" ] && [ "$N_MED" = "0" ] && [ "$N_LOW" = "0" ]; then
            printf 'Sin hallazgos por encima de informativo.\n\n'
        fi

        printf '## Detalle\n\n'
        if [ -n "$file" ] && [ -s "$file" ]; then
            sorted_findings "$file" | while IFS="$TAB" read -r id severity category title detail remediation evidence; do
                case "$severity" in
                    Info) continue ;;
                esac
                printf '### [%s] %s - %s\n\n' "$severity" "$id" "$title"
                printf -- '- **Categoria:** %s\n' "$category"
                printf -- '- **Observado:** %s\n' "$detail"
                printf -- '- **Remediacion:** %s\n' "$remediation"
                if [ -n "$evidence" ]; then
                    printf -- '- **Evidencia:** `%s`\n' "$evidence"
                fi
                printf '\n'
            done

            printf '## Informativo\n\n'
            sorted_findings "$file" | while IFS="$TAB" read -r id severity category title detail remediation evidence; do
                case "$severity" in
                    Info) printf -- '- %s - %s: %s\n' "$id" "$title" "$detail" ;;
                esac
            done
            printf '\n'
        else
            printf 'No se registraron hallazgos.\n\n'
        fi

        if [ -s "${AUDIT_METRICS_TSV:-}" ]; then
            printf '## Metricas\n\n'
            printf '| Metrica | Valor |\n|---|---|\n'
            while IFS="$TAB" read -r name value; do
                printf '| `%s` | %s |\n' "$name" "$(printf '%s' "$value" | metric_display)"
            done < "$AUDIT_METRICS_TSV"
            printf '\n'
        fi

        printf -- '---\n\n'
        printf 'Lectura principal: **postura**, escala base 100 restando 20 por Critical, 6 por High, '
        printf '3 por Medium y 1 por Low, con techo de grado C cuando hay algun Critical.\n\n'
        printf 'El **cumplimiento** conserva la formula del contrato (25/12/5/1) y se publica aparte: '
        printf 'es una medida de conformidad estricta, no de riesgo operativo. Con esa escala cualquier '
        printf 'equipo real con dos o tres hallazgos altos cae por debajo de 60.\n'
    } > "$out"
}

# --------------------------------------------------------------------- informe.html
report_write_html() {
    local out=$1
    local file=${AUDIT_FINDINGS_TSV:-}

    {
        printf '<!DOCTYPE html>\n'
        printf '<html lang="es">\n<head>\n'
        printf '<meta charset="utf-8">\n'
        printf '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        printf '<title>Auditoria %s - %s</title>\n' "$(printf '%s' "$AUDIT_HOST" | html_escape)" "$(printf '%s' "$STARTED" | cut -c1-10)"
        printf '<style>\n'
        cat <<'CSS'
* { box-sizing: border-box; }
body { margin: 0; font-family: "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f4f6f7; color: #212f3d; line-height: 1.5; }
header { background: #1b2631; color: #fdfefe; padding: 26px 32px; }
header h1 { margin: 0 0 6px; font-size: 22px; font-weight: 600; }
header .sub { color: #aab7b8; font-size: 13px; }
.badge { float: right; text-align: center; padding: 10px 22px; border-radius: 8px; background: #2c3e50; }
.badge b { display: block; font-size: 30px; line-height: 1.1; }
.badge span { font-size: 12px; color: #aab7b8; }
.badge .note { display: block; font-size: 11px; color: #85929e; margin-top: 5px; line-height: 1.45; }
main { max-width: 1080px; margin: 0 auto; padding: 24px 20px 60px; }
section { background: #fff; border: 1px solid #d5dbdb; border-radius: 8px; padding: 18px 22px; margin: 0 0 18px; }
h2 { font-size: 16px; margin: 0 0 14px; color: #1b2631; border-bottom: 1px solid #eaeded; padding-bottom: 8px; }
.cards { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 18px; }
.card { flex: 1 1 120px; background: #fff; border: 1px solid #d5dbdb; border-top: 4px solid #999; border-radius: 6px; padding: 10px 12px; }
.card b { display: block; font-size: 22px; }
.card span { font-size: 12px; color: #5d6d7e; text-transform: uppercase; letter-spacing: .04em; }
table { width: 100%; border-collapse: collapse; font-size: 13.5px; }
th { text-align: left; background: #eaeded; color: #1b2631; font-weight: 600; padding: 8px 10px; border-bottom: 1px solid #d5dbdb; }
td { padding: 8px 10px; border-bottom: 1px solid #f0f3f4; vertical-align: top; }
tr:last-child td { border-bottom: none; }
code { background: #f0f3f4; padding: 1px 5px; border-radius: 3px; font-family: Consolas, "Courier New", monospace; font-size: 12.5px; }
.pill { display: inline-block; padding: 2px 9px; border-radius: 10px; color: #fff; font-size: 11.5px; font-weight: 600; }
.muted { color: #5d6d7e; font-size: 12.5px; }
.ok { background: #eafaf1; border-left: 4px solid #27ae60; padding: 10px 14px; border-radius: 4px; margin-bottom: 16px; font-size: 13.5px; }
.warn { background: #fef5e7; border-left: 4px solid #b9770e; padding: 10px 14px; border-radius: 4px; margin-bottom: 16px; font-size: 13.5px; }
footer { max-width: 1080px; margin: 0 auto; padding: 0 20px 40px; color: #7b8a8b; font-size: 12px; }
CSS
        printf '</style>\n</head>\n<body>\n'

        printf '<header>\n'
        # El badge muestra la postura (lectura operativa). El score del contrato
        # se conserva debajo como dato de cumplimiento, no como titular.
        local pscore=${PRIMARY_SCORE:-$SCORE}
        local pgrade=${PRIMARY_GRADE:-$GRADE}
        local plabel=${PRIMARY_LABEL:-Este equipo}
        [ -n "$pscore" ] || { pscore=$SCORE; pgrade=$GRADE; plabel="Global"; }
        printf '<div class="badge"><b>%s</b><span>/ 100 &middot; grado %s</span><span class="note">Postura: %s<br>Cumplimiento (contrato): %s/100 %s</span></div>\n' \
            "$(printf '%s' "$pscore" | html_escape)" \
            "$(printf '%s' "$pgrade" | html_escape)" \
            "$(printf '%s' "$plabel" | html_escape)" \
            "$(printf '%s' "$SCORE" | html_escape)" \
            "$(printf '%s' "$GRADE" | html_escape)"
        printf '<h1>Informe de auditoria - %s</h1>\n' "$(printf '%s' "$AUDIT_HOST" | html_escape)"
        printf '<div class="sub">%s &middot; %s &middot; modo %s</div>\n' \
            "$(printf '%s' "$OS_TEXT" | html_escape)" \
            "$(printf '%s' "$STARTED" | html_escape)" \
            "$(printf '%s' "$MODE" | html_escape)"
        printf '</header>\n<main>\n'

        # Aviso de alcance. El orquestador usa 1/0, no "true": comparar contra
        # "true" dejaba el aviso en "no se modifico nada" incluso tras aplicar.
        if [ "${APPLY:-0}" = "1" ]; then
            printf '<div class="warn"><b>Hardening aplicado.</b> Esta ejecucion modifico la configuracion del equipo. Use el script de rollback indicado abajo para revertir los cambios.</div>\n'
        else
            printf '<div class="ok"><b>Modo diagnostico.</b> No se modifico la configuracion del equipo. El hardening se aplica solo con <code>--apply</code>.</div>\n'
        fi

        # Tarjetas
        printf '<div class="cards">\n'
        for pair in "Critical:$N_CRIT" "High:$N_HIGH" "Medium:$N_MED" "Low:$N_LOW" "Info:$N_INFO"; do
            local name=${pair%%:*}
            local count=${pair##*:}
            printf '<div class="card" style="border-top-color:%s"><b style="color:%s">%s</b><span>%s</span></div>\n' \
                "$(severity_color "$name")" "$(severity_color "$name")" "$count" "$name"
        done
        printf '</div>\n'

        # Postura
        printf '<section>\n<h2>Postura por dominio</h2>\n'
        printf '<p class="muted">Postura = base 100 &minus; 20&times;Critical &minus; 6&times;High &minus; 3&times;Medium &minus; 1&times;Low; con algun Critical el grado no pasa de C. Aqui se separa la postura del equipo auditado de la de cada sitio web, porque son objetos distintos y no deberian promediarse. El cumplimiento estricto del contrato se muestra en el badge como dato secundario.</p>\n'
        printf '<table><thead><tr><th>Objeto</th><th style="width:90px">Puntos</th><th style="width:70px">Grado</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr></thead><tbody>\n'
        if [ "${HOST_AUDITED:-1}" = "1" ]; then
            printf '<tr><td><b>Este equipo</b> <span class="muted">(sin hallazgos Web ni de preflight)</span></td><td><b>%s</b></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
                "$HOST_SCORE" "$HOST_GRADE" "$HOST_CRIT" "$HOST_HIGH" "$HOST_MED" "$HOST_LOW"
        else
            # En modo web el equipo no se audito: mostrarlo como 100/A seria
            # afirmar una conformidad que nadie comprobo.
            printf '<tr><td><b>Este equipo</b> <span class="muted">(no auditado en este modo)</span></td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>\n'
        fi
        if [ -n "${AUDIT_WEB_POSTURE_TSV:-}" ] && [ -s "$AUDIT_WEB_POSTURE_TSV" ]; then
            while IFS="$TAB" read -r target value grade c h m l; do
                printf '<tr><td>Sitio <code>%s</code></td><td><b>%s</b></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
                    "$(printf '%s' "$target" | html_escape)" "$value" "$grade" "$c" "$h" "$m" "$l"
            done < "$AUDIT_WEB_POSTURE_TSV"
        else
            printf '<tr><td>Sitios web <span class="muted">(no auditados en este modo)</span></td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>\n'
        fi
        printf '</tbody></table>\n</section>\n'

        # Hallazgos
        local total=$((N_CRIT + N_HIGH + N_MED + N_LOW + N_INFO))
        printf '<section>\n<h2>Hallazgos (%s)</h2>\n' "$total"
        if [ -n "$file" ] && [ -s "$file" ]; then
            printf '<table><thead><tr><th style="width:70px">Severidad</th><th style="width:170px">Id</th><th>Hallazgo</th><th style="width:120px">Categoria</th></tr></thead><tbody>\n'
            sorted_findings "$file" | while IFS="$TAB" read -r id severity category title detail remediation evidence; do
                printf '<tr><td><span class="pill" style="background:%s">%s</span></td><td><code>%s</code></td><td><b>%s</b><br><span class="muted">%s</span><br><span class="muted"><b>Remediar:</b> %s</span></td><td>%s</td></tr>\n' \
                    "$(severity_color "$severity")" \
                    "$(printf '%s' "$severity" | html_escape)" \
                    "$(printf '%s' "$id" | html_escape)" \
                    "$(printf '%s' "$title" | html_escape)" \
                    "$(printf '%s' "$detail" | html_escape)" \
                    "$(printf '%s' "$remediation" | html_escape)" \
                    "$(printf '%s' "$category" | html_escape)"
            done
            printf '</tbody></table>\n'
        else
            printf '<p class="muted">No se registraron hallazgos.</p>\n'
        fi
        printf '</section>\n'

        # Hardening
        printf '<section>\n<h2>Hardening</h2>\n<table><thead><tr><th style="width:150px">Estado</th><th>Controles</th></tr></thead><tbody>\n'
        printf '<tr><td><span class="pill" style="background:#27ae60">Aplicado</span></td><td>%s</td></tr>\n' "$(json_list_or_dash "${AUDIT_APPLIED_LIST:-}")"
        printf '<tr><td><span class="pill" style="background:#b9770e">Pendiente</span></td><td>%s</td></tr>\n' "$(json_list_or_dash "${AUDIT_PENDING_LIST:-}")"
        printf '<tr><td><span class="pill" style="background:#5d6d7e">Omitido</span></td><td>%s</td></tr>\n' "$(json_list_or_dash "${AUDIT_SKIPPED_LIST:-}")"
        printf '</tbody></table>\n'
        if [ -n "${AUDIT_ROLLBACK_FILE:-}" ]; then
            printf '<div class="warn" style="margin-top:14px">Rollback disponible: <code>%s</code> &mdash; ejecute <code>Rollback-Hardening.sh</code> junto a ese archivo para revertir.</div>\n' \
                "$(printf '%s' "$AUDIT_ROLLBACK_FILE" | html_escape)"
        fi
        printf '</section>\n'

        # Metricas
        if [ -s "${AUDIT_METRICS_TSV:-}" ]; then
            printf '<section>\n<h2>Metricas</h2>\n<table><thead><tr><th>Metrica</th><th style="width:220px">Valor</th></tr></thead><tbody>\n'
            while IFS="$TAB" read -r name value; do
                case "$name" in
                    *_ms|evidence_*|web_target_*) continue ;;
                esac
                printf '<tr><td><code>%s</code></td><td>%s</td></tr>\n' \
                    "$(printf '%s' "$name" | html_escape)" \
                    "$(printf '%s' "$value" | metric_display | html_escape)"
            done < "$AUDIT_METRICS_TSV"
            printf '</tbody></table>\n'
            printf '<details style="margin-top:12px"><summary class="muted">Diagnostico de la herramienta (tiempos y evidencia)</summary>\n'
            printf '<table><thead><tr><th>Metrica</th><th style="width:220px">Valor</th></tr></thead><tbody>\n'
            while IFS="$TAB" read -r name value; do
                case "$name" in
                    *_ms|evidence_*|web_target_*) ;;
                    *) continue ;;
                esac
                printf '<tr><td><code>%s</code></td><td>%s</td></tr>\n' \
                    "$(printf '%s' "$name" | html_escape)" \
                    "$(printf '%s' "$value" | metric_display | html_escape)"
            done < "$AUDIT_METRICS_TSV"
            printf '</tbody></table></details>\n</section>\n'
        fi

        printf '</main>\n<footer>\n'
        printf '%s v%s &middot; generado el %s<br>\n' "$AUDIT_TOOL_NAME" "$AUDIT_TOOL_VERSION" "$(date '+%Y-%m-%d %H:%M:%S')"
        printf 'Duracion de la auditoria: %s s &middot; %s\n' "$DURATION" "$(printf '%s' "$AUDIT_EVIDENCE_DIR" | html_escape)"
        printf '</footer>\n</body>\n</html>\n'
    } > "$out"
}

# Lista de Ids con separador legible; "ninguno" si esta vacia.
# Acepta dos formas porque los llamadores tienen ambas: la ruta de un archivo
# con un Id por linea (lo que genera el orquestador) o una lista "a,b,c".
# OJO: 'read' descarta el ultimo elemento si no acaba en salto de linea, asi
# que el texto se normaliza con '%s\n' antes de partirlo. Sin eso la lista
# salia vacia y el informe ocultaba los controles omitidos.
json_list_or_dash() {
    local src=${1-}
    local text=""
    if [ -z "$src" ]; then
        printf '<span class="muted">ninguno</span>'
        return 0
    fi
    if [ -f "$src" ] && [ -r "$src" ]; then
        text=$(cat "$src" 2>/dev/null)
    else
        text=$(printf '%s\n' "$src" | tr ',' '\n')
    fi
    if [ -z "$text" ]; then
        printf '<span class="muted">ninguno</span>'
        return 0
    fi
    printf '%s\n' "$text" | while IFS= read -r item; do
        [ -n "$item" ] && printf '<code>%s</code> ' "$(printf '%s' "$item" | html_escape)"
    done
}
