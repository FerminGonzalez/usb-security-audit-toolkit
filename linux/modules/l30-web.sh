#!/usr/bin/env bash
# USB Security Audit Toolkit - modulo l30: auditoria externa de sitios web
# ASCII puro. Solo tecnicas pasivas: se leen cabeceras y certificado, no se
# envia ninguna carga de ataque.
#
# Degradacion: sin curl el modulo se declara no verificable. Sin openssl se
# audita solo HTTP y se avisa en el hallazgo, nunca se asume conformidad.

if [ -n "${AUDIT_L30_LOADED:-}" ]; then
    return 0
fi
AUDIT_L30_LOADED=1

# ---------------------------------------------------------------- utilidades

web_scheme_of() {
    case "$1" in
        https://*) printf 'https' ;;
        http://*)  printf 'http' ;;
        *)         printf 'https' ;;
    esac
}

web_host_of() {
    local u=$1
    u=${u#*://}
    u=${u%%/*}
    u=${u%%\?*}
    u=${u##*@}
    # Quita el puerto, respetando IPv6 entre corchetes.
    case "$u" in
        \[*\]:*) u=${u%%\]:*} ; u=${u#\[} ;;
        \[*\])   u=${u#\[} ; u=${u%\]} ;;
        *:*)     u=${u%%:*} ;;
    esac
    printf '%s' "$u"
}

web_slug_of() {
    printf '%s' "$1" | sed -e 's|^[a-z]*://||' -e 's|[/:?#].*$||' -e 's|[^A-Za-z0-9]|-|g'
}

# Cabeceras completas de la respuesta final, incluidas las de la redireccion.
web_headers() {
    local url=$1 tmo_s=$2
    tmo $((tmo_s + 5)) curl -sS -L --max-time "$tmo_s" \
        -A 'Mozilla/5.0 (USB-Audit-Toolkit)' -D - -o /dev/null "$url" 2>/dev/null
}

# Valor de una cabecera, sin distinguir mayusculas. La ultima ocurrencia gana.
web_header_value() {
    local headers=$1 name=$2
    printf '%s\n' "$headers" \
        | awk -v want="$(printf '%s' "$name" | tr 'A-Z' 'a-z')" '
            BEGIN { FS = ":" }
            {
                key = tolower($1)
                sub(/\r$/, "", key)
                if (key == want) {
                    val = $0
                    sub(/^[^:]*:[[:space:]]*/, "", val)
                    sub(/\r$/, "", val)
                    found = val
                }
            }
            END { if (found != "") print found }
        '
}

# ---------------------------------------------------------------- un sitio
web_audit_one() {
    local url=$1
    local slug host scheme timeout
    slug=$(web_slug_of "$url")
    host=$(web_host_of "$url")
    scheme=$(web_scheme_of "$url")
    timeout=${AUDIT_WEB_TIMEOUT:-15}

    local c=0 h=0 m=0 l=0
    local counted

    # Cuenta y emite. Centralizar el conteo evita que un check nuevo se olvide
    # de sumar en la postura del sitio.
    # OJO: add_finding espera (id, severity, category, title, detail, ...), pero
    # aqui la severidad llega primero para poder contarla. Hay que reinsertarla
    # en su posicion o todos los campos se desplazan uno y la severidad acaba
    # valiendo "Web".
    counted() {
        local sev=$1
        shift
        local fid=$1
        shift
        case "$sev" in
            Critical) c=$((c + 1)) ;;
            High)     h=$((h + 1)) ;;
            Medium)   m=$((m + 1)) ;;
            Low)      l=$((l + 1)) ;;
        esac
        add_finding "$fid" "$sev" "$@"
    }

    if ! have curl; then
        add_finding "WEB-NV-$slug" "Info" "Web" \
            "Auditoria web no verificable: $host" \
            "No se encontro curl. No se pudo contactar el sitio ni leer sus cabeceras." \
            "Instale curl y repita la auditoria."
        return 0
    fi

    local headers status_code time_total
    headers=$(web_headers "$url" "$timeout")
    status_code=$(tmo $((timeout + 5)) curl -sS -L --max-time "$timeout" \
        -A 'Mozilla/5.0 (USB-Audit-Toolkit)' -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)
    time_total=$(tmo $((timeout + 5)) curl -sS -L --max-time "$timeout" \
        -A 'Mozilla/5.0 (USB-Audit-Toolkit)' -o /dev/null -w '%{time_total}' "$url" 2>/dev/null)

    metric "web_target_$slug" "$url"
    metric "web_${slug}_status" "${status_code:-000}"
    metric "web_${slug}_time_s" "${time_total:-null}"

    # ---------------------------------------------------------- disponibilidad
    if [ -z "$status_code" ] || [ "$status_code" = "000" ]; then
        counted "High" "WEB-010" "Web" \
            "Sitio inaccesible: $host" \
            "No hubo respuesta de $url dentro de ${timeout}s. Puede ser caida, filtrado de red o DNS." \
            "Verifique desde otra red antes de concluir que el sitio esta caido."
    elif [ "$status_code" -ge 500 ] 2>/dev/null; then
        counted "Medium" "WEB-011" "Web" \
            "Error del servidor en $host" \
            "$url respondio $status_code. Un error 5xx expone a veces trazas con rutas internas." \
            "Revise los registros del servidor y desactive la depuracion en produccion."
    elif [ "$status_code" -ge 400 ] 2>/dev/null; then
        add_finding "WEB-OK-$slug" "Info" "Web" \
            "Sitio responde con error de cliente: $host" \
            "$url devolvio $status_code. Para una ruta raiz suele indicar que el sitio espera otro host o una ruta concreta." \
            "Confirme que la URL auditada es la correcta."
    fi

    if [ -z "$headers" ]; then
        # No se registra postura del sitio: un sitio que no se pudo leer no
        # esta conforme, simplemente no se midio. Puntuarlo 100/A seria mentir.
        add_finding "WEB-NV-HDR-$slug" "Info" "Web" \
            "Cabeceras no verificables: $host" \
            "Curl no devolvio cabeceras para $url." \
            "Compruebe conectividad y proxy antes de repetir."
        return 0
    fi

    evidence_write "web-$slug-headers.txt" <<EOF
$headers
EOF

    # ---------------------------------------------------------- transporte
    if [ "$scheme" = "http" ]; then
        counted "High" "WEB-012" "Web" \
            "Sitio servido sin cifrar: $host" \
            "La URL auditada usa http://. Todo el trafico, incluidas credenciales y cookies de sesion, viaja en claro." \
            "Sirva el sitio por HTTPS y redirija todo el trafico HTTP con un 301 permanente."
    else
        # Redireccion de http a https. Solo tiene sentido si el host resuelve.
        local code_http
        code_http=$(tmo $((timeout + 5)) curl -sS -o /dev/null --max-time "$timeout" \
            -A 'Mozilla/5.0 (USB-Audit-Toolkit)' -w '%{http_code}' "http://$host/" 2>/dev/null)
        if [ -n "$code_http" ] && [ "$code_http" != "000" ]; then
            if [ "$code_http" -ge 300 ] 2>/dev/null && [ "$code_http" -lt 400 ]; then
                add_finding "WEB-OK-HTTPS-$slug" "Info" "Web" \
                    "Redireccion a HTTPS correcta: $host" \
                    "http://$host/ responde $code_http."
            else
                counted "Medium" "WEB-013" "Web" \
                    "Sin redireccion de HTTP a HTTPS: $host" \
                    "http://$host/ responde $code_http en lugar de redirigir. Un usuario que teclee el dominio sin 's' navega sin cifrar." \
                    "Configure una redireccion 301 permanente de http a https en el servidor o en el balanceador."
            fi
        fi

        local hsts
        hsts=$(web_header_value "$headers" 'strict-transport-security')
        if [ -z "$hsts" ]; then
            counted "Medium" "WEB-014" "Web" \
                "HSTS ausente: $host" \
                "No se envio Strict-Transport-Security. Sin HSTS, un atacante en la red puede degradar la primera visita a HTTP." \
                "Strict-Transport-Security: max-age=31536000; includeSubDomains"
        else
            local maxage
            maxage=$(printf '%s' "$hsts" | sed -n 's/.*max-age=\([0-9]*\).*/\1/p')
            if [ -n "$maxage" ] && [ "$maxage" -lt 15552000 ] 2>/dev/null; then
                counted "Low" "WEB-015" "Web" \
                    "HSTS con vigencia corta: $host" \
                    "Strict-Transport-Security declara max-age=$maxage, por debajo de los 180 dias recomendados." \
                    "Aumente max-age a 31536000 una vez confirmado que todos los subdominios soportan HTTPS."
            else
                add_finding "WEB-OK-HSTS-$slug" "Info" "Web" \
                    "HSTS configurado: $host" \
                    "Strict-Transport-Security: $hsts" 
            fi
        fi
    fi

    # ---------------------------------------------------------- cabeceras de defensa
    local csp xfo xcto refpol permpol
    csp=$(web_header_value "$headers" 'content-security-policy')
    xfo=$(web_header_value "$headers" 'x-frame-options')
    xcto=$(web_header_value "$headers" 'x-content-type-options')
    refpol=$(web_header_value "$headers" 'referrer-policy')

    if [ -z "$csp" ]; then
        counted "Medium" "WEB-016" "Web" \
            "Content-Security-Policy ausente: $host" \
            "Sin CSP no hay segunda barrera frente a XSS: cualquier HTML inyectado se ejecuta con el origen del sitio." \
            "Defina una CSP restrictiva (default-src 'self') y ajustela hasta eliminar los avisos del navegador."
    else
        add_finding "WEB-OK-CSP-$slug" "Info" "Web" \
            "Content-Security-Policy presente: $host" \
            "Se recibio una CSP de $(printf '%s' "$csp" | wc -c) caracteres."
    fi

    if [ -z "$xfo" ]; then
        case "$csp" in
            *frame-ancestors*) : ;;
            *)
                counted "Low" "WEB-017" "Web" \
                    "Sin proteccion contra clickjacking: $host" \
                    "No hay X-Frame-Options ni frame-ancestors en la CSP, de modo que el sitio puede incrustarse en un iframe ajeno." \
                    "X-Frame-Options: DENY  (o 'frame-ancestors none' en la CSP)"
                ;;
        esac
    fi

    if [ -z "$xcto" ]; then
        counted "Low" "WEB-018" "Web" \
            "X-Content-Type-Options ausente: $host" \
            "Sin 'nosniff', el navegador puede interpretar como script un archivo subido con otro tipo declarado." \
            "X-Content-Type-Options: nosniff"
    fi

    if [ -z "$refpol" ]; then
        case "${AUDIT_MODE:-rapido}" in
            rapido) : ;;
            *)
                counted "Low" "WEB-019" "Web" \
                    "Referrer-Policy ausente: $host" \
                    "Sin politica de referente, la URL completa (que puede incluir tokens) se envia a terceros." \
                    "Referrer-Policy: strict-origin-when-cross-origin"
                ;;
        esac
    fi

    case "${AUDIT_MODE:-rapido}" in
        rapido) : ;;
        *)
            permpol=$(web_header_value "$headers" 'permissions-policy')
            if [ -z "$permpol" ]; then
                counted "Low" "WEB-020" "Web" \
                    "Permissions-Policy ausente: $host" \
                    "Sin Permissions-Policy, cualquier iframe de terceros puede solicitar camara, microfono o geolocalizacion." \
                    "Permissions-Policy: geolocation=(), camera=(), microphone=()"
            fi
            ;;
    esac

    # ---------------------------------------------------------- fuga de version
    local server xpb leaks=""
    server=$(web_header_value "$headers" 'server')
    xpb=$(web_header_value "$headers" 'x-powered-by')
    case "$server" in
        *[0-9].[0-9]*) leaks="$leaks Server=$server" ;;
    esac
    case "$xpb" in
        ?*) leaks="$leaks X-Powered-By=$xpb" ;;
    esac
    if [ -n "$leaks" ]; then
        counted "Low" "WEB-021" "Web" \
            "Version del servidor revelada: $host" \
            "Las cabeceras publican software y version:$leaks. Permite buscar exploits exactos sin adivinar." \
            "Oculte la version: server_tokens off (nginx), ServerTokens Prod (Apache), y elimine X-Powered-By."
    fi

    # ---------------------------------------------------------- cookies
    case "${AUDIT_MODE:-rapido}" in
        rapido) : ;;
        *)
            local setcookies insecure=0 nohttponly=0 total_cookies=0
            setcookies=$(printf '%s\n' "$headers" | grep -i '^set-cookie:' | tr -d '\r')
            if [ -n "$setcookies" ]; then
                total_cookies=$(printf '%s\n' "$setcookies" | grep -c .)
                insecure=$(printf '%s\n' "$setcookies" | grep -vic 'secure')
                nohttponly=$(printf '%s\n' "$setcookies" | grep -vic 'httponly')
                metric "web_${slug}_cookies" "$total_cookies"
                if [ "$insecure" -gt 0 ]; then
                    counted "Medium" "WEB-022" "Web" \
                        "Cookies sin atributo Secure: $host" \
                        "$insecure de $total_cookies cookie(s) no declaran Secure y viajan tambien por HTTP en claro." \
                        "Anada 'Secure' a todas las cookies de sesion y sirva el sitio unicamente por HTTPS."
                fi
                if [ "$nohttponly" -gt 0 ]; then
                    counted "Low" "WEB-023" "Web" \
                        "Cookies accesibles desde JavaScript: $host" \
                        "$nohttponly de $total_cookies cookie(s) no declaran HttpOnly, de modo que un XSS puede leer la sesion." \
                        "Anada 'HttpOnly' a las cookies que no necesiten leerse desde script."
                fi
            fi
            ;;
    esac

    # ---------------------------------------------------------- TLS
    if [ "$scheme" = "https" ]; then
        if ! have openssl; then
            add_finding "WEB-NV-TLS-$slug" "Info" "Web" \
                "Certificado TLS no verificable: $host" \
                "No se encontro openssl. No se puede comprobar version de protocolo ni fecha de caducidad." \
                "Instale openssl y repita la auditoria."
        else
            local cert notafter end_epoch now_epoch days
            cert=$(tmo $((timeout + 5)) openssl s_client -connect "$host:443" -servername "$host" \
                </dev/null 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null)
            notafter=${cert#notAfter=}
            if [ -n "$notafter" ] && [ "$notafter" != "$cert" ]; then
                end_epoch=$(date -d "$notafter" +%s 2>/dev/null)
                now_epoch=$(date +%s)
                if [ -n "$end_epoch" ]; then
                    days=$(( (end_epoch - now_epoch) / 86400 ))                    metric "web_${slug}_cert_days" "$days"
                    if [ "$days" -lt 0 ]; then
                        counted "High" "WEB-024" "Web" \
                            "Certificado TLS caducado: $host" \
                            "El certificado expiro hace $(( -days )) dia(s) ($notafter). Los navegadores muestran un aviso de sitio no seguro." \
                            "Renueve el certificado y compruebe que la renovacion automatica esta activa."
                    elif [ "$days" -lt 15 ]; then
                        counted "Medium" "WEB-025" "Web" \
                            "Certificado TLS a punto de caducar: $host" \
                            "Quedan $days dia(s) para la caducidad ($notafter)." \
                            "Renueve el certificado ahora y verifique el temporizador de renovacion."
                    else
                        add_finding "WEB-OK-TLS-$slug" "Info" "Web" \
                            "Certificado TLS vigente: $host" \
                            "Caduca en $days dia(s)." 
                    fi
                else
                    # date -d es GNU. Sin el, la fecha no se puede convertir y
                    # antes esto no dejaba ningun rastro: silencio, no conformidad.
                    add_finding "WEB-NV-TLS3-$slug" "Info" "Web" \
                        "Caducidad del certificado no calculable: $host" \
                        "Se obtuvo la fecha de caducidad ($notafter) pero 'date -d' no pudo convertirla en este sistema. No se asume conformidad." \
                        "Compruebe la fecha manualmente: 'echo | openssl s_client -connect $host:443 2>/dev/null | openssl x509 -noout -enddate'."
                fi
            else
                add_finding "WEB-NV-TLS2-$slug" "Info" "Web" \
                    "Certificado TLS no legible: $host" \
                    "openssl no pudo obtener el certificado de $host:443. Puede ser un proxy de inspeccion o un fallo de conexion." \
                    "Repita con 'openssl s_client -connect $host:443 -servername $host'."
            fi
        fi
    fi

    # Postura del sitio: el orquestador aplica la formula del contrato.
    printf '%s\t%s\t%s\t%s\t%s\n' "$url" "$c" "$h" "$m" "$l" >> "${AUDIT_WEB_COUNTS_TSV:-/dev/null}"
}

# ---------------------------------------------------------------- entrada
module_l30_web() {
    section "Sitios web"

    if [ "${#AUDIT_WEB_TARGETS[@]}" -eq 0 ]; then
        add_finding "WEB-000" "Info" "Preflight" \
            "Sin objetivos web configurados" \
            "No se indico ningun sitio con --target ni existe la lista web.targets en settings.json." \
            "Ejecute: audit-linux.sh --mode web --target https://ejemplo.com"
        return 0
    fi

    local t
    for t in "${AUDIT_WEB_TARGETS[@]}"; do
        [ -n "$t" ] || continue
        run_check "WEB-$(web_slug_of "$t")" web_audit_one "$t"
    done
    ok "Web: ${#AUDIT_WEB_TARGETS[@]} sitio(s) revisados"
}
