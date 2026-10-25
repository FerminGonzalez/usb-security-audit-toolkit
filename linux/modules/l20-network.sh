#!/usr/bin/env bash
# USB Security Audit Toolkit - modulo l20: red, puertos y conectividad
# ASCII puro.

if [ -n "${AUDIT_L20_LOADED:-}" ]; then
    return 0
fi
AUDIT_L20_LOADED=1

# ---------------------------------------------------------------- utilidades

# Devuelve la puerta de enlace por defecto. ip route es la fuente fiable;
# route -n queda como respaldo para sistemas sin iproute2.
net_default_gateway() {
    local gw=""
    if have ip; then
        gw=$(tmo 5 ip route 2>/dev/null | awk '$1 == "default" { print $3; exit }')
    fi
    if [ -z "$gw" ] && have route; then
        gw=$(tmo 5 route -n 2>/dev/null | awk '$1 == "0.0.0.0" { print $2; exit }')
    fi
    printf '%s' "$gw"
}

# Lista "proto puerto direccion" de los sockets en escucha.
net_listening() {
    if have ss; then
        tmo 10 ss -tulnH 2>/dev/null | awk '{ print $1, $5 }'
        return 0
    fi
    if have netstat; then
        tmo 10 netstat -tuln 2>/dev/null | awk 'NR > 2 && $1 ~ /^(tcp|udp)/ { print $1, $4 }'
        return 0
    fi
    return 1
}

# Un socket esta expuesto si escucha en comodin (0.0.0.0, [::] o *), no en
# loopback. Se compara el host sin el puerto: mas robusto que patrones glob
# sobre la cadena completa, y no confunde 127.0.0.1 con un comodin.
net_is_exposed() {
    local host
    host=${1%:*}
    case "$host" in
        0.0.0.0|"*"|"[::]"|""|"::") return 0 ;;
    esac
    return 1
}

net_port_of() {
    local addr=$1
    printf '%s' "${addr##*:}"
}

# ---------------------------------------------------------------- interfaces
l20_net_interfaces() {
    local count=0 up=0

    if have ip; then
        count=$(tmo 5 ip -o link show 2>/dev/null | grep -vc ' lo: ')
        up=$(tmo 5 ip -o link show up 2>/dev/null | grep -vc ' lo: ')
    elif have ifconfig; then
        count=$(tmo 5 ifconfig -a 2>/dev/null | grep -c '^[a-z]')
        up=$(tmo 5 ifconfig 2>/dev/null | grep -c '^[a-z]')
    fi

    metric "net_interfaces" "$count"
    metric "net_interfaces_up" "$up"

    # Direcciones globales. Se listan para que el operador sepa que expone.
    local addrs=""
    if have ip; then
        addrs=$(tmo 5 ip -o -4 addr show scope global 2>/dev/null | awk '{ print $2 ":" $4 }' | tr '\n' ' ')
    fi
    if [ -n "$addrs" ]; then
        add_finding "LIN-OK-NET" "Info" "Red" \
            "Interfaces con direccion IPv4" \
            "Direcciones globales: $addrs" \
            "Ninguna."
    fi

    # IPv6 es superficie adicional: si esta activo y sin firewall, importa.
    local v6="no"
    if have ip; then
        if tmo 5 ip -o -6 addr show scope global 2>/dev/null | grep -q 'inet6'; then
            v6="si"
        fi
    fi
    metric "ipv6_global" "$v6"
    if [ "$v6" = "si" ]; then
        add_finding "LIN-120" "Low" "Red" \
            "Direccionamiento IPv6 global activo" \
            "El equipo tiene direcciones IPv6 globales. Muchos firewalls solo filtran IPv4, de modo que los servicios quedan alcanzables por una via que nadie revisa." \
            "Revise las reglas de ip6tables/nft para IPv6 o deshabilite IPv6 si no se usa."
    fi
}

# ---------------------------------------------------------------- puertos
l20_net_ports() {
    local listing
    if ! listing=$(net_listening); then
        add_finding "LIN-NV-PORTS" "Info" "Red" \
            "Puertos en escucha no verificables" \
            "No se encontro ss ni netstat. No se puede enumerar la superficie de red local." \
            "Instale iproute2 (ss) y repita la auditoria."
        return 0
    fi

    local total exposed proto addr port
    total=$(printf '%s\n' "$listing" | grep -c .)
    metric "listening_ports" "$total"

    # Cero sockets en escucha no es un equipo limpio: es un fallo de la
    # herramienta. Un Linux real siempre tiene algo escuchando (o el propio ss
    # no supo leerlo). Se declara no verificable en lugar de conforme.
    if [ "$total" -eq 0 ]; then
        add_finding "LIN-NV-PORTS-EMPTY" "Info" "Red" \
            "Enumeracion de puertos vacia" \
            "La herramienta de enumeracion no devolvio ningun socket. No se puede afirmar que no haya servicios expuestos." \
            "Compruebe que 'ss -tuln' funciona con sudo y repita la auditoria."
        return 0
    fi

    # Puertos con riesgo alto por si mismos: protocolos en claro o paneles
    # administrativos que no deberian estar en un equipo de usuario.
    local high_ports=" 23 21 512 513 514 3389 445 139 2375 2376 9200 9300 6379 27017 3306 5432 11211 "
    # Puertos que solo son graves si no hay firewall.
    local med_ports=" 22 25 110 143 993 995 5900 8080 8443 8888 "

    local high_list="" med_list="" other_list=""
    while read -r proto addr; do
        [ -n "$addr" ] || continue
        net_is_exposed "$addr" || continue
        port=$(net_port_of "$addr")
        [ -n "$port" ] || continue
        case "$high_ports" in
            *" $port "*) high_list="$high_list $port/$proto" ; continue ;;
        esac
        case "$med_ports" in
            *" $port "*) med_list="$med_list $port/$proto" ; continue ;;
        esac
        other_list="$other_list $port/$proto"
    done <<EOF
$listing
EOF

    if [ -n "$high_list" ]; then
        add_finding "LIN-121" "High" "Red" \
            "Servicios de alto riesgo escuchando en todas las interfaces" \
            "Puertos expuestos:$high_list. Son protocolos en claro (telnet/ftp), comparticion de archivos (SMB/NetBIOS) o bases de datos sin autenticacion por defecto." \
            "Detenga el servicio o limite la escucha a 127.0.0.1. Verifique con 'ss -tulnp' que proceso lo ocupa."
    fi

    local fw="ninguno"
    if [ -n "${AUDIT_FW_MECHANISM:-}" ]; then
        fw="$AUDIT_FW_MECHANISM"
    fi

    if [ -n "$med_list" ]; then
        # El mismo puerto es High sin firewall y Medium con filtrado activo:
        # el firewall reduce el riesgo pero no lo elimina.
        local sev="Medium"
        [ "$fw" = "ninguno" ] && sev="High"
        add_finding "LIN-122" "$sev" "Red" \
            "Servicios administrativos accesibles desde la red" \
            "Puertos expuestos:$med_list. Filtrado de red detectado: $fw." \
            "Restrinja el acceso por origen (ufw allow from <red> to any port <n>) o limite la escucha a loopback."
    fi

    if [ -n "$other_list" ]; then
        add_finding "LIN-123" "Low" "Red" \
            "Otros servicios escuchando en todas las interfaces" \
            "Puertos expuestos:$other_list." \
            "Confirme que cada uno debe ser alcanzable desde la red; si no, fije la directiva de escucha a 127.0.0.1."
    fi

    if [ -z "$high_list" ] && [ -z "$med_list" ] && [ -z "$other_list" ]; then
        add_finding "LIN-OK-PORTS" "Info" "Red" \
            "Sin servicios expuestos fuera de loopback" \
            "$total socket(s) en escucha, todos limitados a la interfaz local." \
            "Ninguna."
    fi
}

# ---------------------------------------------------------------- DNS
l20_net_dns() {
    local ns="" count=0 resolvable="desconocido" probe

    if [ -r /etc/resolv.conf ]; then
        ns=$(awk '/^[[:space:]]*nameserver/ { print $2 }' /etc/resolv.conf | tr '\n' ' ')
        count=$(printf '%s' "$ns" | wc -w)
    fi
    metric "dns_servers" "$count"

    if [ "$count" -eq 0 ]; then
        add_finding "LIN-130" "Medium" "Red" \
            "Sin servidores DNS configurados" \
            "/etc/resolv.conf no declara ningun nameserver. La resolucion depende de mecanismos implicitos y fallara de forma intermitente." \
            "Configure DNS por systemd-resolved o anada 'nameserver <ip>' en /etc/resolv.conf."
    fi

    # Un resolvedor local (127.0.0.53) es normal en systemd-resolved; el test
    # de resolucion es lo que realmente dice si funciona.
    probe="www.google.com"
    if [ -n "${AUDIT_DNS_TEST_HOST:-}" ]; then
        probe="$AUDIT_DNS_TEST_HOST"
    fi

    if have getent; then
        if tmo 6 getent hosts "$probe" >/dev/null 2>&1; then
            resolvable="yes"
        else
            resolvable="no"
        fi
    elif have nslookup; then
        if tmo 6 nslookup "$probe" >/dev/null 2>&1; then
            resolvable="yes"
        else
            resolvable="no"
        fi
    fi
    metric "dns_resolution" "$resolvable"

    if [ "$resolvable" = "no" ]; then
        add_finding "LIN-131" "High" "Red" \
            "La resolucion DNS no funciona" \
            "No se pudo resolver $probe con los servidores configurados ($ns). Sin DNS fallan las actualizaciones, TLS por nombre y la mayor parte del software." \
            "Compruebe conectividad al puerto 53/UDP y la configuracion de systemd-resolved o dnsmasq."
    elif [ "$resolvable" = "yes" ]; then
        add_finding "LIN-OK-DNS" "Info" "Red" \
            "Resolucion DNS operativa" \
            "$probe resuelve correctamente. Servidores: ${ns:-implicitos}." \
            "Ninguna."
    else
        add_finding "LIN-NV-DNS" "Info" "Red" \
            "Resolucion DNS no verificable" \
            "No hay getent ni nslookup disponibles." \
            "Instale libc-bin o bind-utils para verificar."
    fi
}

# ---------------------------------------------------------------- conectividad
l20_net_connectivity() {
    local gw loss_gw="null" loss_net="null" count pinged="no"

    gw=$(net_default_gateway)
    if [ -n "$gw" ]; then
        metric "default_gateway" "$gw"
    else
        add_finding "LIN-132" "Medium" "Red" \
            "Sin puerta de enlace por defecto" \
            "No se encontro ruta default. El equipo solo alcanza su propia subred." \
            "Revise 'ip route' y la configuracion de DHCP de la interfaz."
    fi

    count=4
    if [ -n "${AUDIT_PING_COUNT:-}" ]; then
        count="$AUDIT_PING_COUNT"
    fi

    if ! have ping; then
        add_finding "LIN-NV-PING" "Info" "Red" \
            "Conectividad no verificable" \
            "No se encontro ping. No se puede medir perdida de paquetes." \
            "Instale iputils-ping para obtener la medicion."
        metric "ping_gateway_loss_pct" "null"
        metric "ping_internet_loss_pct" "null"
        return 0
    fi

    # Perdida hacia la puerta de enlace: mide el enlace local.
    # LC_ALL=C fija el idioma de la salida de ping: con locale espanol la linea
    # es "perdida de paquetes" y el awk no encontraria la cifra.
    if [ -n "$gw" ]; then
        pinged="yes"
        loss_gw=$(LC_ALL=C tmo $((count + 10)) ping -c "$count" -W 1 -n "$gw" 2>/dev/null \
            | awk -F', ' '/packet loss/ { gsub(/% packet loss.*/, "", $3); print $3; exit }')
        [ -n "$loss_gw" ] || loss_gw="null"
    fi
    metric "ping_gateway_loss_pct" "$loss_gw"

    # Perdida hacia 1.1.1.1: mide la salida a Internet sin depender de DNS.
    if [ "$pinged" = "yes" ]; then
        loss_net=$(LC_ALL=C tmo $((count + 10)) ping -c "$count" -W 1 -n 1.1.1.1 2>/dev/null \
            | awk -F', ' '/packet loss/ { gsub(/% packet loss.*/, "", $3); print $3; exit }')
        [ -n "$loss_net" ] || loss_net="null"
    fi
    metric "ping_internet_loss_pct" "$loss_net"

    if [ "$loss_gw" != "null" ] && [ "$loss_gw" -gt 0 ] 2>/dev/null; then
        add_finding "LIN-133" "Medium" "Red" \
            "Perdida de paquetes hacia la puerta de enlace" \
            "Perdida del ${loss_gw}% hacia $gw. Indica problema de cable, Wi-Fi o saturacion del enlace local." \
            "Revise el estado del enlace con 'ip -s link' y descarte interferencia o cableado."
    elif [ "$loss_gw" != "null" ]; then
        add_finding "LIN-OK-GW" "Info" "Red" \
            "Enlace local estable" \
            "Sin perdida de paquetes hacia la puerta de enlace $gw." \
            "Ninguna."
    fi

    if [ "$loss_net" != "null" ] && [ "$loss_net" -gt 20 ] 2>/dev/null; then
        add_finding "LIN-134" "Low" "Red" \
            "Perdida de paquetes hacia Internet" \
            "Perdida del ${loss_net}% hacia 1.1.1.1. Puede ser el proveedor o un filtrado en el camino." \
            "Compare con una segunda red antes de abrir incidencia con el proveedor."
    fi
}

# ---------------------------------------------------------------- vecinos
l20_net_neighbors() {
    local neigh=""
    if have ip; then
        neigh=$(tmo 5 ip -4 neigh show 2>/dev/null | awk '$1 != "" { print $1, $5 }')
    elif have arp; then
        neigh=$(tmo 5 arp -n 2>/dev/null | awk 'NR > 1 { print $1, $3 }')
    fi

    if [ -z "$neigh" ]; then
        return 0
    fi

    local total
    total=$(printf '%s\n' "$neigh" | grep -c .)
    metric "arp_entries" "$total"

    # Dos IP distintas con la misma MAC en la misma subred es la firma clasica
    # de ARP spoofing, salvo en balanceadores o failover.
    local dup
    dup=$(printf '%s\n' "$neigh" | awk '{ print $2 }' | grep -v '^$' | sort | uniq -d)
    if [ -n "$dup" ]; then
        add_finding "LIN-140" "Medium" "Red" \
            "Posible suplantacion ARP" \
            "Estas MAC aparecen asociadas a mas de una IP: $(printf '%s' "$dup" | tr '\n' ' '). Puede ser un failover legitimo o un ataque de intermediario." \
            "Confirme con 'ip neigh' en el equipo sospechoso; use arpwatch o port-security en el conmutador."
    fi
}

# ---------------------------------------------------------------- entrada
module_l20_network() {
    section "Red"
    run_check "LIN-Ifaces"  l20_net_interfaces
    # El firewall se evaluo en l10; se reutiliza su resultado para graduar
    # la severidad de los puertos expuestos sin repetir la deteccion.
    if [ -n "${AUDIT_FW_MECHANISM:-}" ]; then
        :
    fi
    run_check "LIN-Ports"   l20_net_ports
    run_check "LIN-DNS"     l20_net_dns
    run_check "LIN-Connect" l20_net_connectivity
    run_check "LIN-Neigh"   l20_net_neighbors
    ok "Red: revision completada"
}
