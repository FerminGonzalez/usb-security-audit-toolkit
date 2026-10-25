#!/usr/bin/env bash
# =====================================================================
#  USB Security Audit Toolkit v1.0.0 - Entrada Linux
#  ASCII puro. Saltos de linea LF. Sin BOM.
#  IMPORTANTE: FAT32/exFAT no guardan permisos. Tras copiar al USB o al
#  disco hay que ejecutar:  chmod +x INICIAR.sh
# =====================================================================
set -u

VERSION="1.0.0"

cd "$(dirname "$0")" 2>/dev/null || {
  echo "[ERROR] No se pudo entrar al directorio del toolkit."
  exit 1
}
ROOT="$(pwd)"
SELF="$ROOT/$(basename "$0")"
AUDIT="$ROOT/linux/audit-linux.sh"
MODULE_DIR="$ROOT/linux/modules"

MODE=""
MODEARG=""
APPLY=0
TARGETS=()

# ---------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------
banner() {
  echo "=========================================================="
  echo "  USB SECURITY AUDIT TOOLKIT v$VERSION"
  echo "  Auditoria defensiva de Linux - solo lectura por defecto"
  echo "=========================================================="
}

usage() {
  cat <<'EOF'

USB Security Audit Toolkit - entrada Linux

USO:
  ./INICIAR.sh                Menu interactivo
  ./INICIAR.sh 1              Auditoria rapida
  ./INICIAR.sh 2              Auditoria completa
  ./INICIAR.sh 3 [URL...]     Auditoria web (destinos de settings o indicados)
  ./INICIAR.sh 4              Auditoria rapida y aplicar hardening
  ./INICIAR.sh 5              Salir
  ./INICIAR.sh --help         Esta ayuda

MODOS:
  1 rapido    Comprobaciones esenciales.
  2 completo  Revision profunda de sistema, red y servicios.
  3 web       TLS, certificados y cabeceras de los destinos.
  4 aplicar   Modo rapido y despues aplica los controles de hardening.
              Genera rollback-<id>.sh para revertir. Modifica el sistema.

REQUISITOS:
  bash 4+, coreutils, curl, openssl. Root recomendado: sin root la
  mayoria de las comprobaciones quedan fuera de alcance.

SALIDA:
  evidencia/<ID>/findings.json   datos de la auditoria
  evidencia/<ID>/resumen.md      resumen legible

AVISO LEGAL:
  Use esta herramienta solo en equipos propios o con autorizacion
  escrita del responsable.

NOTA: si el toolkit vive en FAT32 o exFAT los permisos no se guardan.
      Ejecute  chmod +x INICIAR.sh  despues de copiarlo.

EOF
}

die() {
  echo ""
  echo "[ERROR] $1"
  echo ""
  exit "${2:-1}"
}

apply_mode() {
  MODE=""
  APPLY=0
  case "$MODEARG" in
    1) MODE="rapido" ;;
    2) MODE="completo" ;;
    3) MODE="web" ;;
    4) MODE="rapido"; APPLY=1 ;;
    5) echo ""; echo "Saliendo. No se ejecuto ninguna comprobacion."; exit 0 ;;
    *) return 1 ;;
  esac
  return 0
}

# ---------------------------------------------------------------------
# Comprobacion del toolkit
# ---------------------------------------------------------------------
[ -f "$AUDIT" ] || die "Toolkit incompleto: no existe linux/audit-linux.sh en $ROOT" 3
[ -d "$MODULE_DIR" ] || echo "[WARN] No existe $MODULE_DIR; el motor podria fallar."

# ---------------------------------------------------------------------
# Argumentos
# ---------------------------------------------------------------------
if [ "$#" -gt 0 ]; then
  case "$1" in
    --help|-h|--ayuda|help)
      usage
      exit 0
      ;;
  esac
  MODEARG="$1"
  case "$MODEARG" in
    rapido|Rapido|RAPIDO) MODEARG="1" ;;
    completo|Completo|COMPLETO) MODEARG="2" ;;
    web|Web|WEB) MODEARG="3" ;;
    aplicar|hardening) MODEARG="4" ;;
  esac
  shift
  while [ "$#" -gt 0 ]; do
    TARGETS+=("$1")
    shift
  done
  apply_mode || die "Opcion no reconocida: $MODEARG (validas: 1 2 3 4 5 --help)" 5
else
  # -------------------------------------------------------------------
  # Menu interactivo
  # -------------------------------------------------------------------
  while :; do
    clear 2>/dev/null || true
    banner
    echo ""
    echo "   1  Auditoria RAPIDA           - comprobaciones esenciales"
    echo "   2  Auditoria COMPLETA         - revision profunda"
    echo "   3  Auditoria WEB              - TLS, cabeceras, cookies"
    echo "   4  RAPIDA + APLICAR HARDENING - modifica el sistema"
    echo "   5  Salir"
    echo ""
    printf "  Seleccione una opcion 1-5: "
    if ! read -r MODEARG; then
      echo ""
      echo "Entrada cerrada. Saliendo."
      exit 0
    fi
    case "$MODEARG" in
      1|2|3|4|5) ;;
      *) echo ""; echo "  Opcion no valida."; sleep 1; continue ;;
    esac
    apply_mode
    break
  done

  if [ "$MODE" = "web" ]; then
    printf "  Destino web (vacio = usar config/settings.json): "
    if read -r EXTRA; then
      if [ -n "$EXTRA" ]; then
        # Admite varios destinos separados por espacios o comas.
        OLDIFS="$IFS"
        IFS=', '
        for t in $EXTRA; do
          [ -n "$t" ] && TARGETS+=("$t")
        done
        IFS="$OLDIFS"
      fi
    fi
  fi
fi

# ---------------------------------------------------------------------
# Root / sudo
# ---------------------------------------------------------------------
IS_ROOT=0
[ "$(id -u 2>/dev/null || echo 1)" = "0" ] && IS_ROOT=1

if [ "$APPLY" -eq 1 ] && [ "$IS_ROOT" -eq 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    echo "[INFO] El hardening requiere root. Relanzando con sudo..."
    if [ "${#TARGETS[@]}" -gt 0 ]; then
      exec sudo -- "$SELF" "$MODEARG" "${TARGETS[@]}"
    else
      exec sudo -- "$SELF" "$MODEARG"
    fi
  fi
  echo "[WARN] Sin root no se puede aplicar hardening. Se ejecutara solo la auditoria."
  APPLY=0
fi

if [ "$IS_ROOT" -eq 0 ]; then
  echo "[WARN] Ejecutando sin root: muchos checks quedaran fuera de alcance."
  echo ""
fi

# ---------------------------------------------------------------------
# Ejecucion
# ---------------------------------------------------------------------
banner
echo ""
echo "   Raiz     : $ROOT"
echo "   Modo     : $MODE"
if [ "$APPLY" -eq 1 ]; then
  echo "   Cambios  : SI - se aplicara hardening"
else
  echo "   Cambios  : NO - solo lectura"
fi
if [ "${#TARGETS[@]}" -gt 0 ]; then
  echo "   Destinos : ${TARGETS[*]}"
fi
echo "=========================================================="
echo ""

CMD=(bash "$AUDIT" --mode "$MODE")
[ "$APPLY" -eq 1 ] && CMD+=(--apply)

if [ "$MODE" = "web" ] && [ "${#TARGETS[@]}" -gt 0 ]; then
  if grep -q -- '--target' "$AUDIT" 2>/dev/null; then
    for t in "${TARGETS[@]}"; do
      CMD+=(--target "$t")
    done
  else
    echo "[WARN] linux/audit-linux.sh no acepta --target; se usan los destinos de settings."
    echo ""
  fi
fi

"${CMD[@]}"
RC=$?

echo ""
echo "[INFO] Codigo de salida del motor: $RC"

# ---------------------------------------------------------------------
# Localiza la evidencia mas reciente
# ---------------------------------------------------------------------
FINDINGS=""
HTML=""
if [ -d "$ROOT/evidencia" ]; then
  FINDINGS="$(find "$ROOT/evidencia" -type f -name 'findings.json' 2>/dev/null | xargs -r ls -1t 2>/dev/null | head -n 1)"
  HTML="$(find "$ROOT/evidencia" -type f -name '*.html' 2>/dev/null | xargs -r ls -1t 2>/dev/null | head -n 1)"
fi

if [ -n "$FINDINGS" ]; then
  echo "[OK] Datos de la auditoria: $FINDINGS"
  echo "[INFO] Para generar el informe HTML desde Linux o Windows:"
  echo "       pwsh -File report/Build-Report.ps1 -EvidenceDir \"$(dirname "$FINDINGS")\""
else
  echo "[WARN] No se encontro findings.json. La auditoria no llego a completarse."
fi

[ -n "$HTML" ] && echo "[OK] Informe HTML: $HTML"

echo ""
printf "Pulse Enter para cerrar..."
read -r _ 2>/dev/null || true
exit "$RC"
