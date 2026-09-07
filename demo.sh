#!/usr/bin/env bash
set -euo pipefail

IFACE="${1:-wlp0s20f3}"
DURATION="${2:-1800}"
DB="./demo-netwatch.db"

NC_BIN="$(command -v netwatch)"
NC_PATH="$(python -c 'import sys; print(":".join(sys.path))')"

run_capture() {
  if [ "$(id -u)" = "0" ]; then
    # already root: plain
    netwatch capture start -i "$IFACE" --duration "${DURATION}s" --db "$DB"
  elif sudo -n true 2>/dev/null; then
    # sudo available without password: run with user's module paths
    echo "  (captura exige root — usando sudo)"
    sudo PYTHONPATH="$NC_PATH" "$NC_BIN" capture start -i "$IFACE" --duration "${DURATION}s" --db "/tmp/demo-netwatch.db"
    sudo chown "$(id -u):$(id -g)" /tmp/demo-netwatch.db* 2>/dev/null || true
    cp -f /tmp/demo-netwatch.db "$DB"
    sudo rm -f /tmp/demo-netwatch.db* /root/.netwatch/capture.status 2>/dev/null || true
  else
    echo "ERRO: captura ao vivo exige root/CAP_NET_RAW. Sem permissão sudo sem senha." >&2
    echo "  Opção 1: rodar com 'sudo ./demo.sh'" >&2
    echo "  Opção 2: adicionar CAP_NET_RAW: sudo setcap cap_net_raw+ep $NC_BIN" >&2
    exit 1
  fi
}

echo "=== NetWatch Demo ==="
echo ""

echo "[1/3] Capturando ${DURATION}s na interface $IFACE ..."
run_capture
echo ""

echo "[2/3] Resultados:"
echo ""

echo "--- devices list ---"
netwatch devices list --db "$DB"
echo ""

echo "--- flows list ---"
netwatch flows list --db "$DB"
echo ""

echo "--- flows list (externos) ---"
netwatch flows list --external-only --db "$DB"
echo ""

echo "--- summary ---"
netwatch summary --db "$DB"
echo ""

echo "--- export (JSON) ---"
netwatch export --format json --db "$DB"
echo ""

echo "--- config ---"
netwatch config --db "$DB"
echo ""

echo "[3/3] Limpando ..."
rm -f "$DB" "$DB-wal" "$DB-shm"
echo "Feito."
