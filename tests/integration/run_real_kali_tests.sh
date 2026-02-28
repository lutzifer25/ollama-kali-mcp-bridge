#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"

ENV_FILE="tests/integration/integration.env"
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

if [[ -z "${KALI_HOST:-}" ]]; then
  echo "[ERROR] KALI_HOST ist nicht gesetzt."
  echo "Lege tests/integration/integration.env an (Vorlage: integration.env.example)."
  exit 2
fi

KALI_USER="${KALI_USER:-kali}"
BRIDGE_CONFIG="${BRIDGE_CONFIG:-bridge-config.example.json}"
KALI_TEST_TARGET="${KALI_TEST_TARGET:-$KALI_HOST}"
KALI_TEST_TIMEOUT_SEC="${KALI_TEST_TIMEOUT_SEC:-30}"
KALI_TEST_MAX_OUTPUT_BYTES="${KALI_TEST_MAX_OUTPUT_BYTES:-65536}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERROR] python3 nicht gefunden."
  exit 2
fi

if [[ ! -f "$BRIDGE_CONFIG" ]]; then
  echo "[ERROR] Bridge-Konfiguration nicht gefunden: $BRIDGE_CONFIG"
  exit 2
fi

echo "[INFO] Build bridge binary"
source "$HOME/.cargo/env"
cargo build --release >/dev/null

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

MCP_OUT="$TMP_DIR/mcp_out.jsonl"
MCP_ERR="$TMP_DIR/mcp_err.jsonl"
WF_OUT="$TMP_DIR/wf_out.jsonl"
WF_ERR="$TMP_DIR/wf_err.jsonl"

echo "[INFO] Test 1/3: MCP tools/list"
cargo run --quiet -- mcp-serve --config "$BRIDGE_CONFIG" >"$MCP_OUT" 2>"$MCP_ERR" <<EOF
{"id":1,"method":"initialize"}
{"id":2,"method":"tools/list"}
EOF

python3 - "$MCP_OUT" <<'PY'
import json, sys
path = sys.argv[1]
lines = [json.loads(l) for l in open(path, "r", encoding="utf-8") if l.strip()]
list_resp = next((x for x in lines if x.get("id") == 2), None)
if not list_resp:
    raise SystemExit("[FAIL] tools/list Antwort fehlt")
tools = list_resp.get("result", {}).get("tools", [])
if not tools:
    raise SystemExit("[FAIL] tools/list liefert keine Tools")
print(f"[OK] tools/list liefert {len(tools)} Tools")
PY

echo "[INFO] Test 2/3: MCP tools/call nmap"
cargo run --quiet -- mcp-serve --config "$BRIDGE_CONFIG" >"$MCP_OUT" 2>"$MCP_ERR" <<EOF
{"id":3,"method":"tools/call","params":{"name":"nmap","arguments":{"host":"$KALI_HOST","user":"$KALI_USER","args":["-sn","$KALI_TEST_TARGET"],"timeout_sec":$KALI_TEST_TIMEOUT_SEC,"max_output_bytes":$KALI_TEST_MAX_OUTPUT_BYTES}}}
EOF

python3 - "$MCP_OUT" "$MCP_ERR" <<'PY'
import json, sys
out_path, err_path = sys.argv[1], sys.argv[2]
lines = [json.loads(l) for l in open(out_path, "r", encoding="utf-8") if l.strip()]
resp = next((x for x in lines if x.get("id") == 3), None)
if not resp:
    raise SystemExit("[FAIL] tools/call Antwort fehlt")
if "error" in resp:
    raise SystemExit(f"[FAIL] tools/call error: {resp['error']}")
sc = resp.get("result", {}).get("structuredContent", {})
if "attempts" not in sc:
    raise SystemExit("[FAIL] structuredContent.attempts fehlt")
if "duration_ms" not in sc:
    raise SystemExit("[FAIL] structuredContent.duration_ms fehlt")
if sc.get("attempts", 0) < 1:
    raise SystemExit("[FAIL] attempts < 1")
obs = [json.loads(l) for l in open(err_path, "r", encoding="utf-8") if l.strip().startswith("{")]
if not any(x.get("event") == "attempt_started" for x in obs):
    raise SystemExit("[FAIL] observability event attempt_started fehlt")
print("[OK] tools/call liefert structuredContent + Observability")
PY

echo "[INFO] Test 3/3: workflow-serve one-step"
cargo run --quiet -- workflow-serve --config "$BRIDGE_CONFIG" >"$WF_OUT" 2>"$WF_ERR" <<EOF
{"id":"wf-int-1","host":"$KALI_HOST","user":"$KALI_USER","stop_on_error":true,"steps":[{"tool":"nmap","args":["-sn","$KALI_TEST_TARGET"],"timeout_sec":$KALI_TEST_TIMEOUT_SEC,"max_output_bytes":$KALI_TEST_MAX_OUTPUT_BYTES}]}
EOF

python3 - "$WF_OUT" <<'PY'
import json, sys
path = sys.argv[1]
lines = [json.loads(l) for l in open(path, "r", encoding="utf-8") if l.strip()]
events = [x.get("event") for x in lines]
if "workflow_started" not in events:
    raise SystemExit("[FAIL] workflow_started fehlt")
if "step_started" not in events:
    raise SystemExit("[FAIL] step_started fehlt")
if "workflow_finished" not in events:
    raise SystemExit("[FAIL] workflow_finished fehlt")
print("[OK] workflow events vollständig")
PY

echo "[PASS] Alle Integrationstests erfolgreich"
