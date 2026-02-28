# ollama-kali-mcp-bridge

Systemnahe Bridge zwischen Ollama (Agent/LLM) auf macOS und Kali-Tools auf Kali Linux über SSH.

## Ziel

- Kali-Tools nur aus freigegebener Whitelist ausführen
- Endlosläufer verhindern (harte Timeouts + Kill)
- Streaming-Feedback an die KI liefern
- KI kann anhand von `finished`/`error` den nächsten Schritt einleiten

## Features

- JSON-Line Protokoll über STDIO (`serve`)
- MCP JSON-RPC Endpoint über STDIO (`mcp-serve`) mit `tools/list` und `tools/call`
- Workflow-State-Machine über STDIO (`workflow-serve`) für Mehrschritt-Ausführung
- Einzelaufruf per CLI (`run`)
- SSH-Transport macOS -> Kali
- Tool-Whitelist mit Arg-Limit
- `timeout --signal=TERM --kill-after=5s` auf Kali
- SSH-Härtung: `ConnectTimeout`, `ServerAliveInterval`, `ServerAliveCountMax`, `StrictHostKeyChecking`
- Retry-Policy mit Backoff für MCP/Workflow-Ausführungen
- JSON-Observability-Logs auf `stderr` (korrelationsfähig)
- Strukturierte Events: `started`, `stdout_chunk`, `stderr_chunk`, `output_truncated`, `finished`, `error`

## Voraussetzungen

- macOS: `ssh`, Rust Toolchain
- Kali: freigegebene Tools installiert (z. B. `nmap`, `nikto`, `sqlmap`)
- SSH-Key-Login von macOS nach Kali
- Auf Kali: GNU `timeout` (coreutils)

## Build

```bash
cargo build --release
```

## Konfiguration

Datei `bridge-config.json` (optional). Wenn nicht vorhanden, wird eine sichere Default-Konfiguration geladen.

Beispiel siehe `bridge-config.example.json`.

## Verwendung

### 1) Schema anzeigen

```bash
cargo run -- print-schema
```

### 2) Einmaliger Tool-Run

```bash
cargo run -- run \
  --host 192.168.178.70 \
  --user kali \
  --tool nmap \
  --args -sn --args 192.168.178.0/24 \
  --timeout-sec 40
```

### 3) Serve-Modus für Ollama-Agent

```bash
cargo run -- serve --config bridge-config.json
```

Dann pro Zeile ein JSON-Request an `stdin` senden:

```json
{"id":"step-1","host":"192.168.178.70","user":"kali","tool":"nmap","args":["-sn","192.168.178.0/24"],"timeout_sec":40}
```

Antwort sind JSON-Events zeilenweise auf `stdout`.

### 4) MCP-Serve (`tools/list`, `tools/call`)

```bash
cargo run -- mcp-serve --config bridge-config.json
```

Beispiel `tools/list` Request:

```json
{"id":1,"method":"tools/list"}
```

Beispiel `tools/call` Request:

```json
{"id":2,"method":"tools/call","params":{"name":"nmap","arguments":{"host":"192.168.178.70","user":"kali","args":["-sn","192.168.178.0/24"],"timeout_sec":40}}}
```

### 5) Workflow-State-Machine (Mehrschritt)

```bash
cargo run -- workflow-serve --config bridge-config.json
```

Workflow-Request (eine Zeile JSON):

```json
{"id":"wf-1","host":"192.168.178.70","user":"kali","stop_on_error":true,"steps":[{"tool":"nmap","args":["-sn","192.168.178.0/24"],"timeout_sec":40},{"tool":"nikto","args":["-h","http://192.168.178.10"],"timeout_sec":60}]}
```

Antwort-Events: `workflow_started`, `step_started`, `step_finished`, `step_failed`, `workflow_finished`.

`step_finished` enthält zusätzlich `attempts`, damit die KI Retry-Verläufe auswerten kann.

## Observability und Retry-Policy

Zusätzliche Konfigurationsfelder in `bridge-config.json`:

- `max_retries`: Anzahl Wiederholungen nach fehlgeschlagenem Attempt (Timeout/Exit != 0 oder Laufzeitfehler)
- `retry_backoff_ms`: linearer Backoff in Millisekunden (`attempt * retry_backoff_ms`)
- `observability_json_logs`: schreibt strukturierte Logs nach `stderr`

Beispiel-Logzeile:

```json
{"ts_ms":1740770600123,"event":"retry_scheduled","payload":{"correlation_id":"mcp-call","attempt":1,"next_attempt":2,"backoff_ms":750}}
```

## Sicherheitsprinzipien

- Keine freien Shell-Kommandos aus der KI
- Nur Whitelist-Tools und begrenzte Args
- Harter Laufzeit-Deckel lokal + remote
- Ausgabe-Limit gegen Speicher-/Token-Explosion

## Nächste Schritte

- Retry-Policy + Backoff + Korrelations-IDs erweitern
- Integrationstests gegen echte Kali-VM
