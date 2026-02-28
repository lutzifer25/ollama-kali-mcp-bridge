# ollama-kali-mcp-bridge

Systemnahe Bridge zwischen Ollama (Agent/LLM) auf macOS und Kali-Tools auf Kali Linux über SSH.

## Ziel

- Kali-Tools nur aus freigegebener Whitelist ausführen
- Endlosläufer verhindern (harte Timeouts + Kill)
- Streaming-Feedback an die KI liefern
- KI kann anhand von `finished`/`error` den nächsten Schritt einleiten

## Features (MVP)

- JSON-Line Protokoll über STDIO (`serve`)
- Einzelaufruf per CLI (`run`)
- SSH-Transport macOS -> Kali
- Tool-Whitelist mit Arg-Limit
- `timeout --signal=TERM --kill-after=5s` auf Kali
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

## Sicherheitsprinzipien

- Keine freien Shell-Kommandos aus der KI
- Nur Whitelist-Tools und begrenzte Args
- Harter Laufzeit-Deckel lokal + remote
- Ausgabe-Limit gegen Speicher-/Token-Explosion

## Nächste Schritte

- MCP-Adapter (`tools/list`, `tools/call`) auf dieses JSON-Line-Protokoll legen
- Retry-Policy + Backoff + Korrelations-IDs erweitern
- Integrationstests gegen echte Kali-VM
