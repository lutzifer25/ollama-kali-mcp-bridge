# Integration Tests (echte Kali-Tools)

Diese Tests führen die Bridge gegen eine echte Kali-Instanz aus.

## Vorbereitung

1. SSH-Key Login macOS -> Kali sicherstellen.
2. Auf Kali müssen freigegebene Tools installiert sein (mind. `nmap`).
3. Datei `integration.env` erzeugen:

```bash
cp tests/integration/integration.env.example tests/integration/integration.env
# Werte anpassen
```

## Ausführen

```bash
bash tests/integration/run_real_kali_tests.sh
```

## Was wird geprüft

- MCP `tools/list` liefert Tool-Liste
- MCP `tools/call` führt `nmap` aus und liefert `structuredContent` inkl. `attempts`
- Workflow-Modus liefert `workflow_finished`
- Observability-Events auf `stderr` (z. B. `attempt_started`, `attempt_finished`)

## Hinweise

- Der Test ist absichtlich begrenzt: Timeouts werden immer mitgegeben.
- Wenn SSH/Kali nicht erreichbar ist, schlägt der Test mit klarer Fehlermeldung fehl.
