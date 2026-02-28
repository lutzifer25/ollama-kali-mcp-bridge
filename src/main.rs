use std::collections::HashMap;
use std::time::SystemTime;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

#[derive(Parser, Debug)]
#[command(version, about = "Ollama ↔ Kali tool bridge over SSH with strict runtime control")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Run(RunArgs),
    Serve(ServeArgs),
    McpServe(ServeArgs),
    WorkflowServe(ServeArgs),
    PrintSchema,
}

#[derive(Args, Debug)]
struct ServeArgs {
    #[arg(long, default_value = "bridge-config.json")]
    config: String,
}

#[derive(Args, Debug)]
struct RunArgs {
    #[arg(long)]
    host: String,
    #[arg(long)]
    user: Option<String>,
    #[arg(long)]
    tool: String,
    #[arg(long)]
    args: Vec<String>,
    #[arg(long)]
    timeout_sec: Option<u64>,
    #[arg(long)]
    max_output_bytes: Option<usize>,
    #[arg(long, default_value = "bridge-config.json")]
    config: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ToolPolicy {
    command: String,
    #[serde(default)]
    default_args: Vec<String>,
    #[serde(default = "default_max_args")]
    max_args: usize,
}

fn default_max_args() -> usize {
    16
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BridgeConfig {
    #[serde(default = "default_timeout")]
    default_timeout_sec: u64,
    #[serde(default = "default_max_timeout")]
    max_timeout_sec: u64,
    #[serde(default = "default_max_output")]
    max_output_bytes: usize,
    #[serde(default = "default_ssh_connect_timeout")]
    ssh_connect_timeout_sec: u64,
    #[serde(default = "default_ssh_server_alive_interval")]
    ssh_server_alive_interval_sec: u64,
    #[serde(default = "default_ssh_server_alive_count_max")]
    ssh_server_alive_count_max: u64,
    #[serde(default = "default_strict_host_key_checking")]
    ssh_strict_host_key_checking: bool,
    #[serde(default = "default_max_retries")]
    max_retries: u32,
    #[serde(default = "default_retry_backoff_ms")]
    retry_backoff_ms: u64,
    #[serde(default = "default_observability_json_logs")]
    observability_json_logs: bool,
    #[serde(default)]
    tools: HashMap<String, ToolPolicy>,
}

fn default_timeout() -> u64 {
    30
}

fn default_max_timeout() -> u64 {
    300
}

fn default_max_output() -> usize {
    128 * 1024
}

fn default_ssh_connect_timeout() -> u64 {
    10
}

fn default_ssh_server_alive_interval() -> u64 {
    15
}

fn default_ssh_server_alive_count_max() -> u64 {
    2
}

fn default_strict_host_key_checking() -> bool {
    true
}

fn default_max_retries() -> u32 {
    1
}

fn default_retry_backoff_ms() -> u64 {
    750
}

fn default_observability_json_logs() -> bool {
    true
}

impl Default for BridgeConfig {
    fn default() -> Self {
        let mut tools = HashMap::new();
        tools.insert(
            "nmap".to_string(),
            ToolPolicy {
                command: "/usr/bin/nmap".to_string(),
                default_args: Vec::new(),
                max_args: 12,
            },
        );
        tools.insert(
            "nikto".to_string(),
            ToolPolicy {
                command: "/usr/bin/nikto".to_string(),
                default_args: Vec::new(),
                max_args: 12,
            },
        );
        tools.insert(
            "sqlmap".to_string(),
            ToolPolicy {
                command: "/usr/bin/sqlmap".to_string(),
                default_args: Vec::new(),
                max_args: 12,
            },
        );
        Self {
            default_timeout_sec: default_timeout(),
            max_timeout_sec: default_max_timeout(),
            max_output_bytes: default_max_output(),
            ssh_connect_timeout_sec: default_ssh_connect_timeout(),
            ssh_server_alive_interval_sec: default_ssh_server_alive_interval(),
            ssh_server_alive_count_max: default_ssh_server_alive_count_max(),
            ssh_strict_host_key_checking: default_strict_host_key_checking(),
            max_retries: default_max_retries(),
            retry_backoff_ms: default_retry_backoff_ms(),
            observability_json_logs: default_observability_json_logs(),
            tools,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RunRequest {
    id: Option<String>,
    host: String,
    user: Option<String>,
    tool: String,
    #[serde(default)]
    args: Vec<String>,
    timeout_sec: Option<u64>,
    max_output_bytes: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
struct WorkflowRequest {
    id: Option<String>,
    host: String,
    user: Option<String>,
    #[serde(default = "default_stop_on_error")]
    stop_on_error: bool,
    steps: Vec<WorkflowStep>,
}

fn default_stop_on_error() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
struct WorkflowStep {
    tool: String,
    #[serde(default)]
    args: Vec<String>,
    timeout_sec: Option<u64>,
    max_output_bytes: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct McpCallParams {
    name: String,
    #[serde(default)]
    arguments: Value,
}

#[derive(Debug, Deserialize)]
struct McpToolArguments {
    host: String,
    user: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    timeout_sec: Option<u64>,
    max_output_bytes: Option<usize>,
}

#[derive(Debug, Serialize)]
struct Event {
    id: String,
    event: String,
    payload: serde_json::Value,
}

#[derive(Debug)]
struct FinalStatus {
    exit_code: Option<i32>,
    timed_out: bool,
    duration_ms: u128,
}

#[derive(Debug)]
struct CollectedRun {
    final_status: FinalStatus,
    stdout: String,
    stderr: String,
    truncated: bool,
    attempts: u32,
}

#[derive(Debug)]
enum Chunk {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run(args) => {
            let config = load_config(&args.config).await?;
            let request = RunRequest {
                id: Some("cli-run".to_string()),
                host: args.host,
                user: args.user,
                tool: args.tool,
                args: args.args,
                timeout_sec: args.timeout_sec,
                max_output_bytes: args.max_output_bytes,
            };
            let mut out = io::stdout();
            run_request(&config, request, &mut out).await?;
        }
        Commands::Serve(args) => {
            let config = load_config(&args.config).await?;
            serve_stdio(&config).await?;
        }
        Commands::McpServe(args) => {
            let config = load_config(&args.config).await?;
            serve_mcp_stdio(&config).await?;
        }
        Commands::WorkflowServe(args) => {
            let config = load_config(&args.config).await?;
            serve_workflow_stdio(&config).await?;
        }
        Commands::PrintSchema => print_schema()?,
    }
    Ok(())
}

async fn load_config(path: &str) -> Result<BridgeConfig> {
    match tokio::fs::read_to_string(path).await {
        Ok(content) => {
            let cfg: BridgeConfig =
                serde_json::from_str(&content).context("config JSON konnte nicht geparst werden")?;
            Ok(cfg)
        }
        Err(_) => Ok(BridgeConfig::default()),
    }
}

async fn serve_stdio(config: &BridgeConfig) -> Result<()> {
    let stdin = io::stdin();
    let mut lines = BufReader::new(stdin).lines();
    let mut out = io::stdout();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<RunRequest>(&line) {
            Ok(request) => {
                if let Err(error) = run_request(config, request, &mut out).await {
                    emit(
                        &mut out,
                        Event {
                            id: "unknown".to_string(),
                            event: "error".to_string(),
                            payload: json!({
                                "code": "E_EXEC",
                                "message": error.to_string()
                            }),
                        },
                    )
                    .await?;
                }
            }
            Err(error) => {
                emit(
                    &mut out,
                    Event {
                        id: "unknown".to_string(),
                        event: "error".to_string(),
                        payload: json!({
                            "code": "E_PARSE",
                            "message": error.to_string()
                        }),
                    },
                )
                .await?;
            }
        }
    }
    Ok(())
}

async fn serve_mcp_stdio(config: &BridgeConfig) -> Result<()> {
    let stdin = io::stdin();
    let mut lines = BufReader::new(stdin).lines();
    let mut out = io::stdout();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        let parsed = serde_json::from_str::<JsonRpcRequest>(&line);
        let request = match parsed {
            Ok(req) => req,
            Err(error) => {
                write_json_line(
                    &mut out,
                    json!({
                        "jsonrpc": "2.0",
                        "id": Value::Null,
                        "error": {
                            "code": -32700,
                            "message": format!("parse error: {}", error)
                        }
                    }),
                )
                .await?;
                continue;
            }
        };

        handle_mcp_request(config, request, &mut out).await?;
    }

    Ok(())
}

async fn handle_mcp_request<W: AsyncWrite + Unpin>(
    config: &BridgeConfig,
    request: JsonRpcRequest,
    writer: &mut W,
) -> Result<()> {
    let id = request.id.unwrap_or(Value::Null);
    match request.method.as_str() {
        "initialize" => {
            write_json_line(
                writer,
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "protocolVersion": "2025-01-01",
                        "capabilities": {
                            "tools": {}
                        },
                        "serverInfo": {
                            "name": "ollama-kali-mcp-bridge",
                            "version": env!("CARGO_PKG_VERSION")
                        }
                    }
                }),
            )
            .await?;
        }
        "tools/list" => {
            let tools = config
                .tools
                .iter()
                .map(|(name, policy)| {
                    json!({
                        "name": name,
                        "description": format!("Executes {} on Kali via SSH with timeout enforcement", policy.command),
                        "inputSchema": {
                            "type": "object",
                            "required": ["host"],
                            "properties": {
                                "host": {"type": "string"},
                                "user": {"type": "string"},
                                "args": {"type": "array", "items": {"type": "string"}},
                                "timeout_sec": {"type": "integer", "minimum": 1},
                                "max_output_bytes": {"type": "integer", "minimum": 1024}
                            }
                        }
                    })
                })
                .collect::<Vec<_>>();

            write_json_line(
                writer,
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {"tools": tools}
                }),
            )
            .await?;
        }
        "tools/call" => {
            let params_value = request.params.unwrap_or_else(|| json!({}));
            let params: McpCallParams = match serde_json::from_value(params_value) {
                Ok(parsed) => parsed,
                Err(error) => {
                    write_json_line(
                        writer,
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": {
                                "code": -32602,
                                "message": format!("invalid params: {}", error)
                            }
                        }),
                    )
                    .await?;
                    return Ok(());
                }
            };

            let arguments: McpToolArguments = match serde_json::from_value(params.arguments) {
                Ok(parsed) => parsed,
                Err(error) => {
                    write_json_line(
                        writer,
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": {
                                "code": -32602,
                                "message": format!("invalid tool arguments: {}", error)
                            }
                        }),
                    )
                    .await?;
                    return Ok(());
                }
            };

            let run = RunRequest {
                id: Some("mcp-call".to_string()),
                host: arguments.host,
                user: arguments.user,
                tool: params.name,
                args: arguments.args,
                timeout_sec: arguments.timeout_sec,
                max_output_bytes: arguments.max_output_bytes,
            };

            let result = execute_request_collect(config, run).await;
            match result {
                Ok(collected) => {
                    let summary = format!(
                        "exit_code={:?}, timed_out={}, duration_ms={}, attempts={}",
                        collected.final_status.exit_code,
                        collected.final_status.timed_out,
                        collected.final_status.duration_ms,
                        collected.attempts
                    );
                    write_json_line(
                        writer,
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [
                                    {"type": "text", "text": summary},
                                    {"type": "text", "text": collected.stdout},
                                    {"type": "text", "text": collected.stderr}
                                ],
                                "isError": collected.final_status.exit_code.unwrap_or(1) != 0 || collected.final_status.timed_out,
                                "structuredContent": {
                                    "exit_code": collected.final_status.exit_code,
                                    "timed_out": collected.final_status.timed_out,
                                    "duration_ms": collected.final_status.duration_ms,
                                    "truncated": collected.truncated,
                                    "attempts": collected.attempts
                                }
                            }
                        }),
                    )
                    .await?;
                }
                Err(error) => {
                    write_json_line(
                        writer,
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": {
                                "code": -32000,
                                "message": error.to_string()
                            }
                        }),
                    )
                    .await?;
                }
            }
        }
        _ => {
            write_json_line(
                writer,
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32601,
                        "message": format!("method not found: {}", request.method)
                    }
                }),
            )
            .await?;
        }
    }

    Ok(())
}

async fn serve_workflow_stdio(config: &BridgeConfig) -> Result<()> {
    let stdin = io::stdin();
    let mut lines = BufReader::new(stdin).lines();
    let mut out = io::stdout();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        let workflow: WorkflowRequest = match serde_json::from_str(&line) {
            Ok(req) => req,
            Err(error) => {
                emit(
                    &mut out,
                    Event {
                        id: "workflow".to_string(),
                        event: "error".to_string(),
                        payload: json!({"code": "E_PARSE", "message": error.to_string()}),
                    },
                )
                .await?;
                continue;
            }
        };

        run_workflow(config, workflow, &mut out).await?;
    }

    Ok(())
}

async fn run_workflow<W: AsyncWrite + Unpin>(
    config: &BridgeConfig,
    workflow: WorkflowRequest,
    writer: &mut W,
) -> Result<()> {
    let id = workflow.id.unwrap_or_else(|| "workflow".to_string());
    let stop_on_error = workflow.stop_on_error;
    let mut last_status = json!({"state": "empty"});

    emit(
        writer,
        Event {
            id: id.clone(),
            event: "workflow_started".to_string(),
            payload: json!({"steps": workflow.steps.len()}),
        },
    )
    .await?;

    for (index, step) in workflow.steps.iter().enumerate() {
        emit(
            writer,
            Event {
                id: id.clone(),
                event: "step_started".to_string(),
                payload: json!({"index": index, "tool": step.tool}),
            },
        )
        .await?;

        let run = RunRequest {
            id: Some(format!("{}-step-{}", id, index)),
            host: workflow.host.clone(),
            user: workflow.user.clone(),
            tool: step.tool.clone(),
            args: step.args.clone(),
            timeout_sec: step.timeout_sec,
            max_output_bytes: step.max_output_bytes,
        };

        let collected = execute_request_collect(config, run).await;
        match collected {
            Ok(result) => {
                let failed = result.final_status.timed_out || result.final_status.exit_code.unwrap_or(1) != 0;
                last_status = json!({
                    "index": index,
                    "exit_code": result.final_status.exit_code,
                    "timed_out": result.final_status.timed_out,
                    "duration_ms": result.final_status.duration_ms,
                    "truncated": result.truncated,
                    "attempts": result.attempts,
                    "stdout_preview": result.stdout.chars().take(240).collect::<String>(),
                    "stderr_preview": result.stderr.chars().take(240).collect::<String>()
                });

                emit(
                    writer,
                    Event {
                        id: id.clone(),
                        event: "step_finished".to_string(),
                        payload: last_status.clone(),
                    },
                )
                .await?;

                if failed && stop_on_error {
                    break;
                }
            }
            Err(error) => {
                last_status = json!({
                    "index": index,
                    "error": error.to_string()
                });
                emit(
                    writer,
                    Event {
                        id: id.clone(),
                        event: "step_failed".to_string(),
                        payload: last_status.clone(),
                    },
                )
                .await?;

                if stop_on_error {
                    break;
                }
            }
        }
    }

    emit(
        writer,
        Event {
            id,
            event: "workflow_finished".to_string(),
            payload: last_status,
        },
    )
    .await?;

    Ok(())
}

async fn run_request<W: AsyncWrite + Unpin>(
    config: &BridgeConfig,
    request: RunRequest,
    writer: &mut W,
) -> Result<FinalStatus> {
    let id = request.id.unwrap_or_else(|| "request".to_string());
    let policy = config
        .tools
        .get(&request.tool)
        .ok_or_else(|| anyhow!("tool '{}' ist nicht freigegeben", request.tool))?;

    if request.args.len() > policy.max_args {
        bail!(
            "zu viele args für tool '{}': {} > {}",
            request.tool,
            request.args.len(),
            policy.max_args
        );
    }

    let timeout_sec = request
        .timeout_sec
        .unwrap_or(config.default_timeout_sec)
        .min(config.max_timeout_sec);
    let max_output_bytes = request.max_output_bytes.unwrap_or(config.max_output_bytes);
    let target = format_target(&request.user, &request.host);

    log_observation(
        config,
        "stream_run_started",
        json!({
            "correlation_id": id.clone(),
            "tool": request.tool.clone(),
            "target": target.clone(),
            "timeout_sec": timeout_sec,
            "max_output_bytes": max_output_bytes
        }),
    );

    emit(
        writer,
        Event {
            id: id.clone(),
            event: "started".to_string(),
            payload: json!({
                "target": target,
                "tool": request.tool,
                "timeout_sec": timeout_sec,
                "max_output_bytes": max_output_bytes
            }),
        },
    )
    .await?;

    let remote_command = build_remote_command(policy, &request.args, timeout_sec);
    let mut child = build_ssh_command(config, &target, &remote_command)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("SSH-Prozess konnte nicht gestartet werden")?;

    let stdout = child.stdout.take().context("stdout pipe fehlt")?;
    let stderr = child.stderr.take().context("stderr pipe fehlt")?;
    let (tx, mut rx) = mpsc::channel::<Chunk>(64);

    let tx_out = tx.clone();
    let out_task = tokio::spawn(async move {
        let mut reader = BufReader::new(stdout);
        let mut buf = [0_u8; 4096];
        loop {
            let read = reader.read(&mut buf).await?;
            if read == 0 {
                break;
            }
            if tx_out.send(Chunk::Stdout(buf[..read].to_vec())).await.is_err() {
                break;
            }
        }
        Result::<()>::Ok(())
    });

    let err_task = tokio::spawn(async move {
        let mut reader = BufReader::new(stderr);
        let mut buf = [0_u8; 4096];
        loop {
            let read = reader.read(&mut buf).await?;
            if read == 0 {
                break;
            }
            if tx.send(Chunk::Stderr(buf[..read].to_vec())).await.is_err() {
                break;
            }
        }
        Result::<()>::Ok(())
    });

    let started = Instant::now();
    let deadline = started + Duration::from_secs(timeout_sec);

    let mut process_done = false;
    let mut timed_out = false;
    let mut exit_code = None;
    let mut written_bytes = 0_usize;
    let mut truncated = false;

    while !process_done || !rx.is_closed() {
        tokio::select! {
            chunk = rx.recv() => {
                if let Some(chunk) = chunk {
                    let (event_name, bytes) = match chunk {
                        Chunk::Stdout(data) => ("stdout_chunk", data),
                        Chunk::Stderr(data) => ("stderr_chunk", data),
                    };

                    if written_bytes < max_output_bytes {
                        let remaining = max_output_bytes - written_bytes;
                        let part = if bytes.len() > remaining { &bytes[..remaining] } else { &bytes[..] };
                        written_bytes += part.len();
                        let text = String::from_utf8_lossy(part).to_string();
                        emit(
                            writer,
                            Event {
                                id: id.clone(),
                                event: event_name.to_string(),
                                payload: json!({"data": text}),
                            },
                        ).await?;
                    } else if !truncated {
                        truncated = true;
                        emit(
                            writer,
                            Event {
                                id: id.clone(),
                                event: "output_truncated".to_string(),
                                payload: json!({"max_output_bytes": max_output_bytes}),
                            },
                        ).await?;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)), if !process_done => {
                if let Some(status) = child.try_wait().context("Statusprüfung des SSH-Prozesses fehlgeschlagen")? {
                    exit_code = status.code();
                    process_done = true;
                } else if Instant::now() >= deadline {
                    timed_out = true;
                    let _ = child.kill().await;
                    let status = child.wait().await.context("Timeout und kill fehlgeschlagen")?;
                    exit_code = status.code();
                    process_done = true;
                }
            }
            else => {
                if process_done {
                    break;
                }
            }
        }
    }

    out_task.await.context("stdout task join fehlgeschlagen")??;
    err_task.await.context("stderr task join fehlgeschlagen")??;

    let final_status = FinalStatus {
        exit_code,
        timed_out,
        duration_ms: started.elapsed().as_millis(),
    };

    log_observation(
        config,
        "stream_run_finished",
        json!({
            "correlation_id": id.clone(),
            "exit_code": final_status.exit_code,
            "timed_out": final_status.timed_out,
            "duration_ms": final_status.duration_ms
        }),
    );

    emit(
        writer,
        Event {
            id,
            event: "finished".to_string(),
            payload: json!({
                "exit_code": final_status.exit_code,
                "timed_out": final_status.timed_out,
                "duration_ms": final_status.duration_ms,
                "next_action_hint": if final_status.timed_out { "reduce scope or increase timeout" } else { "analyze output and schedule next tool" }
            }),
        },
    )
    .await?;

    Ok(final_status)
}

async fn execute_request_collect(config: &BridgeConfig, request: RunRequest) -> Result<CollectedRun> {
    let correlation_id = request.id.clone().unwrap_or_else(|| "request".to_string());
    let max_attempts = config.max_retries.saturating_add(1);
    let mut attempt: u32 = 1;

    loop {
        log_observation(
            config,
            "attempt_started",
            json!({
                "correlation_id": correlation_id.clone(),
                "attempt": attempt,
                "max_attempts": max_attempts,
                "tool": request.tool.clone(),
                "host": request.host.clone()
            }),
        );

        match execute_request_collect_once(config, request.clone()).await {
            Ok(mut collected) => {
                collected.attempts = attempt;
                let success = run_success(&collected.final_status);

                log_observation(
                    config,
                    "attempt_finished",
                    json!({
                        "correlation_id": correlation_id.clone(),
                        "attempt": attempt,
                        "success": success,
                        "exit_code": collected.final_status.exit_code,
                        "timed_out": collected.final_status.timed_out,
                        "duration_ms": collected.final_status.duration_ms,
                        "truncated": collected.truncated
                    }),
                );

                if success || attempt >= max_attempts {
                    return Ok(collected);
                }

                let backoff_ms = config.retry_backoff_ms.saturating_mul(attempt as u64);
                log_observation(
                    config,
                    "retry_scheduled",
                    json!({
                        "correlation_id": correlation_id.clone(),
                        "attempt": attempt,
                        "next_attempt": attempt + 1,
                        "backoff_ms": backoff_ms
                    }),
                );
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }
            Err(error) => {
                let message = error.to_string();
                log_observation(
                    config,
                    "attempt_error",
                    json!({
                        "correlation_id": correlation_id.clone(),
                        "attempt": attempt,
                        "message": message
                    }),
                );

                if attempt >= max_attempts {
                    return Err(error);
                }

                let backoff_ms = config.retry_backoff_ms.saturating_mul(attempt as u64);
                log_observation(
                    config,
                    "retry_scheduled",
                    json!({
                        "correlation_id": correlation_id.clone(),
                        "attempt": attempt,
                        "next_attempt": attempt + 1,
                        "backoff_ms": backoff_ms
                    }),
                );
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }
        }

        attempt = attempt.saturating_add(1);
    }
}

async fn execute_request_collect_once(config: &BridgeConfig, request: RunRequest) -> Result<CollectedRun> {
    let policy = config
        .tools
        .get(&request.tool)
        .ok_or_else(|| anyhow!("tool '{}' ist nicht freigegeben", request.tool))?;

    if request.args.len() > policy.max_args {
        bail!(
            "zu viele args für tool '{}': {} > {}",
            request.tool,
            request.args.len(),
            policy.max_args
        );
    }

    let timeout_sec = request
        .timeout_sec
        .unwrap_or(config.default_timeout_sec)
        .min(config.max_timeout_sec);
    let max_output_bytes = request.max_output_bytes.unwrap_or(config.max_output_bytes);
    let target = format_target(&request.user, &request.host);
    let remote_command = build_remote_command(policy, &request.args, timeout_sec);

    let mut child = build_ssh_command(config, &target, &remote_command)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("SSH-Prozess konnte nicht gestartet werden")?;

    let stdout = child.stdout.take().context("stdout pipe fehlt")?;
    let stderr = child.stderr.take().context("stderr pipe fehlt")?;
    let (tx, mut rx) = mpsc::channel::<Chunk>(64);

    let tx_out = tx.clone();
    let out_task = tokio::spawn(async move {
        let mut reader = BufReader::new(stdout);
        let mut buf = [0_u8; 4096];
        loop {
            let read = reader.read(&mut buf).await?;
            if read == 0 {
                break;
            }
            if tx_out.send(Chunk::Stdout(buf[..read].to_vec())).await.is_err() {
                break;
            }
        }
        Result::<()>::Ok(())
    });

    let err_task = tokio::spawn(async move {
        let mut reader = BufReader::new(stderr);
        let mut buf = [0_u8; 4096];
        loop {
            let read = reader.read(&mut buf).await?;
            if read == 0 {
                break;
            }
            if tx.send(Chunk::Stderr(buf[..read].to_vec())).await.is_err() {
                break;
            }
        }
        Result::<()>::Ok(())
    });

    let started = Instant::now();
    let deadline = started + Duration::from_secs(timeout_sec);
    let mut process_done = false;
    let mut timed_out = false;
    let mut exit_code = None;
    let mut written_bytes = 0_usize;
    let mut truncated = false;
    let mut stdout_text = String::new();
    let mut stderr_text = String::new();

    while !process_done || !rx.is_closed() {
        tokio::select! {
            chunk = rx.recv() => {
                if let Some(chunk) = chunk {
                    if written_bytes >= max_output_bytes {
                        truncated = true;
                        continue;
                    }

                    let (data, is_stdout) = match chunk {
                        Chunk::Stdout(bytes) => (bytes, true),
                        Chunk::Stderr(bytes) => (bytes, false),
                    };
                    let remaining = max_output_bytes - written_bytes;
                    let part = if data.len() > remaining { &data[..remaining] } else { &data[..] };
                    written_bytes += part.len();
                    if part.len() < data.len() {
                        truncated = true;
                    }
                    let text = String::from_utf8_lossy(part).to_string();
                    if is_stdout {
                        stdout_text.push_str(&text);
                    } else {
                        stderr_text.push_str(&text);
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)), if !process_done => {
                if let Some(status) = child.try_wait().context("Statusprüfung des SSH-Prozesses fehlgeschlagen")? {
                    exit_code = status.code();
                    process_done = true;
                } else if Instant::now() >= deadline {
                    timed_out = true;
                    let _ = child.kill().await;
                    let status = child.wait().await.context("Timeout und kill fehlgeschlagen")?;
                    exit_code = status.code();
                    process_done = true;
                }
            }
            else => {
                if process_done {
                    break;
                }
            }
        }
    }

    out_task.await.context("stdout task join fehlgeschlagen")??;
    err_task.await.context("stderr task join fehlgeschlagen")??;

    Ok(CollectedRun {
        final_status: FinalStatus {
            exit_code,
            timed_out,
            duration_ms: started.elapsed().as_millis(),
        },
        stdout: stdout_text,
        stderr: stderr_text,
        truncated,
        attempts: 1,
    })
}

fn run_success(status: &FinalStatus) -> bool {
    !status.timed_out && status.exit_code.unwrap_or(1) == 0
}

fn log_observation(config: &BridgeConfig, event: &str, payload: Value) {
    if !config.observability_json_logs {
        return;
    }
    let timestamp_ms = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or(0);
    let line = json!({
        "ts_ms": timestamp_ms,
        "event": event,
        "payload": payload
    });
    eprintln!("{}", line);
}

fn build_remote_command(policy: &ToolPolicy, args: &[String], timeout_sec: u64) -> String {
    let mut full_args = Vec::new();
    full_args.push(policy.command.clone());
    full_args.extend(policy.default_args.iter().cloned());
    full_args.extend(args.iter().cloned());
    let escaped = full_args
        .iter()
        .map(|part| shell_escape(part))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "timeout --signal=TERM --kill-after=5s {}s {}",
        timeout_sec, escaped
    )
}

fn build_ssh_command(config: &BridgeConfig, target: &str, remote_command: &str) -> Command {
    let mut command = Command::new("ssh");
    command
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg(format!("ConnectTimeout={}", config.ssh_connect_timeout_sec))
        .arg("-o")
        .arg(format!(
            "ServerAliveInterval={}",
            config.ssh_server_alive_interval_sec
        ))
        .arg("-o")
        .arg(format!(
            "ServerAliveCountMax={}",
            config.ssh_server_alive_count_max
        ))
        .arg("-o")
        .arg(format!(
            "StrictHostKeyChecking={}",
            if config.ssh_strict_host_key_checking {
                "yes"
            } else {
                "no"
            }
        ))
        .arg(target)
        .arg(remote_command);
    command
}

fn shell_escape(input: &str) -> String {
    if input.is_empty() {
        return "''".to_string();
    }
    let escaped = input.replace('\'', "'\\''");
    format!("'{}'", escaped)
}

fn format_target(user: &Option<String>, host: &str) -> String {
    match user {
        Some(user) => format!("{}@{}", user, host),
        None => host.to_string(),
    }
}

async fn emit<W: AsyncWrite + Unpin>(writer: &mut W, event: Event) -> Result<()> {
    let line = serde_json::to_string(&event)?;
    writer.write_all(line.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

async fn write_json_line<W: AsyncWrite + Unpin>(writer: &mut W, value: Value) -> Result<()> {
    let line = serde_json::to_string(&value)?;
    writer.write_all(line.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

fn print_schema() -> Result<()> {
    let schema = json!({
      "request": {
        "id": "string(optional)",
        "host": "kali-host-or-ip",
        "user": "optional-ssh-user",
        "tool": "whitelisted-tool-name",
        "args": ["arg1", "arg2"],
        "timeout_sec": 30,
        "max_output_bytes": 131072
      },
      "events": [
        "started",
        "stdout_chunk",
        "stderr_chunk",
        "output_truncated",
        "finished",
        "error"
      ]
    });
    println!("{}", serde_json::to_string_pretty(&schema)?);
    Ok(())
}
