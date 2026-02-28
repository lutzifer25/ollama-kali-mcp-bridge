use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::json;
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
    let mut child = Command::new("ssh")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg(target)
        .arg(remote_command)
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
