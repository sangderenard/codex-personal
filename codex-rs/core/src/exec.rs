#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::BufReader;
use tokio::process::Child;
use tokio::process::Command;
use tokio::sync::Notify;

use translation::{DEFAULT_TRANSLATOR, OPERATING_SHELL, initialize};
use translation::command_translation::normalize_path;

use crate::error::CodexErr;
use crate::error::Result;
use crate::error::SandboxErr;
use crate::protocol::SandboxPolicy;
use crate::safety::detect_windows_shell;

use crate::api::{accept_with_retries, send_payload};
pub use crate::black_box::black_box::spawn_command_under_black_box;
pub use crate::black_box::black_box::{
    CODEX_BLACK_BOX_SANDBOX_STATE,
    enable_black_box_sandbox,
    disable_black_box_sandbox,
};
use crate::utils::spawn_wrapper::wrap_spawn_result;
use internal_commands::is_internal_command;


// Maximum we send for each stream, which is either:
// - 10KiB OR
// - 256 lines
const MAX_STREAM_OUTPUT: usize = 10 * 1024;
const MAX_STREAM_OUTPUT_LINES: usize = 256;

const DEFAULT_TIMEOUT_MS: u64 = 10_000;


// Hardcode these since it does not seem worth including the libc crate just
// for these.
const SIGKILL_CODE: i32 = 9;
const TIMEOUT_CODE: i32 = 64;

/// Prime factors used to communicate API sandbox failure states.
pub const API_HANDSHAKE_FAILURE: i32 = 2;
pub const API_PAYLOAD_FAILURE: i32 = 3;
pub const API_SPAWN_FAILURE: i32 = 5;

const MACOS_SEATBELT_BASE_POLICY: &str = include_str!("seatbelt_base_policy.sbpl");

/// When working with `sandbox-exec`, only consider `sandbox-exec` in `/usr/bin`
/// to defend against an attacker trying to inject a malicious version on the
/// PATH. If /usr/bin/sandbox-exec has been tampered with, then the attacker
/// already has root access.
const MACOS_PATH_TO_SEATBELT_EXECUTABLE: &str = "/usr/bin/sandbox-exec";

/// Experimental environment variable that will be set to some non-empty value
/// if both of the following are true:
///
/// 1. The process was spawned by Codex as part of a shell tool call.
/// 2. SandboxPolicy.has_full_network_access() was false for the tool call.
///
/// We may try to have just one environment variable for all sandboxing
/// attributes, so this may change in the future.
pub const CODEX_SANDBOX_NETWORK_DISABLED_ENV_VAR: &str = "CODEX_SANDBOX_NETWORK_DISABLED";

/// Integer constants representing sandbox states.
pub const CODEX_API_SANDBOX_STATE: i32 = 1;
pub const CODEX_WINDOWS_CMD_SANDBOX_STATE: i32 = 2;
pub const CODEX_WINDOWS_PS_SANDBOX_STATE: i32 = 3;
pub const CODEX_LINUX_SHELL_SANDBOX_STATE: i32 = 4;
pub const CODEX_MACOS_SANDBOX_STATE: i32 = 5;

/// Global variables to toggle API and Black Box states.
static mut API_SANDBOX_ENABLED: bool = false;
use crate::black_box::black_box::BLACK_BOX_SANDBOX_ENABLED;

/// Function to determine the active sandbox state.
pub fn determine_sandbox_state() -> i32 {
    unsafe {
        if API_SANDBOX_ENABLED {
            CODEX_API_SANDBOX_STATE
        } else if BLACK_BOX_SANDBOX_ENABLED {
            CODEX_BLACK_BOX_SANDBOX_STATE
        } else if cfg!(target_os = "windows") {
            match detect_windows_shell().as_str() {
                "cmd" => CODEX_WINDOWS_CMD_SANDBOX_STATE,
                "powershell" => CODEX_WINDOWS_PS_SANDBOX_STATE,
                "wsl" | "bash for windows" => CODEX_LINUX_SHELL_SANDBOX_STATE,
                _ => CODEX_BLACK_BOX_SANDBOX_STATE,
            }
        } else if cfg!(target_os = "linux") {
            CODEX_LINUX_SHELL_SANDBOX_STATE
        } else if cfg!(target_os = "macos") {
            CODEX_MACOS_SANDBOX_STATE
        } else {
            CODEX_BLACK_BOX_SANDBOX_STATE
        }
    }
}

/// Functions to toggle API and Black Box states.
pub fn enable_api_sandbox() {
    unsafe {
        API_SANDBOX_ENABLED = true;
    }
}

pub fn disable_api_sandbox() {
    unsafe {
        API_SANDBOX_ENABLED = false;
    }
}


#[derive(Debug, Clone)]
pub struct ExecParams {
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub timeout_ms: Option<u64>,
    pub env: HashMap<String, String>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SandboxType {
    None,

    /// Not implemented yet, similar to API but internal to this codebase.
    BlackBox,

    /// Only available on macOS.
    MacosSeatbelt,

    /// Only available on Linux.
    LinuxSeccomp,

    /// Windows CMD shell sandbox.
    Win64Cmd,

    /// Windows PowerShell sandbox.
    Win64Ps,

    /// API sandbox agnostic to platform.
    Api,
}

pub async fn process_exec_tool_call(
    params: ExecParams,
    sandbox_type: SandboxType,
    ctrl_c: Arc<Notify>,
    sandbox_policy: &SandboxPolicy,
    codex_linux_sandbox_exe: &Option<PathBuf>,
    threat_info: &str,
    threat_weights: &[f64],
) -> Result<ExecToolCallOutput> {
    let start = Instant::now();

    if DEFAULT_TRANSLATOR.get().is_none() {
        initialize(std::env::consts::OS);
    }
    let translation_result = {
        let mut guard = DEFAULT_TRANSLATOR
            .get()
            .expect("translator initialized")
            .lock()
            .expect("lock translator");
        let shell = OPERATING_SHELL
            .get()
            .map(String::as_str)
            .unwrap_or(std::env::consts::OS);
        guard.translate_command(&params.command[0], shell, threat_info, threat_weights)
    };

    let mut params = params;
    let translated_or_original = translation_result.translated_command.as_ref().map(|s| s.clone()).unwrap_or_else(|| params.command[0].clone());
    params.command[0] = translated_or_original;
    
    let mut sandbox_type = sandbox_type;
    if is_internal_command(params.command[0].as_str()) || CODEX_BLACK_BOX_SANDBOX_STATE == determine_sandbox_state() {
        sandbox_type = SandboxType::BlackBox;
    }

    let raw_output_result = match sandbox_type {
        SandboxType::None => exec(params, sandbox_policy, ctrl_c, Some(translation_result.clone())).await,
        SandboxType::BlackBox => {
            Ok(RawExecToolCallOutput {
                exit_status: synthetic_exit_status(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
                translation_result: Some(translation_result.clone()),
            })
        }
        SandboxType::MacosSeatbelt => {
            let ExecParams {
                command,
                cwd,
                timeout_ms,
                env,
            } = params;
            let (child, translation_result) = spawn_command_under_seatbelt(
                command,
                sandbox_policy,
                cwd,
                StdioPolicy::RedirectForShellTool,
                env,
                Some(translation_result.clone()),
            )
            .await?;
            consume_truncated_output(child, ctrl_c, timeout_ms, translation_result).await
        }
        SandboxType::LinuxSeccomp => {
            let ExecParams {
                command,
                cwd,
                timeout_ms,
                env,
            } = params;

            let codex_linux_sandbox_exe = codex_linux_sandbox_exe
                .as_ref()
                .ok_or(CodexErr::LandlockSandboxExecutableNotProvided)?;
            let (child, translation_result) = spawn_command_under_linux_sandbox(
                codex_linux_sandbox_exe,
                command,
                sandbox_policy,
                cwd,
                StdioPolicy::RedirectForShellTool,
                env,
                Some(translation_result.clone()),
            )
            .await?;

            consume_truncated_output(child, ctrl_c, timeout_ms, translation_result).await
        }
        SandboxType::Win64Cmd => {
            let ExecParams {
                command,
                cwd,
                timeout_ms,
                env,
            } = params;

            let (child, translation_result) = spawn_command_under_win64_cmd(
                command,
                sandbox_policy,
                cwd,
                StdioPolicy::RedirectForShellTool,
                env,
                Some(translation_result.clone()),
            )
            .await?;

            consume_truncated_output(child, ctrl_c, timeout_ms, translation_result).await
        }
        SandboxType::Win64Ps => {
            let ExecParams {
                command,
                cwd,
                timeout_ms,
                env,
            } = params;

            let (child, translation_result) = spawn_command_under_win64_ps(
                command,
                sandbox_policy,
                cwd,
                StdioPolicy::RedirectForShellTool,
                env,
                Some(translation_result.clone()),
            )
            .await?;

            consume_truncated_output(child, ctrl_c, timeout_ms, translation_result).await
        }
        SandboxType::Api => {
            let ExecParams {
                command,
                cwd,
                timeout_ms,
                env,
            } = params;

            spawn_command_under_api(
                command,
                sandbox_policy,
                cwd,
                StdioPolicy::RedirectForShellTool,
                env,
                timeout_ms,
                Some(translation_result.clone()),
            )
            .await
        }
    };
    let duration = start.elapsed();
    match raw_output_result {
        Ok(raw_output) => {
            let stdout = String::from_utf8_lossy(&raw_output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&raw_output.stderr).to_string();

            #[cfg(target_family = "unix")]
            match raw_output.exit_status.signal() {
                Some(TIMEOUT_CODE) => return Err(CodexErr::Sandbox(SandboxErr::Timeout)),
                Some(signal) => {
                    return Err(CodexErr::Sandbox(SandboxErr::Signal(signal)));
                }
                None => {}
            }

            let exit_code = raw_output.exit_status.code().unwrap_or(-1);

            // NOTE(ragona): This is much less restrictive than the previous check. If we exec
            // a command, and it returns anything other than success, we assume that it may have
            // been a sandboxing error and allow the user to retry. (The user of course may choose
            // not to retry, or in a non-interactive mode, would automatically reject the approval.)
            if exit_code != 0 &&
                !(matches!(sandbox_type, SandboxType::None | SandboxType::BlackBox))
            {
                return Err(CodexErr::Sandbox(SandboxErr::Denied(
                    exit_code, stdout, stderr,
                )));
            }

            Ok(ExecToolCallOutput {
                exit_code,
                stdout,
                stderr,
                duration,
                translation_result: raw_output.translation_result,
            })
        }
        Err(err) => {
            tracing::error!("exec error: {err}");
            Err(err)
        }
    }
}

pub async fn spawn_command_under_seatbelt(
    command: Vec<String>,
    sandbox_policy: &SandboxPolicy,
    cwd: PathBuf,
    stdio_policy: StdioPolicy,
    env: HashMap<String, String>,
    translation_result: Option<translation::command_translation::CommandTranslationResult>,
) -> std::io::Result<(Child, Option<translation::command_translation::CommandTranslationResult>)> {
    let args = create_seatbelt_command_args(command, sandbox_policy, &cwd);
    let arg0 = None;
    wrap_spawn_result(
        spawn_child_async(
            PathBuf::from(MACOS_PATH_TO_SEATBELT_EXECUTABLE),
            args,
            arg0,
            cwd,
            sandbox_policy,
            stdio_policy,
            env,
        ).await,
        translation_result,
    )
}

/// Spawn a shell tool command under the Linux Landlock+seccomp sandbox helper
/// (codex-linux-sandbox).
///
/// Unlike macOS Seatbelt where we directly embed the policy text, the Linux
/// helper accepts a list of `--sandbox-permission`/`-s` flags mirroring the
/// public CLI. We convert the internal [`SandboxPolicy`] representation into
/// the equivalent CLI options.
pub async fn spawn_command_under_linux_sandbox<P>(
    codex_linux_sandbox_exe: P,
    command: Vec<String>,
    sandbox_policy: &SandboxPolicy,
    cwd: PathBuf,
    stdio_policy: StdioPolicy,
    env: HashMap<String, String>,
    translation_result: Option<translation::command_translation::CommandTranslationResult>,
) -> std::io::Result<(Child, Option<translation::command_translation::CommandTranslationResult>)>
where
    P: AsRef<Path>,
{
    let args = create_linux_sandbox_command_args(command, sandbox_policy, &cwd);
    let arg0 = Some("codex-linux-sandbox");
    wrap_spawn_result(
        spawn_child_async(
            codex_linux_sandbox_exe.as_ref().to_path_buf(),
            args,
            arg0,
            cwd,
            sandbox_policy,
            stdio_policy,
            env,
        ).await,
        translation_result,
    )
}

/// Windows CMD shell sandbox.
pub async fn spawn_command_under_win64_cmd(
    command: Vec<String>,
    _sandbox_policy: &SandboxPolicy,
    cwd: PathBuf,
    stdio_policy: StdioPolicy,
    env: HashMap<String, String>,
    translation_result: Option<translation::command_translation::CommandTranslationResult>,
) -> std::io::Result<(Child, Option<translation::command_translation::CommandTranslationResult>)> {
    #[cfg(windows)]
    {
        // Use a helper script to restrict command execution. This wrapper denies
        // attempts to change directories above the current working directory and
        // runs the command under a restricted user account.
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let parent = Path::new(&manifest_dir).parent();
        
        let batch_script_path = format!("{}/{}",
            parent.unwrap().to_str().unwrap(),
            "scripts/win64_cmd_restricted.bat"
        );
        let normalized_path = normalize_path(&batch_script_path);
        let mut cmd = Command::new("cmd.exe");
        cmd.arg("/C").arg(normalized_path);
        cmd.args(&command);
        cmd.current_dir(&cwd);
        cmd.envs(&env);

        match stdio_policy {
            StdioPolicy::RedirectForShellTool => {
                cmd.stdin(Stdio::null());
                cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
            }
            StdioPolicy::Inherit => {
                cmd.stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit());
            }
        }

        wrap_spawn_result(cmd.spawn(), translation_result)
    }

    #[cfg(not(windows))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Windows CMD shell sandbox is only available on Windows targets",
        ))
    }
}

/// Windows PowerShell sandbox.
pub async fn spawn_command_under_win64_ps(
    command: Vec<String>,
    _sandbox_policy: &SandboxPolicy,
    cwd: PathBuf,
    stdio_policy: StdioPolicy,
    env: HashMap<String, String>,
    translation_result: Option<translation::command_translation::CommandTranslationResult>,
) -> std::io::Result<(Child, Option<translation::command_translation::CommandTranslationResult>)> {
    #[cfg(windows)]
    {
        let powershell_script_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "src/scripts/win64_ps_restricted.ps1"
        );
        let normalized_path = normalize_path(&powershell_script_path);
        let mut cmd = Command::new("powershell.exe");
        cmd.arg("-File").arg(normalized_path);
        cmd.args(&command);
        cmd.current_dir(&cwd);
        cmd.envs(&env);

        match stdio_policy {
            StdioPolicy::RedirectForShellTool => {
                cmd.stdin(Stdio::null());
                cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
            }
            StdioPolicy::Inherit => {
                cmd.stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit());
            }
        }

        wrap_spawn_result(cmd.spawn(), translation_result)
    }

    #[cfg(not(windows))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Windows PowerShell sandbox is only available on Windows targets",
        ))
    }
}

/// API sandbox agnostic to platform.
pub async fn spawn_command_under_api(
    command: Vec<String>,
    _sandbox_policy: &SandboxPolicy,
    cwd: PathBuf,
    stdio_policy: StdioPolicy,
    env: HashMap<String, String>,
    timeout_ms: Option<u64>,
    translation_result: Option<translation::command_translation::CommandTranslationResult>,
) -> Result<RawExecToolCallOutput> {
    use tokio::net::TcpListener;
    use tokio::sync::Notify;

    let listener = TcpListener::bind("127.0.0.1:0").await?; // Bind to an ephemeral port
    let local_addr = listener.local_addr()?; // Get the bound address

    tracing::info!("API listener bound to: {}", local_addr);

    let mut status_factor = 1i32;

    const HANDSHAKE_TRIES: usize = 3;
    const HANDSHAKE_RETRY: Duration = Duration::from_secs(1);

    let handshake_handle = tokio::spawn(async move {
        accept_with_retries(listener, HANDSHAKE_TRIES, HANDSHAKE_RETRY).await
    });

    let command_line = command.join(" ");

    if !is_interpreter(command.get(0).map(String::as_str).unwrap_or("")) {
        let (handshake_message, stream_opt) = handshake_handle.await??;
        if let Some(stream) = stream_opt {
            let response = match send_payload(stream, command_line.as_bytes()).await {
                Ok(resp) => String::from_utf8_lossy(&resp).to_string(),
                Err(e) => {
                    status_factor *= API_PAYLOAD_FAILURE;
                    tracing::warn!("Failed to send payload: {}", e);
                    String::new()
                }
            };
            let mut output = handshake_message;
            if !response.is_empty() {
                output.push_str("\n");
                output.push_str(&response);
            } else {
                output.push_str("\n");
                output.push_str(&command_line);
            }
            let code = if status_factor == 1 { 0 } else { status_factor };
            return Ok(RawExecToolCallOutput {
                exit_status: synthetic_exit_status(code),
                stdout: output.into_bytes(),
                stderr: Vec::new(),
                translation_result,
            });
        } else {
            status_factor *= API_HANDSHAKE_FAILURE;
            let output = format!("{}\n{}", handshake_message, command_line);
            return Ok(RawExecToolCallOutput {
                exit_status: synthetic_exit_status(status_factor),
                stdout: output.into_bytes(),
                stderr: Vec::new(),
                translation_result,
            });

        }
    }

    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);

    cmd.current_dir(cwd);
    cmd.envs(env);

    match stdio_policy {
        StdioPolicy::RedirectForShellTool => {
            cmd.stdin(Stdio::null());
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
        StdioPolicy::Inherit => {
            cmd.stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
        }
    }


    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            status_factor *= API_SPAWN_FAILURE;
            tracing::warn!("Failed to spawn command: {}", e);
            return Ok(RawExecToolCallOutput {
                exit_status: synthetic_exit_status(status_factor),
                stdout: Vec::new(),
                stderr: format!("Program not found: {}", command_line).into_bytes(),
                translation_result,
            });
        }
    };

    let output_handle = {
        let ctrl_c = Arc::new(Notify::new());
        let tr = translation_result.clone();
        tokio::spawn(async move { consume_truncated_output(child, ctrl_c, timeout_ms, tr).await })
    };

    let (handshake_message, _stream) = handshake_handle.await??;
    if handshake_message == "No response on the API" {
        status_factor *= API_HANDSHAKE_FAILURE;
    }

    let mut output = output_handle.await??;

    if !handshake_message.is_empty() {
        let mut combined = handshake_message.into_bytes();
        combined.push(b'\n');
        combined.extend_from_slice(&output.stdout);
        output.stdout = combined;
    }
    if status_factor != 1 {
        output.exit_status = synthetic_exit_status(status_factor);
    }
    output.translation_result = translation_result;

    Ok(output)
}

fn is_interpreter(program: &str) -> bool {
    let name = program
        .rsplit_once('/')
        .map(|(_, n)| n)
        .unwrap_or(program)
        .to_ascii_lowercase();
    matches!(
        name.as_str(),
        "sh" | "bash" | "zsh" | "cmd" | "powershell" | "pwsh" | "python" | "python3" | "node" | "perl"
    )
}

/// Converts the sandbox policy into the CLI invocation for `codex-linux-sandbox`.
fn create_linux_sandbox_command_args(
    command: Vec<String>,
    sandbox_policy: &SandboxPolicy,
    cwd: &Path,
) -> Vec<String> {
    let mut linux_cmd: Vec<String> = vec![];

    // Translate individual permissions.
    // Use high-level helper methods to infer flags when we cannot see the
    // exact permission list.
    if sandbox_policy.has_full_disk_read_access() {
        linux_cmd.extend(["-s", "disk-full-read-access"].map(String::from));
    }

    if sandbox_policy.has_full_disk_write_access() {
        linux_cmd.extend(["-s", "disk-full-write-access"].map(String::from));
    } else {
        // Derive granular writable paths (includes cwd if `DiskWriteCwd` is
        // present).
        for root in sandbox_policy.get_writable_roots_with_cwd(cwd) {
            // Check if this path corresponds exactly to cwd to map to
            // `disk-write-cwd`, otherwise use the generic folder rule.
            if root == cwd {
                linux_cmd.extend(["-s", "disk-write-cwd"].map(String::from));
            } else {
                linux_cmd.extend([
                    "-s".to_string(),
                    format!("disk-write-folder={}", root.to_string_lossy()),
                ]);
            }
        }
    }

    if sandbox_policy.has_full_network_access() {
        linux_cmd.extend(["-s", "network-full-access"].map(String::from));
    }

    // Separator so that command arguments starting with `-` are not parsed as
    // options of the helper itself.
    linux_cmd.push("--".to_string());

    // Append the original tool command.
    linux_cmd.extend(command);

    linux_cmd
}

fn create_seatbelt_command_args(
    command: Vec<String>,
    sandbox_policy: &SandboxPolicy,
    cwd: &Path,
) -> Vec<String> {
    let (file_write_policy, extra_cli_args) = {
        if sandbox_policy.has_full_disk_write_access() {
            // Allegedly, this is more permissive than `(allow file-write*)`.
            (
                r#"(allow file-write* (regex #"^/"))"#.to_string(),
                Vec::<String>::new(),
            )
        } else {
            let writable_roots = sandbox_policy.get_writable_roots_with_cwd(cwd);
            let (writable_folder_policies, cli_args): (Vec<String>, Vec<String>) = writable_roots
                .iter()
                .enumerate()
                .map(|(index, root)| {
                    let param_name = format!("WRITABLE_ROOT_{index}");
                    let policy: String = format!("(subpath (param \"{param_name}\"))");
                    let cli_arg = format!("-D{param_name}={}", root.to_string_lossy());
                    (policy, cli_arg)
                })
                .unzip();
            if writable_folder_policies.is_empty() {
                ("".to_string(), Vec::<String>::new())
            } else {
                let file_write_policy = format!(
                    "(allow file-write*\n{}\n)",
                    writable_folder_policies.join(" ")
                );
                (file_write_policy, cli_args)
            }
        }
    };

    let file_read_policy = if sandbox_policy.has_full_disk_read_access() {
        "; allow read-only file operations\n(allow file-read*)"
    } else {
        ""
    };

    // TODO(mbolin): apply_patch calls must also honor the SandboxPolicy.
    let network_policy = if sandbox_policy.has_full_network_access() {
        "(allow network-outbound)\n(allow network-inbound)\n(allow system-socket)"
    } else {
        ""
    };

    let full_policy = format!(
        "{MACOS_SEATBELT_BASE_POLICY}\n{file_read_policy}\n{file_write_policy}\n{network_policy}"
    );
    let mut seatbelt_args: Vec<String> = vec!["-p".to_string(), full_policy];
    seatbelt_args.extend(extra_cli_args);
    seatbelt_args.push("--".to_string());
    seatbelt_args.extend(command);
    seatbelt_args
}

#[derive(Debug)]
pub struct RawExecToolCallOutput {
    pub exit_status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub translation_result: Option<translation::command_translation::CommandTranslationResult>,
}

#[derive(Debug)]
pub struct ExecToolCallOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration: Duration,
    pub translation_result: Option<translation::command_translation::CommandTranslationResult>,
}

async fn exec(
    ExecParams {
        command,
        cwd,
        timeout_ms,
        env,
    }: ExecParams,
    sandbox_policy: &SandboxPolicy,
    ctrl_c: Arc<Notify>,
    translation_result: Option<translation::command_translation::CommandTranslationResult>,
) -> Result<RawExecToolCallOutput> {
    let (program, args) = command.split_first().ok_or_else(|| {
        CodexErr::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "command args are empty",
        ))
    })?;
    let arg0 = None;
    let child = spawn_child_async(
        PathBuf::from(program),
        args.into(),
        arg0,
        cwd,
        sandbox_policy,
        StdioPolicy::RedirectForShellTool,
        env,
    )
    .await?;
    consume_truncated_output(child, ctrl_c, timeout_ms, translation_result).await
}

#[derive(Debug, Clone, Copy)]
pub enum StdioPolicy {
    RedirectForShellTool,
    Inherit,
}

/// Spawns the appropriate child process for the ExecParams and SandboxPolicy,
/// ensuring the args and environment variables used to create the `Command`
/// (and `Child`) honor the configuration.
///
/// For now, we take `SandboxPolicy` as a parameter to spawn_child() because
/// we need to determine whether to set the
/// `CODEX_SANDBOX_NETWORK_DISABLED_ENV_VAR` environment variable.
async fn spawn_child_async(
    program: PathBuf,
    args: Vec<String>,
    #[cfg_attr(not(unix), allow(unused_variables))] arg0: Option<&str>,
    cwd: PathBuf,
    sandbox_policy: &SandboxPolicy,
    stdio_policy: StdioPolicy,
    env: HashMap<String, String>,
) -> std::io::Result<Child> {
    let mut cmd = Command::new(&program);
    #[cfg(unix)]
    cmd.arg0(arg0.map_or_else(|| program.to_string_lossy().to_string(), String::from));
    cmd.args(args);
    cmd.current_dir(cwd);
    cmd.env_clear();
    cmd.envs(env);

    if !sandbox_policy.has_full_network_access() {
        cmd.env(CODEX_SANDBOX_NETWORK_DISABLED_ENV_VAR, "1");
    }

    match stdio_policy {
        StdioPolicy::RedirectForShellTool => {
            // Do not create a file descriptor for stdin because otherwise some
            // commands may hang forever waiting for input. For example, ripgrep has
            // a heuristic where it may try to read from stdin as explained here:
            // https://github.com/BurntSushi/ripgrep/blob/e2362d4d5185d02fa857bf381e7bd52e66fafc73/crates/core/flags/hiargs.rs#L1101-L1103
            cmd.stdin(Stdio::null());

            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
        StdioPolicy::Inherit => {
            // Inherit stdin, stdout, and stderr from the parent process.
            cmd.stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
        }
    }

    cmd.kill_on_drop(true).spawn()
}

/// Consumes the output of a child process, truncating it so it is suitable for
/// use as the output of a `shell` tool call. Also enforces specified timeout.
pub(crate) async fn consume_truncated_output(
    mut child: Child,
    ctrl_c: Arc<Notify>,
    timeout_ms: Option<u64>,
    translation_result: Option<translation::command_translation::CommandTranslationResult>,
) -> Result<RawExecToolCallOutput> {
    let stdout_reader = child.stdout.take().ok_or_else(|| {
        CodexErr::Io(io::Error::other(
            "stdout pipe was unexpectedly not available",
        ))
    })?;
    let stderr_reader = child.stderr.take().ok_or_else(|| {
        CodexErr::Io(io::Error::other(
            "stderr pipe was unexpectedly not available",
        ))
    })?;

    let stdout_handle: tokio::task::JoinHandle<std::result::Result<Vec<u8>, std::io::Error>> = tokio::spawn(async move {
        let mut reader = BufReader::new(stdout_reader);
        let mut buffer = Vec::new();
        let mut result = Vec::new();
        while let Ok(bytes_read) = reader.read_until(b'\n', &mut buffer).await {
            if bytes_read == 0 {
                break;
            }

            // Append the read buffer to the result
            result.extend_from_slice(&buffer);

            // Simulate token-based delay
            let token_estimate = buffer.len() / 4; // Approximate tokens by dividing char count
            let delay_per_token = Duration::from_millis(50); // Example: 50ms per token
            let total_delay = delay_per_token * token_estimate as u32;
            tokio::time::sleep(total_delay).await;

            buffer.clear(); // Clear the buffer for the next read
        }
        Ok(result) // Return the accumulated result
    });

    let stderr_handle = tokio::spawn(read_capped(
        BufReader::new(stderr_reader),
        MAX_STREAM_OUTPUT,
        MAX_STREAM_OUTPUT_LINES,
    ));

    let interrupted = ctrl_c.notified();
    let timeout = Duration::from_millis(timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS));
    let exit_status = tokio::select! {
        result = tokio::time::timeout(timeout, child.wait()) => {
            match result {
                Ok(Ok(exit_status)) => exit_status,
                Ok(e) => e?,
                Err(_) => {
                    child.start_kill()?;
                    synthetic_exit_status(128 + TIMEOUT_CODE)
                }
            }
        }
        _ = interrupted => {
            child.start_kill()?;
            synthetic_exit_status(128 + SIGKILL_CODE)
        }
    };

    let mut stdout = stdout_handle.await??;
    let stderr = stderr_handle.await??;

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let parent = Path::new(&manifest_dir).parent().unwrap();
    let template_path = parent.join("scripts/exec_output_template.md");

    if template_path.exists() {
        let template = std::fs::read_to_string(&template_path)?;
        let stdout_content = String::from_utf8_lossy(&stdout);
        let mut templated_content = template.replace("{{stdout}}", &stdout_content);

        if let Some(translation) = &translation_result {
            templated_content = templated_content
                .replace("{{original_command}}", &translation.original_command)
                .replace("{{translated_command}}", &translation.translated_command.clone().unwrap_or_default())
                .replace("{{informational_output}}", &translation.informational_output);
        }

        let reader_path = template_path.with_file_name("templated_output.txt");
        std::fs::write(&reader_path, &templated_content)?;
        stdout = templated_content.into_bytes();
    }

    Ok(RawExecToolCallOutput {
        exit_status,
        stdout,
        stderr,
        translation_result,
    })
}

async fn read_capped<R: AsyncRead + Unpin>(
    mut reader: R,
    max_output: usize,
    max_lines: usize,
) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(max_output.min(8 * 1024));
    let mut tmp = [0u8; 8192];

    let mut remaining_bytes = max_output;
    let mut remaining_lines = max_lines;

    loop {
        let n = reader.read(&mut tmp).await?;
        if n == 0 {
            break;
        }

        // Copy into the buffer only while we still have byte and line budget.
        if remaining_bytes > 0 && remaining_lines > 0 {
            let mut copy_len = 0;
            for &b in &tmp[..n] {
                if remaining_bytes == 0 || remaining_lines == 0 {
                    break;
                }
                copy_len += 1;
                remaining_bytes -= 1;
                if b == b'\n' {
                    remaining_lines -= 1;
                }
            }
            buf.extend_from_slice(&tmp[..copy_len]);
        }
        // Continue reading to EOF to avoid back-pressure, but discard once caps are hit.
    }

    Ok(buf)
}

#[cfg(unix)]
fn synthetic_exit_status(code: i32) -> ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    std::process::ExitStatus::from_raw((code as i32) << 8)
}

#[cfg(windows)]
fn synthetic_exit_status(code: i32) -> ExitStatus {
    use std::os::windows::process::ExitStatusExt;
    #[expect(clippy::unwrap_used)]
    std::process::ExitStatus::from_raw(code.try_into().unwrap())
}



