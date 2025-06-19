#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::path::PathBuf;
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

use crate::command_translation::{CommandTranslator,
    DEFAULT_TRANSLATOR, OPERATING_SHELL};

use crate::error::CodexErr;
use crate::error::Result;
use crate::error::SandboxErr;
use crate::protocol::SandboxPolicy;

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

/// When this variable is set to a non-empty value, all sandbox implementations
/// are replaced with a dummy "black box" sandbox that merely reports success
/// without executing any commands.
pub const CODEX_DUMMY_SANDBOX_ENV_VAR: &str = "CODEX_DUMMY_SANDBOX";

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

    /// Dummy sandbox that pretends the command executed successfully.
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
) -> Result<ExecToolCallOutput> {
    let start = Instant::now();

    let translated_command = DEFAULT_TRANSLATOR.translate_command(&params.command[0], OPERATING_SHELL);
    println!("{}", translated_command); // Log the translation

    let mut sandbox_type = sandbox_type;
    if std::env::var(CODEX_DUMMY_SANDBOX_ENV_VAR).is_ok() {
        sandbox_type = SandboxType::BlackBox;
    }

    let raw_output_result = match sandbox_type {
        SandboxType::None => exec(params, sandbox_policy, ctrl_c).await,
        SandboxType::BlackBox => {
            Ok(RawExecToolCallOutput {
                exit_status: synthetic_exit_status(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }
        SandboxType::MacosSeatbelt => {
            let ExecParams {
                command,
                cwd,
                timeout_ms,
                env,
            } = params;
            let child = spawn_command_under_seatbelt(
                command,
                sandbox_policy,
                cwd,
                StdioPolicy::RedirectForShellTool,
                env,
            )
            .await?;
            consume_truncated_output(child, ctrl_c, timeout_ms).await
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
            let child = spawn_command_under_linux_sandbox(
                codex_linux_sandbox_exe,
                command,
                sandbox_policy,
                cwd,
                StdioPolicy::RedirectForShellTool,
                env,
            )
            .await?;

            consume_truncated_output(child, ctrl_c, timeout_ms).await
        }
        SandboxType::Win64Cmd => {
            let ExecParams {
                command,
                cwd,
                timeout_ms,
                env,
            } = params;

            let child = spawn_command_under_win64_cmd(
                command,
                sandbox_policy,
                cwd,
                StdioPolicy::RedirectForShellTool,
                env,
            )
            .await?;

            consume_truncated_output(child, ctrl_c, timeout_ms).await
        }
        SandboxType::Win64Ps => {
            let ExecParams {
                command,
                cwd,
                timeout_ms,
                env,
            } = params;

            let child = spawn_command_under_win64_ps(
                command,
                sandbox_policy,
                cwd,
                StdioPolicy::RedirectForShellTool,
                env,
            )
            .await?;

            consume_truncated_output(child, ctrl_c, timeout_ms).await
        }
        SandboxType::Api => {
            let ExecParams {
                command,
                cwd,
                timeout_ms,
                env,
            } = params;

            let child = spawn_command_under_api(
                command,
                sandbox_policy,
                cwd,
                StdioPolicy::RedirectForShellTool,
                env,
            )
            .await?;

            consume_truncated_output(child, ctrl_c, timeout_ms).await
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
) -> std::io::Result<Child> {
    let args = create_seatbelt_command_args(command, sandbox_policy, &cwd);
    let arg0 = None;
    spawn_child_async(
        PathBuf::from(MACOS_PATH_TO_SEATBELT_EXECUTABLE),
        args,
        arg0,
        cwd,
        sandbox_policy,
        stdio_policy,
        env,
    )
    .await
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
) -> std::io::Result<Child>
where
    P: AsRef<Path>,
{
    let args = create_linux_sandbox_command_args(command, sandbox_policy, &cwd);
    let arg0 = Some("codex-linux-sandbox");
    spawn_child_async(
        codex_linux_sandbox_exe.as_ref().to_path_buf(),
        args,
        arg0,
        cwd,
        sandbox_policy,
        stdio_policy,
        env,
    )
    .await
}

/// Windows CMD shell sandbox.
pub async fn spawn_command_under_win64_cmd(
    command: Vec<String>,
    sandbox_policy: &SandboxPolicy,
    cwd: PathBuf,
    stdio_policy: StdioPolicy,
    env: HashMap<String, String>,
) -> std::io::Result<Child> {
    #[cfg(windows)]
    {
        let batch_script_path = "path_to_batch_script.bat"; // Placeholder for batch script path
        let mut cmd = Command::new("cmd.exe");
        cmd.arg("/C").arg(batch_script_path);
        cmd.args(command);
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

        cmd.spawn()
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
    sandbox_policy: &SandboxPolicy,
    cwd: PathBuf,
    stdio_policy: StdioPolicy,
    env: HashMap<String, String>,
) -> std::io::Result<Child> {
    #[cfg(windows)]
    {
        let powershell_script_path = "path_to_powershell_script.ps1"; // Placeholder for PowerShell script path
        let mut cmd = Command::new("powershell.exe");
        cmd.arg("-File").arg(powershell_script_path);
        cmd.args(command);
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

        cmd.spawn()
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
    sandbox_policy: &SandboxPolicy,
    cwd: PathBuf,
    stdio_policy: StdioPolicy,
    env: HashMap<String, String>,
) -> std::io::Result<Child> {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await?; // Bind to an ephemeral port
    let local_addr = listener.local_addr()?; // Get the bound address

    tracing::info!("API listener bound to: {}", local_addr);

    let handle = tokio::spawn(async move {
        match listener.accept().await {
            Ok((stream, _)) => {
                tracing::info!("Connection received from: {}", stream.peer_addr()?);
                let mut buffer = vec![0; 1024];
                let _ = stream.readable().await;
                match stream.try_read(&mut buffer) {
                    Ok(bytes_read) => {
                        tracing::info!("Received {} bytes", bytes_read);
                        Ok(buffer[..bytes_read].to_vec())
                    }
                    Err(e) => {
                        tracing::error!("Error reading from stream: {}", e);
                        Err(e)
                    }
                }
            }
            Err(e) => {
                tracing::error!("Error accepting connection: {}", e);
                Err(e)
            }
        }
    });

    // Spawn the command as usual
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

    let child = cmd.spawn()?;

    // Wait for the listener to complete or timeout
    let timeout = tokio::time::sleep(Duration::from_secs(10));
    tokio::select! {
        result = handle => {
            match result {
                Ok(Ok(data)) => {
                    tracing::info!("Data received: {:?}", data);
                }
                Ok(Err(e)) => {
                    tracing::error!("Error during API communication: {}", e);
                }
                Err(e) => {
                    tracing::error!("Error during API communication: {}", e);
                }
            }
        }
        _ = timeout => {
            tracing::warn!("API listener timed out");
        }
    }

    Ok(child)
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
}

#[derive(Debug)]
pub struct ExecToolCallOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration: Duration,
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
    consume_truncated_output(child, ctrl_c, timeout_ms).await
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
                    // timeout
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

    let stdout = stdout_handle.await??;
    let stderr = stderr_handle.await??;

    Ok(RawExecToolCallOutput {
        exit_status,
        stdout,
        stderr,
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
    std::process::ExitStatus::from_raw(code)
}

#[cfg(windows)]
fn synthetic_exit_status(code: i32) -> ExitStatus {
    use std::os::windows::process::ExitStatusExt;
    #[expect(clippy::unwrap_used)]
    std::process::ExitStatus::from_raw(code.try_into().unwrap())
}

// ---------------------------------------------------------------------------
// IMPORTANT: Future Work Stub
// ---------------------------------------------------------------------------
// The `SandboxType::BlackBox` currently acts as a dummy sandbox that reports
// success without executing commands. This is a placeholder for future work
// to implement a fully virtualized execution space with no reliance on a shell.
// ---------------------------------------------------------------------------
