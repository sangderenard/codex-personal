use std::path::PathBuf;

use codex_common::CliConfigOverrides;
use codex_common::SandboxPermissionOption;
use codex_core::config::Config;
use codex_core::config::ConfigOverrides;
use codex_core::exec::StdioPolicy;
use codex_core::exec::spawn_command_under_linux_sandbox;
use codex_core::exec::spawn_command_under_seatbelt;
use codex_core::exec::spawn_command_under_win64_cmd;
use codex_core::exec::spawn_command_under_win64_ps;
use codex_core::black_box::black_box::spawn_command_under_black_box;
use codex_core::utils::child_ext::{ChildLike, BlackBoxChild};
use crate::BlackBoxCommand;
use codex_core::exec::spawn_command_under_api;
use codex_core::exec_env::create_env;
use codex_core::protocol::SandboxPolicy;
use codex_core::config_types::ShellEnvironmentPolicy;
use crate::ApiCommand;
use crate::LandlockCommand;
use crate::SeatbeltCommand;
use crate::exit_status::handle_exit_status;
use translation::{DEFAULT_TRANSLATOR, OPERATING_SHELL, initialize};

pub async fn run_command_under_seatbelt(
    command: SeatbeltCommand,
    codex_linux_sandbox_exe: Option<PathBuf>,
) -> anyhow::Result<()> {
    let SeatbeltCommand {
        full_auto,
        sandbox,
        config_overrides,
        command,
    } = command;
    run_command_under_sandbox(
        full_auto,
        sandbox,
        command,
        config_overrides,
        codex_linux_sandbox_exe,
        SandboxType::Seatbelt,
    )
    .await
}

pub async fn run_command_under_landlock(
    command: LandlockCommand,
    codex_linux_sandbox_exe: Option<PathBuf>,
) -> anyhow::Result<()> {
    let LandlockCommand {
        full_auto,
        sandbox,
        config_overrides,
        command,
    } = command;
    run_command_under_sandbox(
        full_auto,
        sandbox,
        command,
        config_overrides,
        codex_linux_sandbox_exe,
        SandboxType::Landlock,
    )
    .await
}

pub async fn run_command_under_black_box(
    command: BlackBoxCommand,
    codex_linux_sandbox_exe: Option<PathBuf>,
) -> anyhow::Result<()> {
    let BlackBoxCommand {
        full_auto,
        sandbox,
        config_overrides,
        command,
    } = command;
    run_command_under_sandbox(
        full_auto,
        sandbox,
        command,
        config_overrides,
        codex_linux_sandbox_exe,
        SandboxType::BlackBox,
    )
    .await
}

pub async fn run_command_under_api(
    command: ApiCommand,
    codex_linux_sandbox_exe: Option<PathBuf>,
) -> anyhow::Result<()> {
    let ApiCommand {
        full_auto,
        sandbox,
        config_overrides,
        command,
    } = command;

    run_command_under_sandbox(
        full_auto,
        sandbox,
        command,
        config_overrides,
        codex_linux_sandbox_exe,
        SandboxType::Api,
    )
    .await
}

#[allow(dead_code)]
enum SandboxType {
    Seatbelt,
    Landlock,
    LinuxSeccomp,
    BlackBox,
    Win64Cmd,
    Win64Ps,
    Api,
}

async fn run_command_under_sandbox(
    full_auto: bool,
    sandbox: SandboxPermissionOption,
    command: Vec<String>,
    config_overrides: CliConfigOverrides,
    codex_linux_sandbox_exe: Option<PathBuf>,
    sandbox_type: SandboxType,
) -> anyhow::Result<()> {
    let sandbox_policy = create_sandbox_policy(full_auto, sandbox);
    let cwd = std::env::current_dir()?;
    let config = Config::load_with_cli_overrides(
        config_overrides
            .parse_overrides()
            .map_err(anyhow::Error::msg)?,
        ConfigOverrides {
            sandbox_policy: Some(sandbox_policy),
            codex_linux_sandbox_exe,
            ..Default::default()
        },
    )?;
    let stdio_policy = StdioPolicy::Inherit;
    let env = create_env(&config.shell_environment_policy);

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
        guard.translate_command(&command[0], shell, "N/A", &[])
    };

    let mut child = match sandbox_type {
        SandboxType::LinuxSeccomp => {
            #[expect(clippy::expect_used)]
            let codex_linux_sandbox_exe = config
                .codex_linux_sandbox_exe
                .expect("codex-linux-sandbox executable not found");
            let (child, _returned_tr) = spawn_command_under_linux_sandbox(
                codex_linux_sandbox_exe,
                command,
                &config.sandbox_policy,
                cwd,
                stdio_policy,
                env,
                Some(translation_result.clone()),
            )
            .await?;
            BlackBoxChild::Real(child)
        }
        SandboxType::Landlock => {
            #[expect(clippy::expect_used)]
            let codex_linux_sandbox_exe = config
                .codex_linux_sandbox_exe
                .expect("codex-linux-sandbox executable not found");
            let (child, _returned_tr) = spawn_command_under_linux_sandbox(
                codex_linux_sandbox_exe,
                command,
                &config.sandbox_policy,
                cwd,
                stdio_policy,
                env,
                Some(translation_result.clone()),
            )
            .await?;
            BlackBoxChild::Real(child)
        }
        SandboxType::Seatbelt => {
            let (child, _returned_tr) = spawn_command_under_seatbelt(
                command,
                &config.sandbox_policy,
                cwd,
                stdio_policy,
                env,
                Some(translation_result.clone()),
            )
            .await?;
            BlackBoxChild::Real(child)
        }
        SandboxType::BlackBox => {
            let (child, _returned_tr) = spawn_command_under_black_box(
                command,
                config.sandbox_policy.clone(),
                cwd,
                stdio_policy,
                config.shell_environment_policy.clone(),
                Some(translation_result.clone()),
            )
            .await?;
            child
        }
        SandboxType::Win64Cmd => {
            let (child, _returned_tr) = spawn_command_under_win64_cmd(
                command,
                &config.sandbox_policy,
                cwd,
                stdio_policy,
                env,
                Some(translation_result.clone()),
            )
            .await?;
            BlackBoxChild::Real(child)
        }
        SandboxType::Win64Ps => {
            let (child, _returned_tr) = spawn_command_under_win64_ps(
                command,
                &config.sandbox_policy,
                cwd,
                stdio_policy,
                env,
                Some(translation_result.clone()),
            )
            .await?;
            BlackBoxChild::Real(child)
        }
        SandboxType::Api => {
            let output = spawn_command_under_api(
                command,
                &config.sandbox_policy,
                cwd,
                stdio_policy,
                env,
                None,
                Some(translation_result.clone()),
            )
            .await?;
            println!("{}", String::from_utf8_lossy(&output.stdout));
            handle_exit_status(output.exit_status);
        }
    };

    let status = child.wait_future().await?;
    handle_exit_status(status);
}

pub fn create_sandbox_policy(full_auto: bool, sandbox: SandboxPermissionOption) -> SandboxPolicy {
    if full_auto {
        SandboxPolicy::new_read_only_policy_with_writable_roots(&[])
    } else {
        match sandbox.permissions.map(Into::into) {
            Some(sandbox_policy) => sandbox_policy,
            None => SandboxPolicy::new_read_only_policy(),
        }
    }
}

pub async fn run_command_under_win64_cmd(
    command: Vec<String>,
    sandbox_policy: SandboxPolicy,
) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let env = create_env(&ShellEnvironmentPolicy::default());
    let stdio_policy = StdioPolicy::Inherit;

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
        guard.translate_command(&command[0], shell, "N/A", &[])
    };

    let (mut child, _returned_tr) = spawn_command_under_win64_cmd(
        command,
        &sandbox_policy,
        cwd,
        stdio_policy,
        env,
        Some(translation_result.clone()),
    )
    .await?;

    let status = child.wait().await?;
    handle_exit_status(status);
}

pub async fn run_command_under_win64_ps(
    command: Vec<String>,
    sandbox_policy: SandboxPolicy,
) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let env = create_env(&ShellEnvironmentPolicy::default());
    let stdio_policy = StdioPolicy::Inherit;

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
        guard.translate_command(&command[0], shell, "N/A", &[])
    };

    let (mut child, _returned_tr) = spawn_command_under_win64_ps(
        command,
        &sandbox_policy,
        cwd,
        stdio_policy,
        env,
        Some(translation_result.clone()),
    )
    .await?;

    let status = child.wait().await?;
    handle_exit_status(status);
}