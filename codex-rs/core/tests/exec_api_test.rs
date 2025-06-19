use std::collections::HashMap;
use std::path::PathBuf;
use codex_core::protocol::SandboxPolicy;
use codex_core::exec::{
    spawn_command_under_api, StdioPolicy, API_HANDSHAKE_FAILURE,
};

#[tokio::test]
async fn test_spawn_command_under_api() {
    let command = vec![
        "sh".to_string(),
        "-c".to_string(),
        "echo Hello, World!".to_string(),
    ];
    let sandbox_policy = SandboxPolicy::new_full_auto_policy();
    let cwd = PathBuf::from(".");
    let stdio_policy = StdioPolicy::RedirectForShellTool;
    let env = HashMap::new();

    match spawn_command_under_api(command, &sandbox_policy, cwd, stdio_policy, env, None).await {
        Ok(output) => {
            assert_eq!(output.exit_status.code(), Some(API_HANDSHAKE_FAILURE));
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains("Hello, World!"), "Unexpected output: {}", stdout);
        }
        Err(e) => {
            panic!("Failed to spawn command under API: {}", e);
        }
    }
}

#[tokio::test]
async fn test_spawn_command_under_api_no_handshake() {
    // Command is not an interpreter so no process is spawned.
    let command = vec!["nonexistent".to_string()];
    let sandbox_policy = SandboxPolicy::new_full_auto_policy();
    let cwd = PathBuf::from(".");
    let stdio_policy = StdioPolicy::RedirectForShellTool;
    let env = HashMap::new();

    let output = spawn_command_under_api(command, &sandbox_policy, cwd, stdio_policy, env, Some(100)).await
        .expect("spawn under api failed");

    assert_eq!(output.exit_status.code(), Some(API_HANDSHAKE_FAILURE));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("No response on the API"));
}
