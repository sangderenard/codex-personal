#![expect(clippy::expect_used)]
use codex_execpolicy::{PolicyWatcher, ExecCall, MatchedExec};
use tempfile::TempDir;
use std::fs;

#[test]
fn reload_updates_policy() -> anyhow::Result<()> {
    let dir = TempDir::new()?;
    let path = dir.path().join("policy.star");

    fs::write(&path, "define_program(program=\"ls\", args=[], system_path=[\"/bin/ls\"])")?;
    let watcher = PolicyWatcher::new(path.clone())?;
    let exec = ExecCall::new("ls", &[]);
    assert!(matches!(watcher.policy().check(&exec).expect("failed"), MatchedExec::Match { .. }));

    fs::write(&path, "define_program(program=\"cat\", args=[], system_path=[\"/bin/cat\"])")?;
    watcher.reload()?;
    let exec = ExecCall::new("cat", &[]);
    assert!(matches!(watcher.policy().check(&exec).expect("failed"), MatchedExec::Match { .. }));

    Ok(())
}
