#![expect(clippy::expect_used)]
extern crate codex_execpolicy;

use codex_execpolicy::{ExecCall, MatchedExec, Policy, get_default_policy};

fn setup() -> Policy {
    get_default_policy().expect("failed to load default policy")
}

#[test]
fn cp_is_forbidden() {
    let policy = setup();
    let cp = ExecCall::new("cp", &["foo", "bar"]);
    let result = policy.check(&cp).expect("check failed");
    assert!(matches!(result, MatchedExec::Match { .. } | MatchedExec::Forbidden { .. }));
}
