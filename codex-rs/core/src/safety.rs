use std::collections::HashSet;
use std::env;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

use codex_apply_patch::ApplyPatchAction;
use codex_apply_patch::ApplyPatchFileChange;

use crate::exec::SandboxType;

use crate::protocol::AskForApproval;
use crate::protocol::SandboxPolicy;

#[derive(Debug)]
pub enum SafetyCheck {
    AutoApprove { sandbox_type: SandboxType },
    AskUser,
    Reject { reason: String },
}

pub fn assess_patch_safety(
    action: &ApplyPatchAction,
    policy: AskForApproval,
    writable_roots: &[PathBuf],
    cwd: &Path,
) -> SafetyCheck {
    if action.is_empty() {
        return SafetyCheck::Reject {
            reason: "empty patch".to_string(),
        };
    }

    match policy {
        AskForApproval::OnFailure | AskForApproval::AutoEdit | AskForApproval::Never => {
            // Continue to see if this can be auto-approved.
        }
        // TODO(ragona): I'm not sure this is actually correct? I believe in this case
        // we want to continue to the writable paths check before asking the user.
        AskForApproval::UnlessAllowListed => {
            return SafetyCheck::AskUser;
        }
    }

    if is_write_patch_constrained_to_writable_paths(action, writable_roots, cwd) {
        SafetyCheck::AutoApprove {
            sandbox_type: SandboxType::None,
        }
    } else if policy == AskForApproval::OnFailure {
        // Only auto‑approve when we can actually enforce a sandbox. Otherwise
        // fall back to asking the user because the patch may touch arbitrary
        // paths outside the project.
        match get_platform_sandbox() {
            Some(sandbox_type) => SafetyCheck::AutoApprove { sandbox_type },
            None => SafetyCheck::AskUser,
        }
    } else if policy == AskForApproval::Never {
        SafetyCheck::Reject {
            reason: "writing outside of the project; rejected by user approval settings"
                .to_string(),
        }
    } else {
        SafetyCheck::AskUser
    }
}

pub fn assess_command_safety(
    command: &[String],
    approval_policy: AskForApproval,
    sandbox_policy: &SandboxPolicy,
    approved: &HashSet<Vec<String>>,
) -> SafetyCheck {
    let approve_without_sandbox = || SafetyCheck::AutoApprove {
        sandbox_type: SandboxType::None,
    };
    
    if sandbox_policy.is_unrestricted() {
        approve_without_sandbox()
    } else {
        match get_platform_sandbox() {
            // We have a sandbox, so we can approve the command in all modes
            Some(sandbox_type) => SafetyCheck::AutoApprove { sandbox_type },
            None => {
                // We do not have a sandbox, so we need to consider the approval policy
                match approval_policy {
                    // Never is our "non-interactive" mode; it must automatically reject
                    AskForApproval::Never => SafetyCheck::Reject {
                        reason: "auto-rejected by user approval settings".to_string(),
                    },
                    // Otherwise, we ask the user for approval
                    _ => SafetyCheck::AskUser,
                }
            }
        }
    }
}

pub fn get_platform_sandbox() -> Option<SandboxType> {
    if std::env::var(crate::exec::CODEX_DUMMY_SANDBOX_ENV_VAR).is_ok() {
        return Some(SandboxType::BlackBox);
    } else if( std::env::var(crate::exec::CODEX_API_SANDBOX_ENV_VAR).is_ok() ) {
        return Some(SandboxType::Api);
    }

    if cfg!(target_os = "macos") {
        Some(SandboxType::MacosSeatbelt)
    } else if cfg!(target_os = "linux") {
        Some(SandboxType::LinuxSeccomp)
    } else if cfg!(target_os = "windows") {
        match detect_windows_shell().as_str() {
            "powershell" => Some(SandboxType::Win64Ps),
            "cmd" => Some(SandboxType::Win64Cmd),
            "bash for windows" | "wsl" => Some(SandboxType::Landlock,
            _ => panic!("Unsupported shell for sandboxing"),
        }
    } else {
        panic!("Unsupported platform for sandboxing");
    }
}

fn is_write_patch_constrained_to_writable_paths(
    action: &ApplyPatchAction,
    writable_roots: &[PathBuf],
    cwd: &Path,
) -> bool {
    // Early‑exit if there are no declared writable roots.
    if writable_roots.is_empty() {
        return false;
    }

    // Normalize a path by removing `.` and resolving `..` without touching the
    // filesystem (works even if the file does not exist).
    fn normalize(path: &Path) -> Option<PathBuf> {
        let mut out = PathBuf::new();
        for comp in path.components() {
            match comp {
                Component::ParentDir => {
                    out.pop();
                }
                Component::CurDir => { /* skip */ }
                other => out.push(other.as_os_str()),
            }
        }
        Some(out)
    }

    // Determine whether `path` is inside **any** writable root. Both `path`
    // and roots are converted to absolute, normalized forms before the
    // prefix check.
    let is_path_writable = |p: &PathBuf| {
        let abs = if p.is_absolute() {
            p.clone()
        } else {
            cwd.join(p)
        };
        let abs = match normalize(&abs) {
            Some(v) => v,
            None => return false,
        };

        writable_roots.iter().any(|root| {
            let root_abs = if root.is_absolute() {
                root.clone()
            } else {
                normalize(&cwd.join(root)).unwrap_or_else(|| cwd.join(root))
            };

            abs.starts_with(&root_abs)
        })
    };

    for (path, change) in action.changes() {
        match change {
            ApplyPatchFileChange::Add { .. } | ApplyPatchFileChange::Delete => {
                if !is_path_writable(path) {
                    return false;
                }
            }
            ApplyPatchFileChange::Update { move_path, .. } => {
                if !is_path_writable(path) {
                    return false;
                }
                if let Some(dest) = move_path {
                    if !is_path_writable(dest) {
                        return false;
                    }
                }
            }
        }
    }

    true
}

pub fn detect_windows_shell() -> String {
    let comspec = env::var("COMSPEC").unwrap_or_default();
    if comspec.contains("powershell") {
        "powershell".to_string()
    } else if comspec.contains("cmd") {
        "cmd".to_string()
    } else {
        let shell = env::var("SHELL").unwrap_or_default();
        if shell.contains("bash") {
            "bash for windows".to_string()
        } else if shell.contains("wsl") {
            "wsl".to_string()
        } else {
            "unknown shell".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_writable_roots_constraint() {
        let cwd = std::env::current_dir().unwrap();
        let parent = cwd.parent().unwrap().to_path_buf();

        // Helper to build a single‑entry map representing a patch that adds a
        // file at `p`.
        let make_add_change = |p: PathBuf| ApplyPatchAction::new_add_for_test(&p, "".to_string());

        let add_inside = make_add_change(cwd.join("inner.txt"));
        let add_outside = make_add_change(parent.join("outside.txt"));

        assert!(is_write_patch_constrained_to_writable_paths(
            &add_inside,
            &[PathBuf::from(".")],
            &cwd,
        ));

        let add_outside_2 = make_add_change(parent.join("outside.txt"));
        assert!(!is_write_patch_constrained_to_writable_paths(
            &add_outside_2,
            &[PathBuf::from(".")],
            &cwd,
        ));

        // With parent dir added as writable root, it should pass.
        assert!(is_write_patch_constrained_to_writable_paths(
            &add_outside,
            &[PathBuf::from("..")],
            &cwd,
        ))
    }
}
