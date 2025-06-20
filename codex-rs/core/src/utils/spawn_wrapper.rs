use tokio::process::Child;
use translation::command_translation::CommandTranslationResult;

/// Combines the result of a spawned process with the translation result.
/// Returns a tuple containing the process handle and the translation result.
pub fn wrap_spawn_result(
    spawn_result: std::io::Result<Child>,
    translation_result: Option<CommandTranslationResult>,
) -> std::io::Result<(Child, Option<CommandTranslationResult>)> {
    spawn_result.map(|child| (child, translation_result))
}
