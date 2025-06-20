use std::collections::HashMap;
use std::process::Command;
use std::path::{Path, PathBuf};

const MAX_TRANSLATION_WARNINGS: usize = 3; // Define constant for max warnings

#[derive(Debug, Clone)]
pub struct CommandTranslator {
    translations: HashMap<String, CommandTranslation>,
    max_warnings: usize,
}

#[derive(Debug, Clone)]
pub struct CommandTranslation {
    os_mappings: HashMap<String, String>,
    warnings: usize,
}

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct CommandTranslationResult {
    pub original_command: String,
    pub translated_command: Option<String>,
    pub informational_output: String,
}

impl CommandTranslator {
    pub fn new() -> Self {
        let mut translator = Self {
            translations: HashMap::new(),
            max_warnings: MAX_TRANSLATION_WARNINGS,
        };
        translator.insert_default_map();
        translator
    }

    fn insert_default_map(&mut self) {
        let mut mappings = HashMap::new();
        mappings.insert("linux".to_string(), "ls".to_string());
        mappings.insert("macos".to_string(), "ls".to_string());
        mappings.insert("windows".to_string(), "dir".to_string());
        self.add_translation("ls", mappings);

        let mut mappings = HashMap::new();
        mappings.insert("linux".to_string(), "cat".to_string());
        mappings.insert("macos".to_string(), "cat".to_string());
        mappings.insert("windows".to_string(), "type".to_string());
        self.add_translation("cat", mappings);

        let mut mappings = HashMap::new();
        mappings.insert("linux".to_string(), "cp".to_string());
        mappings.insert("macos".to_string(), "cp".to_string());
        mappings.insert("windows".to_string(), "copy".to_string());
        self.add_translation("cp", mappings);

        let mut mappings = HashMap::new();
        mappings.insert("linux".to_string(), "mv".to_string());
        mappings.insert("macos".to_string(), "mv".to_string());
        mappings.insert("windows".to_string(), "move".to_string());
        self.add_translation("mv", mappings);

        let mut mappings = HashMap::new();
        mappings.insert("linux".to_string(), "rm".to_string());
        mappings.insert("macos".to_string(), "rm".to_string());
        mappings.insert("windows".to_string(), "del".to_string());
        self.add_translation("rm", mappings);

        let mut mappings = HashMap::new();
        mappings.insert("linux".to_string(), "pwd".to_string());
        mappings.insert("macos".to_string(), "pwd".to_string());
        mappings.insert("windows".to_string(), "cd".to_string());
        self.add_translation("pwd", mappings);

        let mut mappings = HashMap::new();
        mappings.insert("linux".to_string(), "which".to_string());
        mappings.insert("macos".to_string(), "which".to_string());
        mappings.insert("windows".to_string(), "where".to_string());
        self.add_translation("which", mappings);

        let mut mappings = HashMap::new();
        mappings.insert("linux".to_string(), "ps".to_string());
        mappings.insert("macos".to_string(), "ps".to_string());
        mappings.insert("windows".to_string(), "tasklist".to_string());
        self.add_translation("ps", mappings);

        let mut mappings = HashMap::new();
        mappings.insert("linux".to_string(), "kill".to_string());
        mappings.insert("macos".to_string(), "kill".to_string());
        mappings.insert("windows".to_string(), "taskkill".to_string());
        self.add_translation("kill", mappings);

        let mut mappings = HashMap::new();
        mappings.insert("linux".to_string(), "grep".to_string());
        mappings.insert("macos".to_string(), "grep".to_string());
        mappings.insert("windows".to_string(), "findstr".to_string());
        self.add_translation("grep", mappings);

        let mut mappings = HashMap::new();
        mappings.insert("linux".to_string(), "clear".to_string());
        mappings.insert("macos".to_string(), "clear".to_string());
        mappings.insert("windows".to_string(), "cls".to_string());
        self.add_translation("clear", mappings);

        let mut mappings = HashMap::new();
        mappings.insert("linux".to_string(), "man".to_string());
        mappings.insert("macos".to_string(), "man".to_string());
        mappings.insert("windows".to_string(), "help".to_string());
        self.add_translation("man", mappings);

        let mut mappings = HashMap::new();
        mappings.insert("linux".to_string(), "mkdir".to_string());
        mappings.insert("macos".to_string(), "mkdir".to_string());
        mappings.insert("windows".to_string(), "mkdir".to_string());
        self.add_translation("mkdir", mappings);

        let mut mappings = HashMap::new();
        mappings.insert("linux".to_string(), "rmdir".to_string());
        mappings.insert("macos".to_string(), "rmdir".to_string());
        mappings.insert("windows".to_string(), "rmdir".to_string());
        self.add_translation("rmdir", mappings);

        let mut mappings = HashMap::new();
        mappings.insert("linux".to_string(), "echo".to_string());
        mappings.insert("macos".to_string(), "echo".to_string());
        mappings.insert("windows".to_string(), "echo".to_string());
        self.add_translation("echo", mappings);
    }

    pub fn add_translation(
        &mut self,
        command: &str,
        os_mappings: HashMap<String, String>,
    ) {
        self.translations.insert(
            command.to_string(),
            CommandTranslation {
                os_mappings,
                warnings: 0,
            },
        );
    }

    pub fn translate_command(
        &mut self,
        command: &str,
        os: &str,
        threat_info: &str,
        threat_weights: &[f64],
    ) -> CommandTranslationResult {
        let threat_statement = format!("Threat Information: {}", threat_info);
        let weights_statement = format!("Categorical Threat Weights: {:?}", threat_weights);

        let informational_output;
        let translated_command;

        if let Some(translation) = self.translations.get_mut(command) {
            translated_command = translation.os_mappings.get(os).cloned();
            translation.warnings += 1;

            if translation.warnings > self.max_warnings {
                informational_output = format!(
                    "Automatic translation disabled for '{}'. Add the command to the database if successful.\n{}\n{}",
                    command, threat_statement, weights_statement
                );
            } else {
                informational_output = format!(
                    "Your command was: {}\n{}\n{}\nTranslated Command: {}",
                    command,
                    threat_statement,
                    weights_statement,
                    translated_command.clone().unwrap_or_else(|| "<none>".to_string())
                );
            }
        } else {
            translated_command = None;
            informational_output = format!(
                "Your command was: {}\n{}\n{}\nNo translation available.",
                command, threat_statement, weights_statement
            );
        }

        CommandTranslationResult {
            original_command: command.to_string(),
            translated_command,
            informational_output,
        }
    }

    pub fn probe_system(&self, command: &str) -> String {
        match Command::new(command).arg("--help").output() {
            Ok(output) => {
                if output.status.success() {
                    String::from_utf8_lossy(&output.stdout).to_string()
                } else {
                    format!("Error: {}", String::from_utf8_lossy(&output.stderr))
                }
            }
            Err(e) => format!("Failed to execute '{} --help': {}", command, e),
        }
    }

    pub fn get_warnings(&self, command: &str) -> usize {
        self.translations.get(command).map_or(0, |t| t.warnings)
    }
}

/// Converts a path with backslashes to forward slashes.
pub fn to_unix_path(path: &str) -> String {
    path.replace('\\', "/")
}

/// Converts a path with forward slashes to Windows-style backslashes.
pub fn to_windows_path(path: &str) -> String {
    path.replace('/', "\\")
}

/// Normalizes a path to the current operating system's format.
pub fn normalize_path(path: &str) -> PathBuf {
    let converted_path = if cfg!(windows) {
        to_windows_path(path)
    } else {
        to_unix_path(path)
    };
    Path::new(&converted_path).to_path_buf()
}

/// Stub for normalizing paths in commands.
pub fn normalize_command_paths(command: &str) -> String {
    // TODO: Implement logic to determine paths from flags and normalize them.
    command.to_string()
}
