use std::collections::HashMap;
use std::process::Command;
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

impl CommandTranslator {
    pub fn new() -> Self {
        Self {
            translations: HashMap::new(),
            max_warnings: MAX_TRANSLATION_WARNINGS,
        }
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
    ) -> String {
        let threat_statement = format!("Threat Information: {}", threat_info);
        let weights_statement = format!("Categorical Threat Weights: {:?}", threat_weights);

        if let Some(translation) = self.translations.get_mut(command) {
            let translated_command = translation
                .os_mappings
                .get(os)
                .cloned()
                .unwrap();

            translation.warnings += 1;
            if translation.warnings > self.max_warnings {
                return format!(
                    "Automatic translation disabled for '{}'. Add the command to the database if successful.\n{}\n{}",
                    command, threat_statement, weights_statement
                );
            }

            format!(
                "Your command was: {}\n{}\n{}\nTranslated Command: {}",
                command, threat_statement, weights_statement, translated_command
            )
        } else {
            format!(
                "Your command was: {}\n{}\n{}\nNo translation available.",
                command, threat_statement, weights_statement
            )
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
