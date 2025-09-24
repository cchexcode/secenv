mod args;
mod manifest;
mod gcp;
mod pgp;
mod reference;

use {
    anyhow::{
        Context,
        Result,
    },
    args::ManualFormat,
    std::collections::HashMap,
};

#[tokio::main]
async fn main() -> Result<()> {
    let cmd = crate::args::ClapArgumentLoader::load()?;

    match cmd.command {
        | crate::args::Command::Manual { path, format } => {
            std::fs::create_dir_all(&path)
                .with_context(|| format!("Failed to create directory: {}", path.display()))?;
            match format {
                | ManualFormat::Manpages => {
                    crate::reference::build_manpages(&path)?;
                },
                | ManualFormat::Markdown => {
                    crate::reference::build_markdown(&path)?;
                },
            }
            Ok(())
        },
        | crate::args::Command::Autocomplete { path, shell } => {
            std::fs::create_dir_all(&path)
                .with_context(|| format!("Failed to create directory: {}", path.display()))?;
            crate::reference::build_shell_completion(&path, &shell)?;
            Ok(())
        },
        | crate::args::Command::Unlock { profile, command } => {
            let mut env_vars = HashMap::new();
            let mut secret_cache: HashMap<String, String> = HashMap::new();
            
            for (key, value) in profile.env.vars.iter() {
                match value.get_value_with_cache(&mut secret_cache) {
                    | Ok(val) => {
                        env_vars.insert(key.clone(), val);
                    },
                    | Err(e) => {
                        eprintln!("Error decrypting {}: {}", key, e);
                        return Err(e);
                    },
                }
            }

            match command {
                Some(cmd_args) if !cmd_args.is_empty() => {
                    execute_command_with_env(&cmd_args, &env_vars, &profile.env.keep)
                },
                _ => {
                    for (key, value) in env_vars {
                        println!("{}={}", key, value);
                    }
                    Ok(())
                }
            }
        },
        | args::Command::Init { path, force } => {
            if path.exists() && !force {
                return Err(anyhow::anyhow!(
                    "Config file '{}' already exists. Use --force to overwrite.",
                    path.display()
                ));
            }

            let example_config = "";
            
            std::fs::write(&path, example_config)
                .with_context(|| format!("Failed to write config file: {}", path.display()))?;
            
            println!("Created example configuration file: {}", path.display());
            println!("Edit the file to add your own variables and PGP keys.");
            Ok(())
        },
    }
}

/// Execute a command with the specified environment variables
fn execute_command_with_env(
    cmd_args: &[String], 
    env_vars: &HashMap<String, String>, 
    keep_env_vars: &Option<Vec<String>>
) -> Result<()> {
    use std::process::Command;
    use regex::Regex;
    
    if cmd_args.is_empty() {
        return Err(anyhow::anyhow!("No command provided"));
    }

    let program = &cmd_args[0];
    let args = &cmd_args[1..];

    let mut command = Command::new(program);
    command.args(args);

    match keep_env_vars {
        None => {
            for (key, value) in env_vars {
                command.env(key, value);
            }
        }
        Some(patterns) => {
            command.env_clear();
            
            let compiled_patterns: Result<Vec<Regex>, _> = patterns
                .iter()
                .map(|pattern| Regex::new(pattern))
                .collect();
            
            let compiled_patterns = compiled_patterns
                .with_context(|| "Failed to compile regex patterns")?;
            
            for (env_key, env_value) in std::env::vars() {
                for pattern in &compiled_patterns {
                    if pattern.is_match(&env_key) {
                        command.env(&env_key, &env_value);
                        break;
                    }
                }
            }
            
            for (key, value) in env_vars {
                command.env(key, value);
            }
        }
    }

    let status = command.status()
        .with_context(|| format!("Failed to execute command: {}", program))?;

    if !status.success() {
        if let Some(code) = status.code() {
            std::process::exit(code);
        } else {
            std::process::exit(1);
        }
    }

    Ok(())
}
