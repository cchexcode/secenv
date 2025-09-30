mod args;
mod gcp;
mod gpg;
mod manifest;
mod pgp;
mod reference;

use {
    anyhow::{
        Context,
        Result,
    },
    args::ManualFormat,
    regex::Regex,
    std::{
        collections::HashMap,
        process::Command,
        path::Path,
    },
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
        | crate::args::Command::Unlock { manifest, profile_name, command, force } => {
            let mut env_vars = HashMap::new();
            let mut pgp_manager = crate::pgp::PgpManager::new().context("Failed to initialize PGP manager")?;

            let profile = manifest
                .profiles
                .get(profile_name.as_str())
                .with_context(|| format!("Profile '{}' not found in manifest", profile_name))?;

            for (key, value) in profile.env.vars.iter() {
                match value.inner.get_value(&mut pgp_manager) {
                    | Ok(val) => {
                        env_vars.insert(key.clone(), val);
                    },
                    | Err(e) => {
                        eprintln!("Error getting value for {}: {}", key, e);
                        return Err(e);
                    },
                }
            }

            // Prepare files from manifest before running command
            let mut created_files: Vec<String> = Vec::new();
            for (file_path, content) in profile.files.iter() {
                let absolute_path = Path::new(file_path);
                if absolute_path.exists() && !force {
                    return Err(anyhow::anyhow!(
                        "File '{}' already exists. Use --force to overwrite.",
                        absolute_path.display()
                    ));
                }

                let value = content.inner.get_value(&mut pgp_manager)?;
                if let Some(parent) = absolute_path.parent() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("Failed to create directories for {}", absolute_path.display()))?;
                }
                std::fs::write(&absolute_path, value)
                    .with_context(|| format!("Failed to write file: {}", absolute_path.display()))?;
                created_files.push(absolute_path.to_string_lossy().to_string());
            }

            let exec_status: Result<Option<std::process::ExitStatus>> = match command {
                | Some(cmd_args) if !cmd_args.is_empty() => {
                    let status = execute_command_with_env(&cmd_args, &env_vars, &profile.env.keep)?;
                    Ok(Some(status))
                },
                | _ => {
                    for (key, value) in env_vars {
                        println!("{}={}", key, value);
                    }
                    Ok(None)
                },
            };

            // Cleanup files after command execution or printing envs
            let mut cleanup_error: Option<anyhow::Error> = None;
            for file in created_files.iter() {
                if let Err(e) = std::fs::remove_file(file) {
                    cleanup_error = Some(anyhow::anyhow!(
                        "Failed to remove file '{}': {}",
                        file,
                        e
                    ));
                }
            }

            if let Some(err) = cleanup_error {
                eprintln!("{}", err);
            }

            match exec_status? {
                | Some(status) => {
                    if !status.success() {
                        if let Some(code) = status.code() {
                            std::process::exit(code);
                        } else {
                            std::process::exit(1);
                        }
                    }
                    Ok(())
                },
                | None => Ok(()),
            }
        },
        | args::Command::Init { path, force } => {
            if path.exists() && !force {
                return Err(anyhow::anyhow!(
                    "Config file '{}' already exists. Use --force to overwrite.",
                    path.display()
                ));
            }

            let example_config = r#"
version = "0.1.0"

profiles = {
  default = {
    env = {
      # keep = ["^PATH$", "^LC_.*"]  # Uncomment to only preserve matching host env vars
      vars = {
        # Example: plain literal value
        APP_NAME.plain.literal = "myapp"

        # Example: plain base64-encoded value
        # DB_HOST.plain.base64 = "bG9jYWxob3N0"  # "localhost" in base64

        # Example: secure value using PGP secret from file
        # SECRET_TOKEN.secure {
        #   secret.pgp.file = "/path/to/private.key"
        #   value.literal = "-----BEGIN PGP MESSAGE-----..."
        # }

        # Example: secure value using PGP secret from GCP (fully qualified resource)
        # API_KEY.secure {
        #   secret.pgp.gcp.secret = "projects/myproject/secrets/my-pgp-key"
        #   # secret.pgp.gcp.version = "latest"  # optional
        #   value.base64 = "<base64-encoded-ASCII-armored-message>"
        # }

        # Example: secure value using inline private key
        # ENCRYPTED_TOKEN.secure {
        #   secret.pgp.literal.literal = """
        #   -----BEGIN PGP PRIVATE KEY BLOCK-----
        #   ...
        #   -----END PGP PRIVATE KEY BLOCK-----
        #   """
        #   value.literal = "-----BEGIN PGP MESSAGE-----..."
        # }
      }
    }
  }
}
"#;

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
    keep_env_vars: &Option<Vec<String>>,
) -> Result<std::process::ExitStatus> {
    if cmd_args.is_empty() {
        return Err(anyhow::anyhow!("No command provided"));
    }

    let program = &cmd_args[0];
    let args = &cmd_args[1..];

    let mut command = Command::new(program);
    command.args(args);

    match keep_env_vars {
        | None => {
            for (key, value) in env_vars {
                command.env(key, value);
            }
        },
        | Some(patterns) => {
            command.env_clear();

            let compiled_patterns: Result<Vec<Regex>, _> = patterns.iter().map(|pattern| Regex::new(pattern)).collect();

            let compiled_patterns = compiled_patterns.with_context(|| "Failed to compile regex patterns")?;

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
        },
    }

    let status = command
        .status()
        .with_context(|| format!("Failed to execute command: {}", program))?;

    Ok(status)
}
