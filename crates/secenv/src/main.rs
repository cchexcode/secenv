mod args;
mod gcp;
mod gpg;
mod manifest;
mod pgp;
mod reference;

use {
    crate::manifest::{FromLocation, FromLocationWrapper}, anyhow::{
        Context,
        Result,
    }, args::ManualFormat, manifest::{
        Content,
        ContentWrapper,
        EncodedValue,
        EncodedValueWrapper,
        Manifest,
        ManifestEnv,
        ManifestProfile,
        Secret,
        SecretAllocation,
        SecretAllocationWrapper,
        SecretWrapper,
    }, regex::Regex, std::{
        collections::HashMap,
        path::Path,
        process::Command,
    }
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
        | crate::args::Command::Unlock {
            manifest,
            profile_name,
            command,
            force,
        } => {
            let mut env_vars = HashMap::new();
            let mut pgp_manager = crate::pgp::PgpManager::new().context("Failed to initialize PGP manager")?;

            let profile = manifest
                .profiles
                .get(profile_name.as_str())
                .with_context(|| format!("Profile '{}' not found in manifest", profile_name))?;

            for from_location in profile.env.from.iter() {
                match &from_location.inner {
                    | FromLocation::GCS { secret, version } => {
                        let gcp = crate::gcp::GcpSecretManager::new().context("Failed to initialize GCP Secret Manager client")?;
                        let spec = crate::gcp::GcpSecretSpec {
                            secret: secret.to_string(),
                            version: version.as_ref().map(|v| v.to_string()),
                        };
                        let value = gcp.access_secret(&spec)?;
                        parse_env_lines(&value, |key, val| {
                            env_vars.insert(key.to_string(), val.to_string());
                        });
                    },
                    | FromLocation::File(file_path) => {
                        let value = std::fs::read_to_string(file_path)?;
                        parse_env_lines(&value, |key, val| {
                            env_vars.insert(key.to_string(), val.to_string());
                        });
                    },
                }
            }
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
                    let status = exec_command(&cmd_args, &env_vars, &profile.env.keep)?;
                    Ok(Some(status))
                },
                | _ => {
                    for (key, value) in env_vars {
                        println!("{}={}", key, value);
                    }
                    Ok(None)
                },
            };

            let mut cleanup_error: Option<anyhow::Error> = None;
            for file in created_files.iter() {
                if let Err(e) = std::fs::remove_file(file) {
                    cleanup_error = Some(anyhow::anyhow!("Failed to remove file '{}': {}", file, e));
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

            let mut profiles = HashMap::new();
            let mut vars = HashMap::new();

            vars.insert("APP_NAME".to_string(), ContentWrapper {
                inner: Content::Plain(EncodedValue::Literal("myapp".to_string())),
            });

            vars.insert("DB_HOST_EXAMPLE".to_string(), ContentWrapper {
                inner: Content::Plain(EncodedValue::Base64("bG9jYWxob3N0".to_string())),
            });

            vars.insert("SECRET_TOKEN_EXAMPLE".to_string(), ContentWrapper {
                inner: Content::Secure {
                    secret: SecretWrapper {
                        inner: Secret::PGP(SecretAllocationWrapper {
                            inner: SecretAllocation::File("/path/to/private.key".to_string()),
                        }),
                    },
                    value: EncodedValueWrapper {
                        inner: EncodedValue::Literal("-----BEGIN PGP MESSAGE-----...".to_string()),
                    },
                },
            });

            vars.insert("API_KEY_EXAMPLE".to_string(), ContentWrapper {
                inner: Content::Secure {
                    secret: SecretWrapper {
                        inner: Secret::PGP(SecretAllocationWrapper {
                            inner: SecretAllocation::Gcp {
                                secret: "projects/myproject/secrets/my-pgp-key".to_string(),
                                version: Some("latest".to_string()),
                            },
                        }),
                    },
                    value: EncodedValueWrapper {
                        inner: EncodedValue::Base64("<base64-encoded-ASCII-armored-message>".to_string()),
                    },
                },
            });

            vars.insert("GPG_ENCRYPTED_EXAMPLE".to_string(), ContentWrapper {
                inner: Content::Secure {
                    secret: SecretWrapper {
                        inner: Secret::PGP(SecretAllocationWrapper {
                            inner: SecretAllocation::Gpg {
                                fingerprint: "1E1BAC706C352094D490D5393F5167F1F3002043".to_string(),
                            },
                        }),
                    },
                    value: EncodedValueWrapper {
                        inner: EncodedValue::Base64("<base64-encoded-ASCII-armored-message>".to_string()),
                    },
                },
            });

            let mut files = HashMap::new();

            files.insert("./config.json".to_string(), ContentWrapper {
                inner: Content::Plain(EncodedValue::Literal("{\"key\": \"value\"}".to_string())),
            });

            files.insert("./credentials.key".to_string(), ContentWrapper {
                inner: Content::Secure {
                    secret: SecretWrapper {
                        inner: Secret::PGP(SecretAllocationWrapper {
                            inner: SecretAllocation::File("/path/to/private.key".to_string()),
                        }),
                    },
                    value: EncodedValueWrapper {
                        inner: EncodedValue::Literal("-----BEGIN PGP MESSAGE-----...".to_string()),
                    },
                },
            });

            let default_profile = ManifestProfile {
                files,
                env: ManifestEnv {
                    keep: Some(vec!["^PATH$".to_string(), "^LC_.*".to_string()]),
                    vars,
                    from: vec![
                        FromLocationWrapper {
                            inner: FromLocation::GCS {
                                secret: "projects/myproject/secrets/my-gcs-secret".to_string(),
                                version: Some("latest".to_string()),
                            },
                        },
                    ],
                },
            };

            profiles.insert("default".to_string(), default_profile);

            let manifest = Manifest {
                version: env!("CARGO_PKG_VERSION").to_string(),
                profiles,
            };

            let json_config =
                serde_json::to_string_pretty(&manifest).context("Failed to serialize example config to JSON")?;

            std::fs::write(&path, json_config)
                .with_context(|| format!("Failed to write config file: {}", path.display()))?;

            println!("Created example configuration file: {}", path.display());
            println!("Edit the file to add your own variables and PGP keys.");
            println!("Note: Remove '_EXAMPLE' suffix from variable names before using them.");
            Ok(())
        },
    }
}

fn parse_env_lines<F>(value: &str, mut callback: F)
where
    F: FnMut(&str, &str),
{
    for line in value.lines() {
        if let Some(pos) = line.find('=') {
            let key = line[..pos].trim();
            let val = line[pos + 1..].trim();
            if !key.is_empty() {
                callback(key, val);
            }
        }
    }
}

fn exec_command(
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
