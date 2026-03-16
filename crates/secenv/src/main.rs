mod args;
mod aws;
mod gcp;
mod gpg;
mod manifest;
mod pgp;
mod reference;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use {
    anyhow::{
        Context,
        Result,
    },
    args::ManualFormat,
    manifest::Manifest,
    std::{
        collections::HashMap,
        path::{
            Path,
            PathBuf,
        },
        process::Command,
        sync::{
            atomic::{
                AtomicBool,
                Ordering,
            },
            Arc,
            Mutex,
        },
    },
    zeroize::Zeroize,
};

#[tokio::main]
async fn main() -> Result<()> {
    let cmd = crate::args::ClapArgumentLoader::load()?;

    match cmd.command {
        | crate::args::Command::Manual { path, format } => {
            std::fs::create_dir_all(&path)
                .with_context(|| format!("Failed to create directory: {}", path.display()))?;
            let builder = crate::reference::ReferenceBuilder::new();
            match format {
                | ManualFormat::Manpages => builder.build_manpages(&path)?,
                | ManualFormat::Markdown => builder.build_markdown(&path)?,
            }
            Ok(())
        },
        | crate::args::Command::Autocomplete { path, shell } => {
            std::fs::create_dir_all(&path)
                .with_context(|| format!("Failed to create directory: {}", path.display()))?;
            let builder = crate::reference::ReferenceBuilder::new();
            builder.build_shell_completion(&path, &shell)?;
            Ok(())
        },
        | crate::args::Command::Unlock {
            manifest,
            profile_name,
            command,
            force,
        } => {
            manifest.warn_if_insecure_permissions();

            let mut pgp_manager = crate::pgp::PgpManager::new().context("Failed to initialize PGP manager")?;

            let profile = manifest
                .profiles
                .get(profile_name.as_str())
                .with_context(|| format!("Profile '{}' not found in manifest", profile_name))?;

            let mut env_vars = EnvParser::load_from_profile(profile)?;

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

            let base_dir = std::env::current_dir().context("Failed to get current directory")?;
            let file_manager = SecretFileManager::new(base_dir);

            file_manager.validate_paths(profile.files.keys())?;

            let interrupted = Arc::new(AtomicBool::new(false));
            let interrupted_clone = interrupted.clone();
            let cleanup_handle = file_manager.created_files.clone();

            let ctrlc_handler = tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    interrupted_clone.store(true, Ordering::SeqCst);
                    SecretFileManager::cleanup(&cleanup_handle);
                    std::process::exit(130);
                }
            });

            for (file_path, content) in profile.files.iter() {
                let value = match content.inner.get_value(&mut pgp_manager) {
                    | Ok(v) => v,
                    | Err(e) => {
                        file_manager.cleanup_all();
                        return Err(e);
                    },
                };
                if let Err(e) = file_manager.write(file_path, &value, force) {
                    file_manager.cleanup_all();
                    return Err(e);
                }
            }

            let exec_status: Result<Option<std::process::ExitStatus>> = match command {
                | Some(cmd_args) if !cmd_args.is_empty() => {
                    let executor = CommandExecutor::new(&cmd_args, &env_vars, &profile.env.keep);
                    let status = executor.run()?;
                    Ok(Some(status))
                },
                | _ => {
                    for (key, value) in &env_vars {
                        println!(
                            "export {}={}",
                            EnvParser::shell_escape(key),
                            EnvParser::shell_escape(value)
                        );
                    }
                    Ok(None)
                },
            };

            ctrlc_handler.abort();
            file_manager.cleanup_all();

            for (_, val) in env_vars.iter_mut() {
                val.zeroize();
            }
            pgp_manager.clear_cache();

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

            let manifest = Manifest::example(path.clone());

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

/// Handles parsing and validation of environment variable key=value data.
struct EnvParser;

impl EnvParser {
    /// Load environment variables from all `from` sources in a profile.
    fn load_from_profile(profile: &manifest::ManifestProfile) -> Result<HashMap<String, String>> {
        let mut env_vars = HashMap::new();
        for from_location in profile.env.from.iter() {
            let value = from_location.inner.resolve()?;
            Self::parse_lines(&value, |key, val| {
                env_vars.insert(key.to_string(), val.to_string());
            })?;
        }
        Ok(env_vars)
    }

    /// Parse KEY=VALUE lines from a string, validating keys and rejecting
    /// malformed input.
    fn parse_lines<F>(value: &str, mut callback: F) -> Result<()>
    where F: FnMut(&str, &str) {
        for (line_num, line) in value.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let line_content = trimmed.strip_prefix("export ").unwrap_or(trimmed);

            if let Some(pos) = line_content.find('=') {
                let key = line_content[..pos].trim();
                let val = line_content[pos + 1..].trim();
                if key.is_empty() {
                    anyhow::bail!("Empty key at line {} in env source", line_num + 1);
                }
                if !Self::is_valid_key(key) {
                    anyhow::bail!(
                        "Invalid env var key '{}' at line {} (must be alphanumeric/underscore only)",
                        key,
                        line_num + 1
                    );
                }
                callback(key, val);
            } else {
                anyhow::bail!(
                    "Malformed line {} in env source (missing '='): '{}'",
                    line_num + 1,
                    trimmed
                );
            }
        }
        Ok(())
    }

    /// Validate that an env var key contains only safe characters.
    fn is_valid_key(key: &str) -> bool {
        !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    }

    /// Shell-escape a string value for safe use in eval contexts.
    fn shell_escape(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

/// Manages creation, tracking, and cleanup of temporary secret files on disk.
struct SecretFileManager {
    base_dir: PathBuf,
    created_files: Arc<Mutex<Vec<String>>>,
}

impl SecretFileManager {
    fn new(base_dir: PathBuf) -> Self {
        Self {
            base_dir,
            created_files: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Validate that all file paths are within the base directory.
    fn validate_paths<'a>(&self, paths: impl Iterator<Item=&'a String>) -> Result<()> {
        let canonical_base = self
            .base_dir
            .canonicalize()
            .with_context(|| format!("Failed to canonicalize base directory: {}", self.base_dir.display()))?;

        for file_path in paths {
            let path = Self::resolve_absolute(file_path)?;
            if let Some(parent) = path.parent() {
                if parent.exists() {
                    let canonical_parent = parent
                        .canonicalize()
                        .with_context(|| format!("Failed to canonicalize parent: {}", parent.display()))?;
                    if !canonical_parent.starts_with(&canonical_base) {
                        anyhow::bail!(
                            "File path '{}' escapes the project directory. Files must be within '{}'.",
                            file_path,
                            canonical_base.display()
                        );
                    }
                } else {
                    let cleaned = path_clean::PathClean::clean(&path);
                    if !cleaned.starts_with(&canonical_base) {
                        anyhow::bail!(
                            "File path '{}' escapes the project directory. Files must be within '{}'.",
                            file_path,
                            canonical_base.display()
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Write secret content to a file with restrictive permissions, tracking it
    /// for cleanup.
    fn write(&self, file_path: &str, content: &str, force: bool) -> Result<()> {
        let absolute_path = Self::resolve_absolute(file_path)?;

        if absolute_path.exists() && !force {
            anyhow::bail!(
                "File '{}' already exists. Use --force to overwrite.",
                absolute_path.display()
            );
        }

        if let Some(parent) = absolute_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directories for {}", absolute_path.display()))?;
        }

        Self::write_with_permissions(&absolute_path, content)
            .with_context(|| format!("Failed to write file {}", absolute_path.display()))?;

        self.created_files
            .lock()
            .unwrap()
            .push(absolute_path.to_string_lossy().to_string());

        Ok(())
    }

    /// Write file content with 0o600 permissions on Unix.
    fn write_with_permissions(path: &Path, content: &str) -> std::io::Result<()> {
        use std::io::Write;

        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);

        #[cfg(unix)]
        opts.mode(0o600);

        let mut file = opts.open(path)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }

    /// Remove all tracked files.
    fn cleanup_all(&self) {
        Self::cleanup(&self.created_files);
    }

    /// Remove all files referenced by the shared file list.
    fn cleanup(files: &Arc<Mutex<Vec<String>>>) {
        let Ok(files) = files.lock() else {
            eprintln!("WARNING: Failed to acquire lock for file cleanup");
            return;
        };
        for file in files.iter() {
            if let Err(e) = std::fs::remove_file(file) {
                eprintln!("Failed to remove file '{}': {}", file, e);
            }
        }
    }

    /// Resolve a file path string to an absolute PathBuf.
    fn resolve_absolute(file_path: &str) -> Result<PathBuf> {
        let path = Path::new(file_path);
        if path.is_absolute() {
            Ok(path.to_path_buf())
        } else {
            Ok(std::env::current_dir()
                .context("Failed to get current directory")?
                .join(path))
        }
    }
}

/// Builds and executes a child process with configured environment variables.
struct CommandExecutor<'a> {
    cmd_args: &'a [String],
    env_vars: &'a HashMap<String, String>,
    keep_env_vars: &'a Option<Vec<String>>,
}

impl<'a> CommandExecutor<'a> {
    fn new(
        cmd_args: &'a [String],
        env_vars: &'a HashMap<String, String>,
        keep_env_vars: &'a Option<Vec<String>>,
    ) -> Self {
        Self {
            cmd_args,
            env_vars,
            keep_env_vars,
        }
    }

    fn run(&self) -> Result<std::process::ExitStatus> {
        if self.cmd_args.is_empty() {
            return Err(anyhow::anyhow!("No command provided"));
        }

        let program = &self.cmd_args[0];
        let args = &self.cmd_args[1..];

        let mut command = Command::new(program);
        command.args(args);

        self.configure_env(&mut command)?;

        let status = command
            .status()
            .with_context(|| format!("Failed to execute command: {}", program))?;

        Ok(status)
    }

    fn configure_env(&self, command: &mut Command) -> Result<()> {
        match self.keep_env_vars {
            | None => {
                for (key, value) in self.env_vars {
                    command.env(key, value);
                }
            },
            | Some(patterns) => {
                command.env_clear();

                let compiled_patterns: Result<Vec<regex::Regex>, _> = patterns
                    .iter()
                    .map(|pattern| {
                        regex::Regex::new(pattern)
                            .with_context(|| format!("Invalid regex pattern in env.keep: '{}'", pattern))
                    })
                    .collect();

                let compiled_patterns = compiled_patterns?;

                for (env_key, env_value) in std::env::vars() {
                    for pattern in &compiled_patterns {
                        if pattern.is_match(&env_key) {
                            command.env(&env_key, &env_value);
                            break;
                        }
                    }
                }

                for (key, value) in self.env_vars {
                    command.env(key, value);
                }
            },
        }
        Ok(())
    }
}
