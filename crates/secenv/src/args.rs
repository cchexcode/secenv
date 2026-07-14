use {
    crate::manifest::Manifest,
    anyhow::{
        Context,
        Result,
    },
    path_clean::PathClean,
    std::{
        path::PathBuf,
        str::FromStr,
    },
    zeroize::Zeroizing,
};

#[derive(Debug)]
pub(crate) enum ManualFormat {
    Manpages,
    Markdown,
}

pub(crate) enum SealInput {
    Pointer(String),
    Direct(Zeroizing<String>),
    Stdin,
}

pub(crate) struct ChildCommand {
    program: String,
    arguments: Vec<String>,
}

impl ChildCommand {
    pub(crate) fn new(program: String, arguments: Vec<String>) -> Result<Self> {
        if program.is_empty() {
            anyhow::bail!("Command program must not be empty");
        }
        Ok(Self { program, arguments })
    }

    pub(crate) fn program(&self) -> &str {
        &self.program
    }

    pub(crate) fn arguments(&self) -> &[String] {
        &self.arguments
    }
}

pub(crate) enum UnlockAction {
    Print,
    Run(ChildCommand),
}

pub(crate) enum Command {
    Manual {
        path: PathBuf,
        format: ManualFormat,
    },
    Autocomplete {
        path: PathBuf,
        shell: clap_complete::Shell,
    },
    Unlock {
        manifest: Manifest,
        profile_name: String,
        action: UnlockAction,
        force: bool,
        timeout: Option<std::time::Duration>,
    },
    Seal {
        manifest: Manifest,
        profile_name: String,
        configured_file: String,
        input: SealInput,
    },
    Init {
        path: PathBuf,
        force: bool,
    },
}

pub(crate) struct ClapArgumentLoader {}

impl ClapArgumentLoader {
    fn get_absolute_path(matches: &clap::ArgMatches, name: &str) -> Result<PathBuf> {
        let path_str = matches
            .get_one::<String>(name)
            .with_context(|| format!("Missing path argument '{}'", name))?;
        let path = std::path::Path::new(path_str);
        if path.is_absolute() {
            Ok(path.to_path_buf().clean())
        } else {
            Ok(std::env::current_dir()?.join(path).clean())
        }
    }

    pub(crate) fn root_command() -> clap::Command {
        clap::Command::new(env!("CARGO_PKG_NAME"))
            .version(env!("CARGO_PKG_VERSION"))
            .about(env!("CARGO_PKG_DESCRIPTION"))
            .author("cchexcode <alexanderh.weber@outlook.com>")
            .propagate_version(true)
            .subcommand_required(false)
            .subcommand(
                clap::Command::new("man")
                    .about("Renders the manual.")
                    .arg(clap::Arg::new("out").short('o').long("out").required(true))
                    .arg(
                        clap::Arg::new("format")
                            .short('f')
                            .long("format")
                            .value_parser(["manpages", "markdown"])
                            .required(true),
                    ),
            )
            .subcommand(
                clap::Command::new("autocomplete")
                    .about("Renders shell completion scripts.")
                    .arg(clap::Arg::new("out").short('o').long("out").required(true))
                    .arg(
                        clap::Arg::new("shell")
                            .short('s')
                            .long("shell")
                            .value_parser(["bash", "zsh", "fish", "elvish", "powershell"])
                            .required(true),
                    ),
            )
            .subcommand(
                clap::Command::new("unlock")
                    .about("Unlocks encrypted values and optionally executes a command.")
                    .arg(
                        clap::Arg::new("config")
                            .short('c')
                            .long("config")
                            .required(false)
                            .default_value("secenv.conf"),
                    )
                    .arg(
                        clap::Arg::new("profile")
                            .short('p')
                            .long("profile")
                            .required(false)
                            .default_value("default"),
                    )
                    .arg(
                        clap::Arg::new("force")
                            .short('f')
                            .long("force")
                            .action(clap::ArgAction::SetTrue)
                            .help("Overwrite existing files defined in the manifest"),
                    )
                    .arg(
                        clap::Arg::new("timeout")
                            .long("timeout")
                            .value_name("SECONDS")
                            .value_parser(clap::value_parser!(u64).range(1..))
                            .requires("command")
                            .help("Maximum subcommand runtime in seconds"),
                    )
                    .arg(
                        clap::Arg::new("command")
                            .help("Command to execute with environment variables set")
                            .num_args(1..)
                            .last(true)
                            .value_name("COMMAND"),
                    ),
            )
            .subcommand(
                clap::Command::new("seal")
                    .about("Encrypts a value for a configured sealed HOCON or JSON file.")
                    .arg(
                        clap::Arg::new("config")
                            .short('c')
                            .long("config")
                            .required(false)
                            .default_value("secenv.conf"),
                    )
                    .arg(
                        clap::Arg::new("profile")
                            .short('p')
                            .long("profile")
                            .required(false)
                            .default_value("default"),
                    )
                    .arg(
                        clap::Arg::new("configured_file")
                            .long("for")
                            .value_name("CONFIGURED_PATH")
                            .required(true)
                            .help("Configured in-place path or template output path"),
                    )
                    .arg(
                        clap::Arg::new("path")
                            .long("path")
                            .value_name("JSON_POINTER")
                            .required(false)
                            .help("RFC 6901 JSON Pointer to replace in the configured source document"),
                    )
                    .arg(
                        clap::Arg::new("value")
                            .value_name("VALUE")
                            .conflicts_with("path")
                            .help("Plaintext value to seal; reads piped stdin when omitted"),
                    ),
            )
            .subcommand(
                clap::Command::new("init")
                    .about("Initialize a new secenv configuration file.")
                    .arg(
                        clap::Arg::new("path")
                            .short('p')
                            .long("path")
                            .required(false)
                            .default_value("secenv.conf")
                            .help("Path for the new HOCON config file"),
                    )
                    .arg(
                        clap::Arg::new("force")
                            .short('f')
                            .long("force")
                            .action(clap::ArgAction::SetTrue)
                            .help("Overwrite existing file"),
                    ),
            )
    }

    pub(crate) fn load() -> Result<Command> {
        let mut command = Self::root_command().get_matches();

        let command = if let Some(subc) = command.subcommand_matches("man") {
            Command::Manual {
                path: Self::get_absolute_path(subc, "out")?,
                format: match subc
                    .get_one::<String>("format")
                    .context("Missing manual format")?
                    .as_str()
                {
                    | "manpages" => ManualFormat::Manpages,
                    | "markdown" => ManualFormat::Markdown,
                    | _ => return Err(anyhow::anyhow!("argument \"format\": unknown format")),
                },
            }
        } else if let Some(subc) = command.subcommand_matches("autocomplete") {
            Command::Autocomplete {
                path: Self::get_absolute_path(subc, "out")?,
                shell: clap_complete::Shell::from_str(
                    subc.get_one::<String>("shell")
                        .context("Missing completion shell")?
                        .as_str(),
                )
                .map_err(|error| anyhow::anyhow!("Invalid completion shell: {}", error))?,
            }
        } else if let Some(subc) = command.subcommand_matches("unlock") {
            let config_path = Self::get_absolute_path(subc, "config")?;
            let cfg = Manifest::load(config_path)?;

            let profile_name = subc.get_one::<String>("profile").context("Missing profile name")?;

            if !cfg.profiles.contains_key(profile_name) {
                return Err(anyhow::anyhow!("Profile '{}' not found in config", profile_name));
            }

            let action = match subc.get_many::<String>("command") {
                | Some(mut values) => {
                    let program = values.next().context("Command is missing its program")?.clone();
                    UnlockAction::Run(ChildCommand::new(program, values.cloned().collect())?)
                },
                | None => UnlockAction::Print,
            };
            let force = subc.get_flag("force");
            let timeout = subc
                .get_one::<u64>("timeout")
                .map(|seconds| std::time::Duration::from_secs(*seconds));

            Command::Unlock {
                manifest: cfg,
                profile_name: profile_name.clone(),
                action,
                force,
                timeout,
            }
        } else if command.subcommand_name() == Some("seal") {
            let (_, mut subc) = command.remove_subcommand().context("Missing seal arguments")?;
            let configured_file = subc
                .remove_one::<String>("configured_file")
                .context("Missing --for path")?;
            let input = match (subc.remove_one::<String>("path"), subc.remove_one::<String>("value")) {
                | (Some(pointer), None) => SealInput::Pointer(pointer),
                | (None, Some(value)) => SealInput::Direct(Zeroizing::new(value)),
                | (None, None) => SealInput::Stdin,
                | (Some(_), Some(_)) => anyhow::bail!("VALUE conflicts with --path"),
            };
            let config_path = Self::get_absolute_path(&subc, "config")?;
            let cfg = Manifest::load(config_path)?;

            let profile_name = subc
                .get_one::<String>("profile")
                .context("Missing profile name")?
                .clone();
            if !cfg.profiles.contains_key(&profile_name) {
                return Err(anyhow::anyhow!("Profile '{}' not found in config", profile_name));
            }

            Command::Seal {
                manifest: cfg,
                profile_name,
                configured_file,
                input,
            }
        } else if let Some(subc) = command.subcommand_matches("init") {
            let config_path = Self::get_absolute_path(subc, "path")?;
            let force = subc.get_flag("force");

            Command::Init {
                path: config_path,
                force,
            }
        } else {
            anyhow::bail!("unknown command")
        };

        Ok(command)
    }
}

#[cfg(test)]
mod tests {
    use super::ClapArgumentLoader;

    #[test]
    fn seal_accepts_a_direct_value_for_a_configured_file() {
        let matches = ClapArgumentLoader::root_command()
            .try_get_matches_from(["secenv", "seal", "--for", "./application.conf", "password"])
            .unwrap();
        let seal = matches.subcommand_matches("seal").unwrap();

        assert_eq!(seal.get_one::<String>("configured_file").unwrap(), "./application.conf");
        assert_eq!(seal.get_one::<String>("value").unwrap(), "password");
    }

    #[test]
    fn seal_value_conflicts_with_path_and_file_is_no_longer_accepted() {
        assert!(ClapArgumentLoader::root_command()
            .try_get_matches_from([
                "secenv",
                "seal",
                "--for",
                "./application.conf",
                "password",
                "--path",
                "/database/password",
            ])
            .is_err());
        assert!(ClapArgumentLoader::root_command()
            .try_get_matches_from(["secenv", "seal", "--file", "./application.conf"])
            .is_err());
    }

    #[test]
    fn unlock_timeout_requires_a_command_and_positive_seconds() {
        assert!(ClapArgumentLoader::root_command()
            .try_get_matches_from(["secenv", "unlock", "--timeout", "1", "--", "true"])
            .is_ok());
        assert!(ClapArgumentLoader::root_command()
            .try_get_matches_from(["secenv", "unlock", "--timeout", "1"])
            .is_err());
        assert!(ClapArgumentLoader::root_command()
            .try_get_matches_from(["secenv", "unlock", "--timeout", "0", "--", "true"])
            .is_err());
    }
}
