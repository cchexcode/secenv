use {
    crate::manifest::Manifest,
    anyhow::{
        Context,
        Result,
    },
    clap::Arg,
    path_clean::PathClean,
    std::{
        path::PathBuf,
        str::FromStr,
    },
};

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Privilege {
    Normal,
    Experimental,
}

#[derive(Debug)]
pub(crate) enum ManualFormat {
    Manpages,
    Markdown,
}

#[derive(Debug)]
pub(crate) struct CallArgs {
    pub privileges: Privilege,
    pub command: Command,
}

impl CallArgs {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.privileges == Privilege::Experimental {
            return Ok(());
        }

        match &self.command {
            | _ => (),
        }

        Ok(())
    }
}

#[derive(Debug)]
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
        command: Option<Vec<String>>,
    },
    Init {
        path: PathBuf,
        force: bool,
    },
}

pub(crate) struct ClapArgumentLoader {}

impl ClapArgumentLoader {
    fn get_absolute_path(matches: &clap::ArgMatches, name: &str) -> Result<PathBuf> {
        let path_str: &String = matches.get_one(name).unwrap();
        let path = std::path::Path::new(path_str);
        if path.is_absolute() {
            Ok(path.to_path_buf().clean())
        } else {
            Ok(std::env::current_dir()?.join(path).clean())
        }
    }

    pub(crate) fn root_command() -> clap::Command {
        let root = clap::Command::new(env!("CARGO_PKG_NAME"))
            .version(env!("CARGO_PKG_VERSION"))
            .about(env!("CARGO_PKG_DESCRIPTION"))
            .author("cchexcode <alexanderh.weber@outlook.com>")
            .propagate_version(true)
            .subcommand_required(false)
            .args([Arg::new("experimental")
                .short('e')
                .long("experimental")
                .help("Enables experimental features.")
                .num_args(0)])
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
                        clap::Arg::new("command")
                            .help("Command to execute with environment variables set")
                            .num_args(0..)
                            .last(true)
                            .value_name("COMMAND"),
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
            );
        root
    }

    pub(crate) fn load() -> Result<CallArgs> {
        let command = Self::root_command().get_matches();

        let privileges = if command.get_flag("experimental") {
            Privilege::Experimental
        } else {
            Privilege::Normal
        };

        let cmd = if let Some(subc) = command.subcommand_matches("man") {
            Command::Manual {
                path: Self::get_absolute_path(subc, "out")?,
                format: match subc.get_one::<String>("format").unwrap().as_str() {
                    | "manpages" => ManualFormat::Manpages,
                    | "markdown" => ManualFormat::Markdown,
                    | _ => return Err(anyhow::anyhow!("argument \"format\": unknown format")),
                },
            }
        } else if let Some(subc) = command.subcommand_matches("autocomplete") {
            Command::Autocomplete {
                path: Self::get_absolute_path(subc, "out")?,
                shell: clap_complete::Shell::from_str(subc.get_one::<String>("shell").unwrap().as_str()).unwrap(),
            }
        } else if let Some(subc) = command.subcommand_matches("unlock") {
            let config_path = Self::get_absolute_path(subc, "config")?;
            let hocon_content = std::fs::read_to_string(&config_path)
                .with_context(|| format!("Failed to read config file: {}", config_path.display()))?;
            let cfg: Manifest = hocon::de::from_str(&hocon_content)
                .with_context(|| format!("Failed to parse HOCON config: {}", config_path.display()))?;

            cfg.validate_version()
                .with_context(|| format!("Version validation failed for config: {}", config_path.display()))?;

            let profile_name = subc.get_one::<String>("profile").unwrap();

            // Validate that the profile exists
            if !cfg.profiles.contains_key(profile_name) {
                return Err(anyhow::anyhow!("Profile '{}' not found in config", profile_name));
            }

            let command = subc
                .get_many::<String>("command")
                .map(|values| values.cloned().collect::<Vec<String>>());

            Command::Unlock {
                manifest: cfg,
                profile_name: profile_name.clone(),
                command,
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

        let callargs = CallArgs {
            privileges,
            command: cmd,
        };

        callargs.validate()?;
        Ok(callargs)
    }
}
