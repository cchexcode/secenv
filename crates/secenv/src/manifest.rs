use {
    crate::{
        aws::{
            AwsSecretManager,
            AwsSecretSpec,
        },
        gcp::{
            GcpSecretManager,
            GcpSecretSpec,
        },
        gpg::{
            GpgKeySpec,
            GpgManager,
        },
    },
    anyhow::{
        Context,
        Result,
    },
    base64::Engine,
    semver::Version,
    serde::{
        Deserialize,
        Serialize,
    },
    std::{
        collections::HashMap,
        fmt,
        path::PathBuf,
    },
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncodedValue {
    Literal(String),
    Base64(String),
}

impl fmt::Debug for EncodedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | EncodedValue::Literal(_) => f.write_str("Literal(<redacted>)"),
            | EncodedValue::Base64(_) => f.write_str("Base64(<redacted>)"),
        }
    }
}

impl EncodedValue {
    pub fn get_value(&self) -> Result<String, anyhow::Error> {
        match self {
            | EncodedValue::Literal(value) => Ok(value.clone()),
            | EncodedValue::Base64(value) => {
                let decoded_bytes = base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .context("Failed to decode base64 value")?;

                Ok(String::from_utf8(decoded_bytes).context("Decoded value is not valid UTF-8")?)
            },
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EncodedValueWrapper {
    #[serde(flatten)]
    pub inner: EncodedValue,
}

impl fmt::Debug for EncodedValueWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncodedValueWrapper")
            .field("inner", &self.inner)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretAllocation {
    Literal(EncodedValue),
    File(String),
    Gpg {
        fingerprint: String,
    },
    Gcp {
        secret: String,
        version: Option<String>,
    },
    Aws {
        secret: String,
        version: Option<String>,
        region: Option<String>,
    },
}

impl fmt::Debug for SecretAllocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | SecretAllocation::Literal(_) => f.write_str("Literal(<redacted>)"),
            | SecretAllocation::File(path) => write!(f, "File({})", path),
            | SecretAllocation::Gpg { fingerprint } => write!(f, "Gpg(fingerprint={})", fingerprint),
            | SecretAllocation::Gcp { secret, .. } => write!(f, "Gcp(secret={})", secret),
            | SecretAllocation::Aws { secret, .. } => write!(f, "Aws(secret={})", secret),
        }
    }
}

impl SecretAllocation {
    pub fn get_value(&self) -> Result<String, anyhow::Error> {
        match self {
            | SecretAllocation::Literal(encoded_value) => encoded_value.get_value(),
            | SecretAllocation::File(file_path) => {
                std::fs::read_to_string(file_path).context(format!("Failed to read file: {}", file_path))
            },
            | SecretAllocation::Gpg { fingerprint } => {
                let spec = GpgKeySpec::new(fingerprint.clone())?;
                let gpg = GpgManager::new().context("Failed to initialize GPG manager")?;
                gpg.export_private_key(&spec)
                    .context("Failed to export GPG private key")
            },
            | SecretAllocation::Gcp { secret, version } => {
                let gcp = GcpSecretManager::new().context("Failed to initialize GCP Secret Manager client")?;
                let spec = GcpSecretSpec {
                    secret: secret.clone(),
                    version: version.clone(),
                };
                gcp.access_secret(&spec).context("Failed to access GCP secret")
            },
            | SecretAllocation::Aws {
                secret,
                version,
                region,
            } => {
                let aws = AwsSecretManager::new().context("Failed to initialize AWS Secret Manager client")?;
                let spec = AwsSecretSpec {
                    secret: secret.clone(),
                    version: version.clone(),
                    region: region.clone(),
                };
                aws.access_secret(&spec).context("Failed to access AWS secret")
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SecretAllocationWrapper {
    #[serde(flatten)]
    pub inner: SecretAllocation,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Secret {
    #[serde(rename = "pgp")]
    PGP(SecretAllocationWrapper),
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | Secret::PGP(alloc) => write!(f, "PGP({:?})", alloc),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SecretWrapper {
    #[serde(flatten)]
    pub inner: Secret,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Manifest {
    pub version: String,
    #[serde(skip)]
    pub source_path: PathBuf,
    #[serde(default)]
    pub profiles: HashMap<String, ManifestProfile>,
}

impl fmt::Debug for Manifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Manifest")
            .field("version", &self.version)
            .field("source_path", &self.source_path)
            .field("profiles", &format!("[{} profile(s)]", self.profiles.len()))
            .finish()
    }
}

impl Manifest {
    pub fn validate_version(&self) -> Result<()> {
        let cli_version = Version::parse(env!("CARGO_PKG_VERSION")).context("Failed to parse CLI version")?;

        #[cfg(debug_assertions)]
        if env!("CARGO_PKG_VERSION") == "0.0.0" {
            return Ok(());
        }

        let config_version =
            Version::parse(&self.version).context(format!("Invalid version format in config: '{}'", self.version))?;

        if config_version.major != cli_version.major {
            return Err(anyhow::anyhow!(
                "Config version {} is incompatible with CLI version {}. Major version mismatch.",
                config_version,
                cli_version
            ));
        }

        if config_version > cli_version {
            return Err(anyhow::anyhow!(
                "Config version {} is newer than CLI version {}. Please upgrade the CLI.",
                config_version,
                cli_version
            ));
        }

        if config_version.minor > cli_version.minor {
            eprintln!(
                "Warning: Config version {} has newer minor version than CLI version {}. Some features may not work.",
                config_version, cli_version
            );
        }

        Ok(())
    }

    /// Warn if the config file has insecure permissions (group/world-writable).
    #[cfg(unix)]
    pub fn warn_if_insecure_permissions(&self) {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata(&self.source_path) {
            let mode = meta.mode();
            if mode & 0o002 != 0 {
                eprintln!(
                    "WARNING: Config file '{}' is world-writable (mode {:04o}). This is a security risk.",
                    self.source_path.display(),
                    mode & 0o777
                );
            }
            if mode & 0o020 != 0 {
                eprintln!(
                    "WARNING: Config file '{}' is group-writable (mode {:04o}). This may be a security risk.",
                    self.source_path.display(),
                    mode & 0o777
                );
            }
        }
    }

    #[cfg(not(unix))]
    pub fn warn_if_insecure_permissions(&self) {}

    /// Build an example manifest suitable for `init`.
    pub fn example(source_path: PathBuf) -> Self {
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

        files.insert("./aws-certificate.pem".to_string(), ContentWrapper {
            inner: Content::Aws {
                secret: "my-app/certificates/tls-cert".to_string(),
                version: None,
                region: Some("us-east-1".to_string()),
            },
        });

        files.insert("./gcs-certificate.pem".to_string(), ContentWrapper {
            inner: Content::Gcs {
                secret: "projects/myproject/secrets/tls-cert".to_string(),
                version: Some("latest".to_string()),
            },
        });

        let default_profile = ManifestProfile {
            files,
            env: ManifestEnv {
                keep: Some(vec!["^PATH$".to_string(), "^LC_.*".to_string()]),
                vars,
                from: vec![FromLocationWrapper {
                    inner: FromLocation::GCS {
                        secret: "projects/myproject/secrets/my-gcs-secret".to_string(),
                        version: Some("latest".to_string()),
                    },
                }],
            },
        };

        let mut profiles = HashMap::new();
        profiles.insert("default".to_string(), default_profile);

        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            source_path,
            profiles,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ManifestProfile {
    #[serde(default)]
    pub files: HashMap<String, ContentWrapper>,

    #[serde(default)]
    pub env: ManifestEnv,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FromLocation {
    File(String),
    #[serde(rename = "gcs")]
    GCS {
        secret: String,
        version: Option<String>,
    },
    #[serde(rename = "aws")]
    AWS {
        secret: String,
        version: Option<String>,
        region: Option<String>,
    },
}

impl fmt::Debug for FromLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | FromLocation::File(path) => write!(f, "File({})", path),
            | FromLocation::GCS { secret, .. } => write!(f, "GCS({})", secret),
            | FromLocation::AWS { secret, .. } => write!(f, "AWS({})", secret),
        }
    }
}

impl FromLocation {
    /// Fetch the raw string content from this source.
    pub fn resolve(&self) -> Result<String> {
        match self {
            | FromLocation::GCS { secret, version } => {
                let gcp = GcpSecretManager::new().context("Failed to initialize GCP Secret Manager client")?;
                let spec = GcpSecretSpec {
                    secret: secret.to_string(),
                    version: version.as_ref().map(|v| v.to_string()),
                };
                gcp.access_secret(&spec)
            },
            | FromLocation::AWS {
                secret,
                version,
                region,
            } => {
                let aws = AwsSecretManager::new().context("Failed to initialize AWS Secret Manager client")?;
                let spec = AwsSecretSpec {
                    secret: secret.to_string(),
                    version: version.as_ref().map(|v| v.to_string()),
                    region: region.as_ref().map(|r| r.to_string()),
                };
                aws.access_secret(&spec)
            },
            | FromLocation::File(file_path) => {
                std::fs::read_to_string(file_path).context(format!("Failed to read env file: {}", file_path))
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FromLocationWrapper {
    #[serde(flatten)]
    pub inner: FromLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct ManifestEnv {
    #[serde(default)]
    pub keep: Option<Vec<String>>,

    #[serde(default)]
    pub vars: HashMap<String, ContentWrapper>,

    #[serde(default)]
    pub from: Vec<FromLocationWrapper>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Content {
    Plain(EncodedValue),

    Secure {
        secret: SecretWrapper,
        value: EncodedValueWrapper,
    },

    /// Load content directly from a local file
    File(String),

    /// Load content directly from GCP Secret Manager
    #[serde(rename = "gcs")]
    Gcs {
        secret: String,
        version: Option<String>,
    },

    /// Load content directly from AWS Secrets Manager
    #[serde(rename = "aws")]
    Aws {
        secret: String,
        version: Option<String>,
        region: Option<String>,
    },
}

impl fmt::Debug for Content {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | Content::Plain(_) => f.write_str("Plain(<redacted>)"),
            | Content::Secure { secret, .. } => write!(f, "Secure({:?})", secret),
            | Content::File(path) => write!(f, "File({})", path),
            | Content::Gcs { secret, .. } => write!(f, "Gcs({})", secret),
            | Content::Aws { secret, .. } => write!(f, "Aws({})", secret),
        }
    }
}

impl Content {
    pub fn get_value(&self, pgp_manager: &mut crate::pgp::PgpManager) -> Result<String, anyhow::Error> {
        match self {
            | Content::Plain(encoded_value) => encoded_value.get_value(),
            | Content::Secure { secret, value } => {
                let encrypted_data = value.inner.get_value()?;

                match &secret.inner {
                    | Secret::PGP(allocation_wrapper) => {
                        match &allocation_wrapper.inner {
                            | SecretAllocation::Gpg { fingerprint } => {
                                let spec = GpgKeySpec::new(fingerprint.clone())?;
                                let gpg = GpgManager::new().context("Failed to initialize GPG manager")?;
                                gpg.decrypt_data_with_spec(&spec, &encrypted_data)
                                    .context("Failed to decrypt value with GPG")
                            },
                            | _ => {
                                let pgp_key = allocation_wrapper.inner.get_value()?;
                                pgp_manager
                                    .decrypt(&pgp_key, &encrypted_data)
                                    .context("Failed to decrypt value with PGP key")
                            },
                        }
                    },
                }
            },
            | Content::File(file_path) => {
                std::fs::read_to_string(file_path).context(format!("Failed to read file: {}", file_path))
            },
            | Content::Gcs { secret, version } => {
                let gcp = GcpSecretManager::new().context("Failed to initialize GCP Secret Manager client")?;
                let spec = GcpSecretSpec {
                    secret: secret.clone(),
                    version: version.clone(),
                };
                gcp.access_secret(&spec).context("Failed to access GCP secret")
            },
            | Content::Aws {
                secret,
                version,
                region,
            } => {
                let aws = AwsSecretManager::new().context("Failed to initialize AWS Secret Manager client")?;
                let spec = AwsSecretSpec {
                    secret: secret.clone(),
                    version: version.clone(),
                    region: region.clone(),
                };
                aws.access_secret(&spec).context("Failed to access AWS secret")
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ContentWrapper {
    #[serde(flatten)]
    pub inner: Content,
}
