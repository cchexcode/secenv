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
    hocon::HoconLoader,
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
    zeroize::Zeroizing,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EncodedValue {
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
    pub(crate) fn decode(&self) -> Result<String> {
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
pub(crate) struct EncodedValueWrapper {
    #[serde(flatten)]
    pub(crate) inner: EncodedValue,
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
pub(crate) enum SecretAllocation {
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
    pub(crate) fn resolve(&self) -> Result<String> {
        match self {
            | SecretAllocation::Literal(encoded_value) => encoded_value.decode(),
            | SecretAllocation::File(file_path) => {
                std::fs::read_to_string(file_path).context(format!("Failed to read file: {}", file_path))
            },
            | SecretAllocation::Gpg { fingerprint } => {
                let spec = GpgKeySpec::new(fingerprint.clone())?;
                GpgManager
                    .export_private_key(&spec)
                    .context("Failed to export GPG private key")
            },
            | SecretAllocation::Gcp { secret, version } => {
                let spec = GcpSecretSpec {
                    secret: secret.clone(),
                    version: version.clone(),
                };
                GcpSecretManager
                    .access_secret(&spec)
                    .context("Failed to access GCP secret")
            },
            | SecretAllocation::Aws {
                secret,
                version,
                region,
            } => {
                let spec = AwsSecretSpec {
                    secret: secret.clone(),
                    version: version.clone(),
                    region: region.clone(),
                };
                AwsSecretManager
                    .access_secret(&spec)
                    .context("Failed to access AWS secret")
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct SecretAllocationWrapper {
    #[serde(flatten)]
    pub(crate) inner: SecretAllocation,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RemoteSecretAllocation {
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

impl fmt::Debug for RemoteSecretAllocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | Self::Gcp { secret, .. } => write!(f, "Gcp(secret={})", secret),
            | Self::Aws { secret, .. } => write!(f, "Aws(secret={})", secret),
        }
    }
}

impl RemoteSecretAllocation {
    pub(crate) fn resolve(&self) -> Result<String> {
        match self {
            | Self::Gcp { secret, version } => {
                GcpSecretManager.access_secret(&GcpSecretSpec {
                    secret: secret.clone(),
                    version: version.clone(),
                })
            },
            | Self::Aws {
                secret,
                version,
                region,
            } => {
                AwsSecretManager.access_secret(&AwsSecretSpec {
                    secret: secret.clone(),
                    version: version.clone(),
                    region: region.clone(),
                })
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct RemoteSecretAllocationWrapper {
    #[serde(flatten)]
    pub(crate) inner: RemoteSecretAllocation,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Secret {
    #[serde(rename = "pgp")]
    Pgp(SecretAllocationWrapper),
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | Secret::Pgp(alloc) => write!(f, "Pgp({:?})", alloc),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct SecretWrapper {
    #[serde(flatten)]
    pub(crate) inner: Secret,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct Manifest {
    pub(crate) version: String,
    #[serde(skip)]
    source_path: PathBuf,
    #[serde(default)]
    pub(crate) profiles: HashMap<String, ManifestProfile>,
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
    pub(crate) fn load(source_path: PathBuf) -> Result<Self> {
        let content = Zeroizing::new(
            std::fs::read_to_string(&source_path)
                .with_context(|| format!("Failed to read config file: {}", source_path.display()))?,
        );
        let mut manifest: Self = HoconLoader::new()
            .no_system()
            .strict()
            .load_str(&content)
            .with_context(|| format!("Failed to parse HOCON config: {}", source_path.display()))?
            .resolve()
            .with_context(|| format!("Failed to deserialize HOCON config: {}", source_path.display()))?;
        manifest.source_path = source_path;
        manifest.validate_version()?;
        Ok(manifest)
    }

    pub(crate) fn validate_version(&self) -> Result<()> {
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

        Ok(())
    }

    /// Warn if the config file has insecure permissions (group/world-writable).
    #[cfg(unix)]
    pub(crate) fn warn_if_insecure_permissions(&self) {
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
    pub(crate) fn warn_if_insecure_permissions(&self) {}

    /// Build an example manifest suitable for `init`.
    pub(crate) fn example(source_path: PathBuf) -> Self {
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
                    inner: Secret::Pgp(SecretAllocationWrapper {
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
                    inner: Secret::Pgp(SecretAllocationWrapper {
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
                    inner: Secret::Pgp(SecretAllocationWrapper {
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
                    inner: Secret::Pgp(SecretAllocationWrapper {
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
            sealed: None,
            files,
            env: ManifestEnv {
                keep: Some(vec!["^PATH$".to_string(), "^LC_.*".to_string()]),
                vars,
                from: vec![FromLocationWrapper {
                    inner: FromLocation::Gcs {
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
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct ManifestProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) sealed: Option<SealedFiles>,

    #[serde(default)]
    pub(crate) files: HashMap<String, ContentWrapper>,

    #[serde(default)]
    pub(crate) env: ManifestEnv,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct SealedFiles {
    /// HOCON or JSON files replaced with their decrypted form for the command
    /// lifetime, then restored.
    #[serde(default)]
    pub(crate) files: HashMap<String, SealedFile>,

    /// Temporary output path to encrypted template path.
    #[serde(default)]
    pub(crate) templates: HashMap<String, SealedTemplate>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SealedSecret {
    Pgp(RemoteSecretAllocationWrapper),
    Argon2idXchacha20Poly1305(RemoteSecretAllocationWrapper),
}

impl fmt::Debug for SealedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | Self::Pgp(allocation) => write!(f, "Pgp({:?})", allocation),
            | Self::Argon2idXchacha20Poly1305(allocation) => {
                write!(f, "Argon2idXchacha20Poly1305({:?})", allocation)
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct SealedSecretWrapper {
    #[serde(flatten)]
    pub(crate) inner: SealedSecret,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct SealedFile {
    pub(crate) secret: SealedSecretWrapper,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct SealedTemplate {
    pub(crate) source: String,
    pub(crate) secret: SealedSecretWrapper,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FromLocation {
    File(String),
    #[serde(rename = "gcs")]
    Gcs {
        secret: String,
        version: Option<String>,
    },
    #[serde(rename = "aws")]
    Aws {
        secret: String,
        version: Option<String>,
        region: Option<String>,
    },
}

impl fmt::Debug for FromLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | FromLocation::File(path) => write!(f, "File({})", path),
            | FromLocation::Gcs { secret, .. } => write!(f, "Gcs({})", secret),
            | FromLocation::Aws { secret, .. } => write!(f, "Aws({})", secret),
        }
    }
}

impl FromLocation {
    /// Fetch the raw string content from this source.
    pub(crate) fn resolve(&self) -> Result<String> {
        match self {
            | FromLocation::Gcs { secret, version } => {
                let spec = GcpSecretSpec {
                    secret: secret.to_string(),
                    version: version.as_ref().map(|v| v.to_string()),
                };
                GcpSecretManager.access_secret(&spec)
            },
            | FromLocation::Aws {
                secret,
                version,
                region,
            } => {
                let spec = AwsSecretSpec {
                    secret: secret.to_string(),
                    version: version.as_ref().map(|v| v.to_string()),
                    region: region.as_ref().map(|r| r.to_string()),
                };
                AwsSecretManager.access_secret(&spec)
            },
            | FromLocation::File(file_path) => {
                std::fs::read_to_string(file_path).context(format!("Failed to read env file: {}", file_path))
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct FromLocationWrapper {
    #[serde(flatten)]
    pub(crate) inner: FromLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub(crate) struct ManifestEnv {
    #[serde(default)]
    pub(crate) keep: Option<Vec<String>>,

    #[serde(default)]
    pub(crate) vars: HashMap<String, ContentWrapper>,

    #[serde(default)]
    pub(crate) from: Vec<FromLocationWrapper>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Content {
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
    pub(crate) fn resolve(&self, pgp_manager: &mut crate::pgp::PgpManager) -> Result<String> {
        match self {
            | Content::Plain(encoded_value) => encoded_value.decode(),
            | Content::Secure { secret, value } => {
                let encrypted_data = value.inner.decode()?;

                match &secret.inner {
                    | Secret::Pgp(allocation_wrapper) => {
                        match &allocation_wrapper.inner {
                            | SecretAllocation::Gpg { fingerprint } => {
                                let spec = GpgKeySpec::new(fingerprint.clone())?;
                                GpgManager
                                    .decrypt_data(&spec, &encrypted_data)
                                    .context("Failed to decrypt value with GPG")
                            },
                            | _ => {
                                let pgp_key = Zeroizing::new(allocation_wrapper.inner.resolve()?);
                                pgp_manager
                                    .decrypt(pgp_key.as_str(), &encrypted_data)
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
                let spec = GcpSecretSpec {
                    secret: secret.clone(),
                    version: version.clone(),
                };
                GcpSecretManager
                    .access_secret(&spec)
                    .context("Failed to access GCP secret")
            },
            | Content::Aws {
                secret,
                version,
                region,
            } => {
                let spec = AwsSecretSpec {
                    secret: secret.clone(),
                    version: version.clone(),
                    region: region.clone(),
                };
                AwsSecretManager
                    .access_secret(&spec)
                    .context("Failed to access AWS secret")
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct ContentWrapper {
    #[serde(flatten)]
    pub(crate) inner: Content,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_profiles_remain_compatible() -> Result<()> {
        let manifest: Manifest = hocon::de::from_str(
            r#"
            version = "0.0.0"
            profiles.default.env.vars.APP_NAME.plain.literal = "myapp"
            "#,
        )?;

        let profile = manifest.profiles.get("default").context("Missing default profile")?;
        assert!(profile.sealed.is_none());
        Ok(())
    }

    #[test]
    fn parses_profile_sealed_files_and_templates() -> Result<()> {
        let manifest: Manifest = hocon::de::from_str(
            r#"
            version = "0.0.0"
            profiles.default.sealed {
              files {
                "./application.conf" {
                  secret.pgp.gcp.secret = "projects/example/secrets/application-pgp-key"
                }
              }
              templates {
                "./credentials.json" {
                  source = "./credentials.json.sealed"
                  secret.argon2id_xchacha20_poly1305.gcp.secret = "projects/example/secrets/credentials-passphrase"
                }
              }
            }
            "#,
        )?;

        let sealed = manifest
            .profiles
            .get("default")
            .and_then(|profile| profile.sealed.as_ref())
            .context("Missing sealed profile configuration")?;
        assert_eq!(
            sealed
                .templates
                .get("./credentials.json")
                .map(|template| template.source.as_str()),
            Some("./credentials.json.sealed")
        );
        assert!(sealed.files.contains_key("./application.conf"));
        assert!(matches!(
            sealed.files["./application.conf"].secret.inner,
            SealedSecret::Pgp(RemoteSecretAllocationWrapper {
                inner: RemoteSecretAllocation::Gcp { .. }
            })
        ));
        assert!(matches!(
            sealed.templates["./credentials.json"].secret.inner,
            SealedSecret::Argon2idXchacha20Poly1305(RemoteSecretAllocationWrapper {
                inner: RemoteSecretAllocation::Gcp { .. }
            })
        ));
        Ok(())
    }

    #[test]
    fn rejects_local_sealed_secrets() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("secenv.conf");
        std::fs::write(
            &path,
            r#"
            version = "0.0.0"
            profiles.default.sealed.files."./application.conf".secret.pgp.file = "private.key"
            "#,
        )?;
        assert!(Manifest::load(path).is_err());
        Ok(())
    }
}
