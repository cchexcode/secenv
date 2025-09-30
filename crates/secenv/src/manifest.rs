use {
    crate::{
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
    std::collections::HashMap,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncodedValue {
    Literal(String),
    Base64(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EncodedValueWrapper {
    #[serde(flatten)]
    pub inner: EncodedValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretAllocation {
    Literal(EncodedValue),
    File(String),
    Gpg { fingerprint: String },
    Gcp { secret: String, version: Option<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SecretAllocationWrapper {
    #[serde(flatten)]
    pub inner: SecretAllocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Secret {
    #[serde(rename = "pgp")]
    PGP(SecretAllocationWrapper),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SecretWrapper {
    #[serde(flatten)]
    pub inner: Secret,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Manifest {
    pub version: String,
    #[serde(default)]
    pub profiles: HashMap<String, ManifestProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ManifestProfile {
    #[serde(default)]
    pub files: HashMap<String, ContentWrapper>,

    #[serde(default)]
    pub env: ManifestEnv,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct ManifestEnv {
    #[serde(default)]
    pub keep: Option<Vec<String>>,

    #[serde(default)]
    pub vars: HashMap<String, ContentWrapper>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Content {
    Plain(EncodedValue),

    Secure {
        secret: SecretWrapper,
        value: EncodedValueWrapper,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ContentWrapper {
    #[serde(flatten)]
    pub inner: Content,
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

impl SecretAllocation {
    pub fn get_value(&self) -> Result<String, anyhow::Error> {
        match self {
            | SecretAllocation::Literal(encoded_value) => encoded_value.get_value(),
            | SecretAllocation::File(file_path) => {
                std::fs::read_to_string(file_path).context(format!("Failed to read file: {}", file_path))
            },
            | SecretAllocation::Gpg { fingerprint } => {
                let gpg = GpgManager::new().context("Failed to initialize GPG manager")?;
                let spec = GpgKeySpec {
                    fingerprint: fingerprint.clone(),
                };
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
                            | SecretAllocation::Gpg { fingerprint: _ } => {
                                let gpg = GpgManager::new().context("Failed to initialize GPG manager")?;
                                gpg.decrypt_data(&encrypted_data)
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
        }
    }
}

impl Manifest {
    pub fn validate_version(&self) -> Result<()> {
        let cli_version = Version::parse(env!("CARGO_PKG_VERSION")).context("Failed to parse CLI version")?;

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
}
