use {
    crate::{
        gcp::{GcpSecretManager, GcpSecretSpec},
        pgp::PgpManager,
    }, anyhow::{Context, Result}, base64::Engine, semver::Version, serde::{
        Deserialize,
        Serialize,
    }, std::collections::HashMap,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Manifest {
    pub version: String,
    pub profiles: HashMap<String, ManifestProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ManifestProfile {
    pub env: ManifestEnv,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ManifestEnv {
    #[serde(default)]
    pub keep: Option<Vec<String>>,
    pub vars: HashMap<String, ValueProvider>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringValue {
    Base64(String),
    Literal(String),
}

impl StringValue {
    pub fn get_value(&self) -> Result<String, anyhow::Error> {
        match self {
            StringValue::Literal(value) => Ok(value.clone()),
            StringValue::Base64(value) => {
                Ok(String::from_utf8(base64::engine::general_purpose::STANDARD.decode(value).context("Failed to decode base64 value")?)
                    .context("Decoded value is not valid UTF-8")?)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpValue {
    Plain {
        secret: String,
    },
    Pgp {
        secret: String,
        value: StringValue,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueProvider {
    Literal(String),
    Environment(String),
    File(String),
    #[serde(rename = "pgp")]
    PGP {
        key: String,
        value: StringValue,
    },
    Gcp(GcpProvider),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GcpProvider {
    #[serde(flatten)]
    pub inner: GcpValue,
}

impl ValueProvider {
    pub fn get_value_with_cache(&self, gcp_secrets: &mut std::collections::HashMap<String, String>) -> Result<String, anyhow::Error> {
        match self {
            | ValueProvider::Literal(value) => Ok(value.clone()),
            | ValueProvider::Environment(value) => {
                Ok(std::env::var(value).context(format!("Failed to get environment variable: {}", value))?)
            },
            | ValueProvider::File(value) => {
                Ok(std::fs::read_to_string(value).context(format!("Failed to read file: {}", value))?)
            },
            | ValueProvider::PGP { key, value } => {
                let pgp_manager = PgpManager::new().context("Failed to initialize PGP manager")?;

                pgp_manager
                    .decrypt(key, &value.get_value()?)
                    .context(format!("Failed to decrypt value using PGP key {}", key))
            },
            | ValueProvider::Gcp(provider) => {
                match &provider.inner {
                    GcpValue::Plain { secret } => {
                        let gcp = GcpSecretManager::new().context("Failed to initialize GCP Secret Manager client")?;
                        let spec = GcpSecretSpec { secret: secret.clone(), version: None };
                        gcp.access_secret_cached_with(gcp_secrets, &spec).context("Failed to access GCP secret")
                    }
                    GcpValue::Pgp { secret, value } => {
                        let gcp = GcpSecretManager::new().context("Failed to initialize GCP Secret Manager client")?;
                        let spec = GcpSecretSpec { secret: secret.clone(), version: None };
                        let key = gcp.access_secret_cached_with(gcp_secrets, &spec).context("Failed to access GCP secret for PGP key")?;
                        let pgp_manager = PgpManager::new().context("Failed to initialize PGP manager")?;
                        pgp_manager
                            .decrypt_with_private_key(&key, &value.get_value()?)
                            .context("Failed to decrypt value with provided PGP private key")
                    }
                }
            }
        }
    }
}

impl Manifest {
    pub fn validate_version(&self) -> Result<()> {
        let cli_version = Version::parse(env!("CARGO_PKG_VERSION"))
            .context("Failed to parse CLI version")?;

        if env!("CARGO_PKG_VERSION") == "0.0.0" {
            return Ok(());
        }
        
        let config_version = Version::parse(&self.version)
            .context(format!("Invalid version format in config: '{}'", self.version))?;
        
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
                config_version,
                cli_version
            );
        }
        
        Ok(())
    }
}
