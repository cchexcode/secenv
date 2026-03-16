use {
    anyhow::{
        Context,
        Result,
    },
    std::process::{
        Command,
        Stdio,
    },
};

#[derive(Debug, Clone)]
pub struct GcpSecretSpec {
    // Fully qualified: projects/{project}/secrets/{secret}
    pub secret: String,
    // Optional version (defaults to latest)
    pub version: Option<String>,
}

impl GcpSecretSpec {
    /// Parse a GCP secret FQN into (project, secret_name, optional_version).
    /// Accepts:
    ///   projects/<project>/secrets/<secret>
    ///   projects/<project>/secrets/<secret>/versions/<version>
    fn parse_fqn(&self) -> Result<(String, String, Option<String>)> {
        let parts: Vec<&str> = self.secret.split('/').collect();
        if parts.len() < 4 || parts[0] != "projects" || parts[2] != "secrets" {
            return Err(anyhow::anyhow!("Invalid secret resource: {}", self.secret));
        }
        let project = parts[1].to_string();
        let secret_name = parts[3].to_string();

        let version = if parts.len() >= 6 && parts[4] == "versions" {
            Some(parts[5].to_string())
        } else {
            None
        };

        Ok((project, secret_name, version))
    }

    /// Resolve the effective version, considering FQN-embedded version and
    /// explicit version field.
    fn effective_version(&self, fqn_version: &Option<String>) -> String {
        if fqn_version.is_some() && self.version.is_some() && fqn_version != &self.version {
            eprintln!(
                "WARNING: Version '{}' specified in secret FQN conflicts with explicit version '{}'. Using explicit \
                 version.",
                fqn_version.as_deref().unwrap_or(""),
                self.version.as_deref().unwrap_or("")
            );
        }

        self.version
            .as_deref()
            .or(fqn_version.as_deref())
            .unwrap_or("latest")
            .to_string()
    }
}

pub struct GcpSecretManager;

impl GcpSecretManager {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

    pub fn access_secret(&self, spec: &GcpSecretSpec) -> Result<String> {
        let (project, secret_name, fqn_version) = spec
            .parse_fqn()
            .context("Invalid GCP secret format. Expected 'projects/<project>/secrets/<name>'")?;

        let version = spec.effective_version(&fqn_version);

        let mut cmd = Command::new("gcloud");
        cmd.args(["secrets", "versions", "access", &version, "--quiet"])
            .arg("--secret")
            .arg(&secret_name)
            .arg("--project")
            .arg(&project);

        let output = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to execute gcloud to access secret")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("gcloud failed: {}", stderr));
        }

        let value = String::from_utf8(output.stdout).context("Secret value is not valid UTF-8")?;
        Ok(value.trim_end_matches(['\n', '\r']).to_string())
    }
}
