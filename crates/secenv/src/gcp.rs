use {
    anyhow::{Context, Result},
    std::{
        collections::HashMap,
        process::{Command, Stdio},
    },
};

#[derive(Debug, Clone)]
pub struct GcpSecretSpec {
    // Fully qualified: projects/{project}/secrets/{secret}
    pub secret: String,
    // Optional version (defaults to latest)
    pub version: Option<String>,
}

pub struct GcpSecretManager;

impl GcpSecretManager {
    pub fn new() -> Result<Self> { Ok(Self) }

    pub fn access_secret(&self, spec: &GcpSecretSpec) -> Result<String> {
        // Accept fully qualified secret path and optional version.
        // Parse FQN and pass --secret <name> and --project <project> to gcloud.
        let version = spec.version.as_deref().unwrap_or("latest");

        let (project, secret_name) = parse_project_and_secret(&spec.secret)
            .context("Invalid GCP secret format. Expected 'projects/<project>/secrets/<name>'")?;

        let mut cmd = Command::new("gcloud");
        cmd
            .args(["secrets", "versions", "access", version, "--quiet"])
            .arg("--secret").arg(&secret_name)
            .arg("--project").arg(&project);

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

    pub fn access_secret_cached_with(&self, cache: &mut HashMap<String, String>, spec: &GcpSecretSpec) -> Result<String> {
        let cache_key = format!("{}#{}", spec.secret, spec.version.clone().unwrap_or_else(|| "latest".into()));
        if let Some(val) = cache.get(&cache_key).cloned() {
            return Ok(val);
        }
        let value = self.access_secret(spec)?;
        cache.insert(cache_key, value.clone());
        Ok(value)
    }
}

fn parse_project_and_secret(fqn: &str) -> Result<(String, String)> {
    // Accepts both:
    // projects/<project>/secrets/<secret>
    // projects/<project>/secrets/<secret>/versions/<version> (version ignored)
    let parts: Vec<&str> = fqn.split('/').collect();
    if parts.len() < 4 || parts[0] != "projects" || parts[2] != "secrets" {
        return Err(anyhow::anyhow!("Invalid secret resource: {}", fqn));
    }
    let project = parts[1].to_string();
    let secret_name = parts[3].to_string();
    Ok((project, secret_name))
}

