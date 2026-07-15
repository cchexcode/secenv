use {
    anyhow::{
        Context,
        Result,
    },
    base64::Engine,
    std::process::{
        Command,
        Stdio,
    },
    zeroize::Zeroize,
};

#[derive(Debug, Clone)]
pub(crate) struct GcpSecretSpec {
    // Fully qualified: projects/{project}/secrets/{secret}
    pub(crate) secret: String,
    // Optional version (defaults to latest)
    pub(crate) version: Option<String>,
}

impl GcpSecretSpec {
    fn parse_fqn(&self) -> Result<(&str, &str, Option<&str>)> {
        let parts: Vec<&str> = self.secret.split('/').collect();
        match parts.as_slice() {
            | ["projects", project, "secrets", secret] if !project.is_empty() && !secret.is_empty() => {
                Ok((project, secret, None))
            },
            | ["projects", project, "secrets", secret, "versions", version]
                if !project.is_empty() && !secret.is_empty() && !version.is_empty() && !version.starts_with('-') =>
            {
                Ok((project, secret, Some(version)))
            },
            | _ => anyhow::bail!("Invalid GCP secret resource: {}", self.secret),
        }
    }

    /// Resolve the effective version, considering FQN-embedded version and
    /// explicit version field.
    fn effective_version<'a>(&'a self, fqn_version: Option<&'a str>) -> Result<&'a str> {
        if let (Some(fqn_version), Some(version)) = (fqn_version, self.version.as_deref()) {
            if fqn_version != version {
                anyhow::bail!(
                    "GCP secret version '{}' conflicts with explicit version '{}'",
                    fqn_version,
                    version
                );
            }
        }
        let version = self.version.as_deref().or(fqn_version).unwrap_or("latest");
        if version.is_empty() || version.starts_with('-') {
            anyhow::bail!("Invalid GCP secret version: '{}'", version);
        }
        Ok(version)
    }
}

pub(crate) struct GcpSecretManager;

impl GcpSecretManager {
    fn decode_payload(encoded: &mut Vec<u8>) -> Result<String> {
        let payload = std::str::from_utf8(encoded)
            .context("GCP secret payload is not valid base64 text")?
            .trim();
        let decoded = base64::engine::general_purpose::URL_SAFE.decode(payload);
        encoded.zeroize();
        let decoded = decoded.context("GCP secret payload is not valid base64")?;
        match String::from_utf8(decoded) {
            | Ok(value) => Ok(value),
            | Err(error) => {
                let mut bytes = error.into_bytes();
                bytes.zeroize();
                anyhow::bail!("Secret value is not valid UTF-8");
            },
        }
    }

    pub(crate) fn access_secret(&self, spec: &GcpSecretSpec, removed_env_vars: &[String]) -> Result<String> {
        let (project, secret_name, fqn_version) = spec
            .parse_fqn()
            .context("Invalid GCP secret format. Expected 'projects/<project>/secrets/<name>'")?;

        let version = spec.effective_version(fqn_version)?;

        let mut cmd = Command::new("gcloud");
        cmd.args([
            "secrets",
            "versions",
            "access",
            version,
            "--quiet",
            "--format=get(payload.data)",
        ])
        .arg("--secret")
        .arg(secret_name)
        .arg("--project")
        .arg(project);
        crate::process::remove_environment_variables(&mut cmd, removed_env_vars);

        let mut output = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to execute gcloud to access secret")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let error = anyhow::anyhow!("gcloud failed: {}", stderr);
            output.stdout.zeroize();
            return Err(error);
        }

        Self::decode_payload(&mut output.stdout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_secret_resources_and_versions() -> Result<()> {
        let spec = GcpSecretSpec {
            secret: "projects/project/secrets/name/versions/7".to_string(),
            version: None,
        };
        let (_, _, version) = spec.parse_fqn()?;
        assert_eq!(spec.effective_version(version)?, "7");

        for invalid in [
            "projects//secrets/name",
            "projects/project/secrets/name/garbage",
            "projects/project/secrets/name/versions/--help",
        ] {
            let spec = GcpSecretSpec {
                secret: invalid.to_string(),
                version: None,
            };
            assert!(spec.parse_fqn().is_err());
        }

        let mut encoded = base64::engine::general_purpose::URL_SAFE
            .encode("secret with newline\n")
            .into_bytes();
        encoded.push(b'\n');
        assert_eq!(GcpSecretManager::decode_payload(&mut encoded)?, "secret with newline\n");
        Ok(())
    }
}
