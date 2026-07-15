use {
    anyhow::{
        Context,
        Result,
    },
    std::{
        io::{
            Seek,
            Write,
        },
        process::{
            Command,
            Stdio,
        },
    },
    zeroize::Zeroize,
};

#[derive(Debug, Clone)]
pub(crate) struct GpgKeySpec {
    fingerprint: String,
}

impl GpgKeySpec {
    /// Create a new GpgKeySpec, validating the fingerprint is well-formed hex
    /// (40 or 64 chars).
    pub(crate) fn new(fingerprint: String) -> Result<Self> {
        let is_valid =
            (fingerprint.len() == 40 || fingerprint.len() == 64) && fingerprint.chars().all(|c| c.is_ascii_hexdigit());

        if !is_valid {
            anyhow::bail!(
                "Invalid GPG fingerprint '{}'. Expected 40 or 64 hex characters.",
                fingerprint
            );
        }
        Ok(Self {
            fingerprint: fingerprint.to_ascii_uppercase(),
        })
    }

    fn as_str(&self) -> &str {
        &self.fingerprint
    }
}

pub(crate) struct GpgManager;

impl GpgManager {
    fn status_uses_key(status: &[u8], spec: &GpgKeySpec) -> bool {
        String::from_utf8_lossy(status).lines().any(|line| {
            line.strip_prefix("[GNUPG:] DECRYPTION_KEY ").is_some_and(|keys| {
                keys.split_whitespace()
                    .take(2)
                    .any(|key| key.eq_ignore_ascii_case(spec.as_str()))
            })
        })
    }

    pub(crate) fn export_private_key(&self, spec: &GpgKeySpec, removed_env_vars: &[String]) -> Result<String> {
        let mut cmd = Command::new("gpg");
        cmd.args([
            "--export-secret-keys",
            "--armor",
            "--batch",
            "--yes",
            "--export-options",
            "export-minimal,export-clean",
            spec.as_str(),
        ]);
        crate::process::remove_environment_variables(&mut cmd, removed_env_vars);

        let mut output = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to execute gpg to export private key")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let error = anyhow::anyhow!("gpg failed to export private key: {}", stderr);
            output.stdout.zeroize();
            return Err(error);
        }

        let mut private_key = match String::from_utf8(output.stdout) {
            | Ok(private_key) => private_key,
            | Err(error) => {
                let mut bytes = error.into_bytes();
                bytes.zeroize();
                anyhow::bail!("GPG private key output is not valid UTF-8");
            },
        };

        if private_key.trim().is_empty() {
            private_key.zeroize();
            anyhow::bail!(
                "No private key found for fingerprint: {}. Make sure the key exists in your GPG keyring.",
                spec.as_str()
            );
        }

        Ok(private_key)
    }

    pub(crate) fn decrypt_data(
        &self,
        spec: &GpgKeySpec,
        encrypted_data: &str,
        removed_env_vars: &[String],
    ) -> Result<String> {
        let mut input = tempfile::tempfile().context("Failed to create temporary GPG input")?;
        input
            .write_all(encrypted_data.as_bytes())
            .context("Failed to write temporary GPG input")?;
        input.rewind().context("Failed to rewind temporary GPG input")?;

        let mut cmd = Command::new("gpg");
        cmd.args([
            "--batch",
            "--quiet",
            "--status-fd=2",
            "--try-secret-key",
            spec.as_str(),
            "--decrypt",
        ]);
        crate::process::remove_environment_variables(&mut cmd, removed_env_vars);

        let mut output = cmd
            .stdin(Stdio::from(input))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to execute gpg process for decryption")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let error = anyhow::anyhow!("GPG failed to decrypt data: {}", stderr);
            output.stdout.zeroize();
            return Err(error);
        }

        if !Self::status_uses_key(&output.stderr, spec) {
            output.stdout.zeroize();
            anyhow::bail!("GPG did not decrypt with configured fingerprint {}", spec.as_str());
        }

        match String::from_utf8(output.stdout) {
            | Ok(decrypted_data) => Ok(decrypted_data),
            | Err(error) => {
                let mut bytes = error.into_bytes();
                bytes.zeroize();
                anyhow::bail!("GPG decrypted output is not valid UTF-8");
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_the_decryption_fingerprint() -> Result<()> {
        let fingerprint = "0123456789abcdef0123456789abcdef01234567";
        let spec = GpgKeySpec::new(fingerprint.to_string())?;
        let status = format!("[GNUPG:] DECRYPTION_KEY subkey {} -\n", fingerprint);
        assert!(GpgManager::status_uses_key(status.as_bytes(), &spec));
        assert!(!GpgManager::status_uses_key(
            b"[GNUPG:] DECRYPTION_KEY other another -\n",
            &spec
        ));
        Ok(())
    }
}
