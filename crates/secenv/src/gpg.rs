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
pub struct GpgKeySpec {
    pub fingerprint: String,
}

pub struct GpgManager;

impl GpgManager {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

    /// Export a GPG private key by fingerprint using the gpg CLI
    pub fn export_private_key(&self, spec: &GpgKeySpec) -> Result<String> {
        // Use gpg --export-secret-keys to get the private key in ASCII armor format
        // Try different export options for better Sequoia OpenPGP compatibility
        let mut cmd = Command::new("gpg");
        cmd.args([
            "--export-secret-keys",
            "--armor",
            "--batch",
            "--yes",
            "--export-options",
            "export-minimal,export-clean",
            "--rfc4880",
            &spec.fingerprint,
        ]);

        let output = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to execute gpg to export private key")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("gpg failed to export private key: {}", stderr));
        }

        let private_key = String::from_utf8(output.stdout).context("GPG private key output is not valid UTF-8")?;

        if private_key.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "No private key found for fingerprint: {}. Make sure the key exists in your GPG keyring.",
                spec.fingerprint
            ));
        }

        Ok(private_key)
    }

    /// Decrypt PGP encrypted data using GPG directly
    pub fn decrypt_data(&self, encrypted_data: &str) -> Result<String> {
        let mut cmd = Command::new("gpg");
        cmd.args(["--decrypt", "--batch", "--quiet"]);

        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn gpg process for decryption")?;

        // Write encrypted data to stdin
        if let Some(stdin) = child.stdin.take() {
            use std::io::Write;
            let mut stdin = stdin;
            stdin
                .write_all(encrypted_data.as_bytes())
                .context("Failed to write encrypted data to gpg stdin")?;
        }

        let output = child
            .wait_with_output()
            .context("Failed to wait for gpg decryption process")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("GPG failed to decrypt data: {}", stderr));
        }

        let decrypted_data = String::from_utf8(output.stdout).context("GPG decrypted output is not valid UTF-8")?;

        Ok(decrypted_data)
    }
}
