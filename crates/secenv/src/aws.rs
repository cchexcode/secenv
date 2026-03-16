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
pub struct AwsSecretSpec {
    // Secret name or ARN: arn:aws:secretsmanager:{region}:{account-id}:secret:{secret-name}
    pub secret: String,
    // Optional version identifier
    pub version: Option<String>,
    // Optional region override
    pub region: Option<String>,
}

impl AwsSecretSpec {
    /// Determine whether a version string is a known AWS version stage label.
    fn is_version_stage(version: &str) -> bool {
        matches!(version, "AWSCURRENT" | "AWSPREVIOUS" | "AWSPENDING")
    }

    /// Apply the version argument to the AWS CLI command.
    fn apply_version_arg(&self, cmd: &mut Command) {
        if let Some(version) = &self.version {
            if Self::is_version_stage(version) {
                cmd.arg("--version-stage").arg(version);
            } else {
                cmd.arg("--version-id").arg(version);
            }
        }
    }
}

pub struct AwsSecretManager;

impl AwsSecretManager {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

    pub fn access_secret(&self, spec: &AwsSecretSpec) -> Result<String> {
        let mut cmd = Command::new("aws");
        cmd.args(["secretsmanager", "get-secret-value"])
            .arg("--secret-id")
            .arg(&spec.secret)
            .arg("--query")
            .arg("SecretString")
            .arg("--output")
            .arg("text");

        spec.apply_version_arg(&mut cmd);

        if let Some(region) = &spec.region {
            cmd.arg("--region").arg(region);
        }

        let output = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to execute aws CLI to access secret")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("aws CLI failed: {}", stderr));
        }

        let value = String::from_utf8(output.stdout).context("Secret value is not valid UTF-8")?;
        Ok(value.trim_end_matches(['\n', '\r']).to_string())
    }
}
