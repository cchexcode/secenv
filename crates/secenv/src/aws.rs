use {
    anyhow::{
        Context,
        Result,
    },
    std::process::{
        Command,
        Stdio,
    },
    zeroize::Zeroize,
};

#[derive(Debug, Clone)]
pub(crate) struct AwsSecretSpec {
    // Secret name or ARN: arn:aws:secretsmanager:{region}:{account-id}:secret:{secret-name}
    pub(crate) secret: String,
    // Optional version identifier
    pub(crate) version: Option<String>,
    // Optional region override
    pub(crate) region: Option<String>,
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

pub(crate) struct AwsSecretManager;

impl AwsSecretManager {
    pub(crate) fn access_secret(&self, spec: &AwsSecretSpec, removed_env_vars: &[String]) -> Result<String> {
        let mut cmd = Command::new("aws");
        cmd.args(["secretsmanager", "get-secret-value"])
            .arg("--secret-id")
            .arg(&spec.secret)
            .arg("--query")
            .arg("SecretString")
            .arg("--output")
            .arg("json");

        spec.apply_version_arg(&mut cmd);

        if let Some(region) = &spec.region {
            cmd.arg("--region").arg(region);
        }
        crate::process::remove_environment_variables(&mut cmd, removed_env_vars);

        let mut output = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to execute aws CLI to access secret")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let error = anyhow::anyhow!("aws CLI failed: {}", stderr);
            output.stdout.zeroize();
            return Err(error);
        }

        let value = serde_json::from_slice::<Option<String>>(&output.stdout);
        output.stdout.zeroize();
        value
            .context("AWS SecretString output is not valid JSON")?
            .context("AWS secret does not contain SecretString")
    }
}
