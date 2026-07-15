#[cfg(unix)]
use std::os::unix::fs::{
    MetadataExt,
    PermissionsExt,
};
use {
    crate::{
        manifest::{
            SealedFile,
            SealedFiles,
            SealedSecret,
            SealedSecretWrapper,
            SealedTemplate,
            SecretAllocation,
        },
        password_cipher::PasswordCipher,
        pgp::PgpManager,
    },
    anyhow::{
        Context,
        Result,
    },
    base64::Engine,
    hocon::{
        Hocon,
        HoconLoader,
    },
    path_clean::PathClean,
    serde_json::Value,
    std::{
        collections::{
            HashMap,
            HashSet,
        },
        fs::Permissions,
        io::Write,
        path::{
            Path,
            PathBuf,
        },
        sync::{
            Arc,
            Mutex,
        },
    },
    zeroize::{
        Zeroize,
        Zeroizing,
    },
};

const PGP_MARKER_PREFIX: &str = "ENC[PGP,";
const ARGON2ID_XCHACHA20_POLY1305_MARKER_PREFIX: &str = "ENC[ARGON2ID-XCHACHA20-POLY1305,";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SealedAlgorithm {
    Pgp,
    Argon2idXchacha20Poly1305,
}

impl SealedAlgorithm {
    fn marker_prefix(self) -> &'static str {
        match self {
            | Self::Pgp => PGP_MARKER_PREFIX,
            | Self::Argon2idXchacha20Poly1305 => ARGON2ID_XCHACHA20_POLY1305_MARKER_PREFIX,
        }
    }

    fn name(self) -> &'static str {
        match self {
            | Self::Pgp => "PGP",
            | Self::Argon2idXchacha20Poly1305 => "ARGON2ID-XCHACHA20-POLY1305",
        }
    }
}

enum CleanupAction {
    Restore {
        path: PathBuf,
        contents: Vec<u8>,
        permissions: Permissions,
    },
    Remove {
        path: PathBuf,
    },
}

impl CleanupAction {
    fn path(&self) -> &Path {
        match self {
            | Self::Restore { path, .. } | Self::Remove { path } => path,
        }
    }

    fn run(&mut self) -> Result<()> {
        match self {
            | Self::Restore {
                path,
                contents,
                permissions,
            } => FileStorage::write_atomic(path, contents, Some(permissions.clone()), ReplaceMode::Overwrite),
            | Self::Remove { path } => {
                match std::fs::remove_file(&path) {
                    | Ok(()) => Ok(()),
                    | Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    | Err(error) => {
                        Err(error)
                            .with_context(|| format!("Failed to remove sealed template output {}", path.display()))
                    },
                }
            },
        }
    }
}

impl Drop for CleanupAction {
    fn drop(&mut self) {
        if let Self::Restore { contents, .. } = self {
            contents.zeroize();
        }
    }
}

#[derive(Clone)]
pub(crate) struct SealedFileRestorer {
    actions: Arc<Mutex<Vec<CleanupAction>>>,
    lifecycle: Arc<Mutex<LifecycleState>>,
}

enum LifecycleState {
    Active,
    ShuttingDown,
}

impl SealedFileRestorer {
    fn push(&self, action: CleanupAction) {
        self.actions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(action);
    }

    fn discard_remove(&self, path: &Path) {
        self.actions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|action| !matches!(action, CleanupAction::Remove { path: action_path } if action_path == path));
    }

    fn while_active<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        let lifecycle = self.lifecycle.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(*lifecycle, LifecycleState::ShuttingDown) {
            anyhow::bail!("Cannot write secret files after restoration has started");
        }
        operation()
    }

    pub(crate) fn restore_all(&self) -> Result<()> {
        let mut lifecycle = self.lifecycle.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *lifecycle = LifecycleState::ShuttingDown;
        let mut pending = {
            let mut actions = self.actions.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut *actions)
        };
        let mut failed = Vec::new();
        let mut failures = Vec::new();

        while let Some(mut action) = pending.pop() {
            if let Err(error) = action.run() {
                failures.push(format!("{}: {}", action.path().display(), error));
                failed.push(action);
            }
        }

        if !failed.is_empty() {
            self.actions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend(failed);
            anyhow::bail!("Failed to restore sealed file(s): {}", failures.join("; "));
        }

        Ok(())
    }
}

struct PreparedTemplate {
    source: PathBuf,
    destination: PathBuf,
    destination_exists: bool,
    secret: SealedSecretWrapper,
}

struct PreparedFile {
    path: PathBuf,
    secret: SealedSecretWrapper,
}

struct PreparedFiles {
    in_place: Vec<PreparedFile>,
    templates: Vec<PreparedTemplate>,
}

struct SelectedFile<'a> {
    source: &'a str,
    secret: &'a SealedSecretWrapper,
}

struct LoadedSecret {
    algorithm: SealedAlgorithm,
    value: Zeroizing<String>,
}

impl PreparedFiles {
    fn is_empty(&self) -> bool {
        self.in_place.is_empty() && self.templates.is_empty()
    }
}

pub(crate) struct SealedFileManager {
    base_dir: PathBuf,
    restorer: SealedFileRestorer,
}

impl SealedFileManager {
    pub(crate) fn new(base_dir: PathBuf) -> Result<Self> {
        let base_dir = base_dir.canonicalize().with_context(|| {
            format!(
                "Failed to canonicalize sealed file base directory {}",
                base_dir.display()
            )
        })?;

        Ok(Self {
            base_dir,
            restorer: SealedFileRestorer {
                actions: Arc::new(Mutex::new(Vec::new())),
                lifecycle: Arc::new(Mutex::new(LifecycleState::Active)),
            },
        })
    }

    #[cfg(test)]
    fn restorer(&self) -> SealedFileRestorer {
        self.restorer.clone()
    }

    pub(crate) fn unseal<C>(
        &self,
        config: &SealedFiles,
        generated_files: &[String],
        removed_env_vars: &[String],
        pgp_manager: &mut PgpManager,
        force: bool,
        mut cancelled: C,
    ) -> Result<()>
    where
        C: FnMut() -> bool,
    {
        let prepared = self.prepare(&config.files, &config.templates, generated_files, force)?;
        if prepared.is_empty() {
            return Ok(());
        }
        // Fetch every per-file key before writing any plaintext document.
        let mut loaded_secrets = Vec::with_capacity(prepared.in_place.len() + prepared.templates.len());
        for secret in prepared
            .in_place
            .iter()
            .map(|file| &file.secret)
            .chain(prepared.templates.iter().map(|template| &template.secret))
        {
            let (algorithm, allocation) = Self::secret_allocation(secret);
            loaded_secrets.push(LoadedSecret {
                algorithm,
                value: Zeroizing::new(
                    allocation
                        .resolve(removed_env_vars)
                        .context("Failed to load encryption secret for sealed file")?,
                ),
            });
        }

        let mut loaded_secrets = loaded_secrets.iter();
        self.apply_with_cancel(
            &prepared,
            |_secret, document| {
                let loaded_secret = loaded_secrets
                    .next()
                    .context("Missing preloaded encryption secret for sealed file")?;
                SealedDocument::decrypt(
                    document,
                    loaded_secret.algorithm,
                    loaded_secret.value.as_str(),
                    pgp_manager,
                )
            },
            &mut cancelled,
        )
    }

    pub(crate) fn restore_all(&self) -> Result<()> {
        self.restorer.restore_all()
    }

    pub(crate) fn validate_profile(
        &self,
        sealed: Option<&SealedFiles>,
        generated_files: &[String],
        force: bool,
    ) -> Result<()> {
        let mut outputs = HashSet::new();
        for configured_path in generated_files {
            let (path, exists) = self.output_file(configured_path)?;
            if exists && !force {
                anyhow::bail!(
                    "File '{}' already exists. Use --force to overwrite it temporarily.",
                    path.display()
                );
            }
            if !outputs.insert(path) {
                anyhow::bail!("Profile file '{}' is configured more than once", configured_path);
            }
        }
        if let Some(sealed) = sealed {
            self.prepare(&sealed.files, &sealed.templates, generated_files, force)?;
        }
        Ok(())
    }

    pub(crate) fn write_generated(&self, configured_path: &str, contents: &str, force: bool) -> Result<()> {
        self.restorer.while_active(|| {
            let (path, exists) = self.output_file(configured_path)?;
            if exists && !force {
                anyhow::bail!(
                    "File '{}' already exists. Use --force to overwrite it temporarily.",
                    path.display()
                );
            }
            self.prepare_output_cleanup(&path, exists)?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create directory for temporary file '{}'", path.display()))?;
            }
            let replace_mode = if exists {
                ReplaceMode::Overwrite
            } else {
                ReplaceMode::Create
            };
            let write_result = FileStorage::write_atomic(&path, contents.as_bytes(), None, replace_mode)
                .with_context(|| format!("Failed to write temporary file '{}'", path.display()));
            if write_result.is_err() && !exists {
                self.restorer.discard_remove(&path);
            }
            write_result
        })
    }

    #[cfg(test)]
    fn while_active<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        self.restorer.while_active(operation)
    }

    pub(crate) fn seal_value(
        &self,
        config: &SealedFiles,
        configured_file: &str,
        plaintext: &str,
        pgp_manager: &PgpManager,
        removed_env_vars: &[String],
    ) -> Result<String> {
        self.prepare(&config.files, &config.templates, &[], true)
            .context("Invalid sealed file configuration")?;
        let selected = Self::select_file(config, configured_file)?;
        Self::encrypt_marker(selected.secret, plaintext, pgp_manager, removed_env_vars)
    }

    pub(crate) fn seal_path(
        &self,
        config: &SealedFiles,
        configured_file: &str,
        json_pointer: &str,
        pgp_manager: &PgpManager,
        removed_env_vars: &[String],
    ) -> Result<String> {
        self.prepare(&config.files, &config.templates, &[], true)
            .context("Invalid sealed file configuration")?;
        let selected = Self::select_file(config, configured_file)?;
        let source_path = self.existing_file(selected.source)?;
        let (contents, permissions) = FileStorage::read_original(&source_path)?;
        let contents = Zeroizing::new(contents);
        let document = std::str::from_utf8(&contents)
            .with_context(|| format!("Sealed source '{}' is not valid UTF-8", source_path.display()))?;
        let (rendered, marker) = SealedDocument::seal_path_with(document, json_pointer, |plaintext| {
            Self::encrypt_marker(selected.secret, plaintext, pgp_manager, removed_env_vars)
        })?;
        let rendered = Zeroizing::new(rendered);
        let write_result = FileStorage::write_atomic(
            &source_path,
            rendered.as_bytes(),
            Some(permissions),
            ReplaceMode::Overwrite,
        )
        .with_context(|| format!("Failed to update sealed source '{}'", source_path.display()));
        write_result?;
        Ok(marker)
    }

    fn select_file<'a>(config: &'a SealedFiles, configured_file: &'a str) -> Result<SelectedFile<'a>> {
        match (config.files.get(configured_file), config.templates.get(configured_file)) {
            | (Some(_), Some(_)) => {
                anyhow::bail!(
                    "Sealed file '{}' is configured as both a file and template",
                    configured_file
                )
            },
            | (Some(file), None) => {
                Ok(SelectedFile {
                    source: configured_file,
                    secret: &file.secret,
                })
            },
            | (None, Some(template)) => {
                if config
                    .templates
                    .values()
                    .filter(|candidate| candidate.source == template.source)
                    .count()
                    > 1
                {
                    anyhow::bail!(
                        "Sealed template source '{}' is configured for more than one output",
                        template.source
                    );
                }
                Ok(SelectedFile {
                    source: &template.source,
                    secret: &template.secret,
                })
            },
            | (None, None) => {
                anyhow::bail!(
                    "Sealed file '{}' is not configured in the selected profile",
                    configured_file
                )
            },
        }
    }

    fn encrypt_marker(
        secret: &SealedSecretWrapper,
        plaintext: &str,
        pgp_manager: &PgpManager,
        removed_env_vars: &[String],
    ) -> Result<String> {
        let (algorithm, allocation) = Self::secret_allocation(secret);
        let secret_value = Zeroizing::new(
            allocation
                .resolve(removed_env_vars)
                .context("Failed to load encryption secret for sealed file")?,
        );
        let ciphertext = match algorithm {
            | SealedAlgorithm::Pgp => {
                pgp_manager
                    .encrypt(secret_value.as_str(), plaintext)
                    .context("Failed to encrypt sealed value with PGP")?
            },
            | SealedAlgorithm::Argon2idXchacha20Poly1305 => PasswordCipher::encrypt(secret_value.as_str(), plaintext)?,
        };
        Ok(format!(
            "{}{}]",
            algorithm.marker_prefix(),
            base64::engine::general_purpose::STANDARD.encode(ciphertext)
        ))
    }

    fn secret_allocation(secret: &SealedSecretWrapper) -> (SealedAlgorithm, &SecretAllocation) {
        match &secret.inner {
            | SealedSecret::Pgp(allocation) => (SealedAlgorithm::Pgp, &allocation.inner),
            | SealedSecret::Argon2idXchacha20Poly1305(allocation) => {
                (SealedAlgorithm::Argon2idXchacha20Poly1305, &allocation.inner)
            },
        }
    }

    fn prepare(
        &self,
        in_place: &HashMap<String, SealedFile>,
        templates: &HashMap<String, SealedTemplate>,
        generated_files: &[String],
        force: bool,
    ) -> Result<PreparedFiles> {
        let mut prepared_in_place = Vec::with_capacity(in_place.len());
        let mut prepared_templates = Vec::with_capacity(templates.len());
        let mut targets = HashSet::new();
        let mut template_sources = HashSet::new();

        let mut file_entries: Vec<_> = in_place.iter().collect();
        file_entries.sort_by_key(|(path, _)| *path);

        for (configured_path, config) in file_entries {
            let path = self.existing_file(configured_path)?;
            if !targets.insert(path.clone()) {
                anyhow::bail!("Sealed file '{}' is configured more than once", configured_path);
            }
            prepared_in_place.push(PreparedFile {
                path,
                secret: config.secret.clone(),
            });
        }

        let mut template_entries: Vec<_> = templates.iter().collect();
        template_entries.sort_by_key(|(path, _)| *path);

        for (destination, config) in template_entries {
            let source = self.existing_file(&config.source)?;
            let (destination, destination_exists) = self.output_file(destination)?;

            if destination_exists && !force {
                anyhow::bail!(
                    "Sealed template output '{}' already exists. Use --force to overwrite it temporarily.",
                    destination.display()
                );
            }
            if !targets.insert(destination.clone()) {
                anyhow::bail!("Sealed target '{}' is configured more than once", destination.display());
            }
            if !template_sources.insert(source.clone()) {
                anyhow::bail!(
                    "Sealed template source '{}' is configured for more than one output",
                    source.display()
                );
            }
            prepared_templates.push(PreparedTemplate {
                source,
                destination,
                destination_exists,
                secret: config.secret.clone(),
            });
        }

        if let Some(conflict) = targets.intersection(&template_sources).next() {
            anyhow::bail!(
                "Sealed template source '{}' is also configured as an output; use a separate template path",
                conflict.display()
            );
        }

        for generated_file in generated_files {
            let (generated_file, _) = self.output_file(generated_file)?;
            if targets.contains(&generated_file) || template_sources.contains(&generated_file) {
                anyhow::bail!(
                    "Profile file '{}' conflicts with a sealed file, template, or output",
                    generated_file.display()
                );
            }
        }

        Ok(PreparedFiles {
            in_place: prepared_in_place,
            templates: prepared_templates,
        })
    }

    #[cfg(test)]
    fn apply<F>(&self, prepared: &PreparedFiles, decrypt: F) -> Result<()>
    where F: FnMut(&SealedSecretWrapper, &str) -> Result<String> {
        self.apply_with_cancel(prepared, decrypt, || false)
    }

    fn apply_with_cancel<F, C>(&self, prepared: &PreparedFiles, mut decrypt: F, mut cancelled: C) -> Result<()>
    where
        F: FnMut(&SealedSecretWrapper, &str) -> Result<String>,
        C: FnMut() -> bool,
    {
        self.restorer.while_active(|| {
            let mut materialized_files = Vec::with_capacity(prepared.in_place.len());
            for file in &prepared.in_place {
                if cancelled() {
                    anyhow::bail!("Interrupted before plaintext files were written");
                }
                let (contents, permissions) = FileStorage::read_original(&file.path)?;
                let document = std::str::from_utf8(&contents)
                    .with_context(|| format!("Sealed file '{}' is not valid UTF-8", file.path.display()))?;
                let decrypted = Zeroizing::new(
                    decrypt(&file.secret, document)
                        .with_context(|| format!("Failed to decrypt sealed file '{}'", file.path.display()))?,
                );
                materialized_files.push((file, contents, permissions, decrypted));
            }

            let mut materialized_templates = Vec::with_capacity(prepared.templates.len());
            for template in &prepared.templates {
                if cancelled() {
                    anyhow::bail!("Interrupted before plaintext files were written");
                }
                let (source, _) = FileStorage::read_original(&template.source)?;
                let source = std::str::from_utf8(&source)
                    .with_context(|| format!("Sealed template '{}' is not valid UTF-8", template.source.display()))?;
                let decrypted =
                    Zeroizing::new(decrypt(&template.secret, source).with_context(|| {
                        format!("Failed to decrypt sealed template '{}'", template.source.display())
                    })?);
                materialized_templates.push((template, decrypted));
            }

            if cancelled() {
                anyhow::bail!("Interrupted before plaintext files were written");
            }

            for (file, contents, permissions, decrypted) in materialized_files {
                self.restorer.push(CleanupAction::Restore {
                    path: file.path.clone(),
                    contents,
                    permissions,
                });
                let write_result =
                    FileStorage::write_atomic(&file.path, decrypted.as_bytes(), None, ReplaceMode::Overwrite)
                        .with_context(|| format!("Failed to replace sealed file '{}'", file.path.display()));
                write_result?;
            }

            for (template, decrypted) in materialized_templates {
                self.prepare_output_cleanup(&template.destination, template.destination_exists)?;
                if let Some(parent) = template.destination.parent() {
                    std::fs::create_dir_all(parent).with_context(|| {
                        format!(
                            "Failed to create sealed template output directory '{}'",
                            parent.display()
                        )
                    })?;
                }
                let replace_mode = if template.destination_exists {
                    ReplaceMode::Overwrite
                } else {
                    ReplaceMode::Create
                };
                let write_result =
                    FileStorage::write_atomic(&template.destination, decrypted.as_bytes(), None, replace_mode)
                        .with_context(|| {
                            format!(
                                "Failed to write sealed template output '{}'",
                                template.destination.display()
                            )
                        });
                if write_result.is_err() && !template.destination_exists {
                    self.restorer.discard_remove(&template.destination);
                }
                write_result?;
            }

            Ok(())
        })
    }

    fn prepare_output_cleanup(&self, path: &Path, expected_exists: bool) -> Result<()> {
        match (expected_exists, path.try_exists()) {
            | (_, Err(error)) => {
                Err(error).with_context(|| format!("Failed to inspect temporary output '{}'", path.display()))
            },
            | (true, Ok(true)) => {
                let (contents, permissions) = FileStorage::read_original(path)?;
                self.restorer.push(CleanupAction::Restore {
                    path: path.to_path_buf(),
                    contents,
                    permissions,
                });
                Ok(())
            },
            | (false, Ok(false)) => {
                self.restorer.push(CleanupAction::Remove {
                    path: path.to_path_buf(),
                });
                Ok(())
            },
            | _ => {
                anyhow::bail!("Temporary output '{}' changed while preparing it", path.display())
            },
        }
    }

    fn existing_file(&self, configured_path: &str) -> Result<PathBuf> {
        let path = self.resolve(configured_path);
        let link_metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("Failed to inspect sealed file '{}'", configured_path))?;
        if link_metadata.file_type().is_symlink() {
            anyhow::bail!("Sealed file '{}' must not be a symbolic link", configured_path);
        }
        if !link_metadata.is_file() {
            anyhow::bail!("Sealed path '{}' is not a regular file", configured_path);
        }
        FileStorage::ensure_single_link(&link_metadata, &path)?;

        let canonical = path
            .canonicalize()
            .with_context(|| format!("Failed to canonicalize sealed file '{}'", configured_path))?;
        self.ensure_contained(&canonical, configured_path)?;
        Ok(canonical)
    }

    fn output_file(&self, configured_path: &str) -> Result<(PathBuf, bool)> {
        let path = self.resolve(configured_path);
        match std::fs::symlink_metadata(&path) {
            | Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    anyhow::bail!(
                        "Sealed template output '{}' must not be a symbolic link",
                        configured_path
                    );
                }
                if !metadata.is_file() {
                    anyhow::bail!("Sealed template output '{}' is not a regular file", configured_path);
                }
                FileStorage::ensure_single_link(&metadata, &path)?;
                let canonical = path
                    .canonicalize()
                    .with_context(|| format!("Failed to canonicalize sealed template output '{}'", configured_path))?;
                self.ensure_contained(&canonical, configured_path)?;
                Ok((canonical, true))
            },
            | Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let path = self.canonicalize_missing_output(&path, configured_path)?;
                Ok((path, false))
            },
            | Err(error) => {
                Err(error).with_context(|| format!("Failed to inspect sealed template output '{}'", configured_path))
            },
        }
    }

    fn canonicalize_missing_output(&self, path: &Path, configured_path: &str) -> Result<PathBuf> {
        let parent = path
            .parent()
            .with_context(|| format!("Sealed template output '{}' has no parent directory", configured_path))?;
        let mut existing_ancestor = parent;
        while !existing_ancestor.exists() {
            existing_ancestor = existing_ancestor.parent().with_context(|| {
                format!(
                    "Could not resolve parent directory for sealed template output '{}'",
                    configured_path
                )
            })?;
        }

        let canonical_ancestor = existing_ancestor.canonicalize().with_context(|| {
            format!(
                "Failed to canonicalize parent of sealed template output '{}'",
                configured_path
            )
        })?;
        self.ensure_contained(&canonical_ancestor, configured_path)?;

        let missing_suffix = parent
            .strip_prefix(existing_ancestor)
            .with_context(|| format!("Failed to resolve sealed template output path '{}'", configured_path))?;
        let file_name = path
            .file_name()
            .with_context(|| format!("Sealed template output '{}' has no file name", configured_path))?;
        let canonical = canonical_ancestor.join(missing_suffix).join(file_name).clean();
        self.ensure_contained(&canonical, configured_path)?;
        Ok(canonical)
    }

    fn ensure_contained(&self, path: &Path, configured_path: &str) -> Result<()> {
        if !path.starts_with(&self.base_dir) {
            anyhow::bail!(
                "Sealed path '{}' escapes the project directory '{}'.",
                configured_path,
                self.base_dir.display()
            );
        }
        Ok(())
    }

    fn resolve(&self, configured_path: &str) -> PathBuf {
        let path = Path::new(configured_path);
        if path.is_absolute() {
            path.to_path_buf().clean()
        } else {
            self.base_dir.join(path).clean()
        }
    }
}

impl Drop for SealedFileManager {
    fn drop(&mut self) {
        if let Err(error) = self.restorer.restore_all() {
            eprintln!("WARNING: {}", error);
        }
    }
}

struct SealedDocument;

struct SensitiveValue(Value);

impl SensitiveValue {
    fn new(value: Value) -> Self {
        Self(value)
    }

    fn as_value(&self) -> &Value {
        &self.0
    }

    fn as_value_mut(&mut self) -> &mut Value {
        &mut self.0
    }

    fn into_value(mut self) -> Value {
        std::mem::replace(&mut self.0, Value::Null)
    }

    fn push(&mut self, value: SensitiveValue) -> Result<()> {
        let Value::Array(values) = &mut self.0 else {
            anyhow::bail!("Cannot append a value to a non-array document node");
        };
        values.push(value.into_value());
        Ok(())
    }

    fn insert(&mut self, key: String, value: SensitiveValue) -> Result<()> {
        let Value::Object(values) = &mut self.0 else {
            anyhow::bail!("Cannot insert a value into a non-object document node");
        };
        values.insert(key, value.into_value());
        Ok(())
    }
}

impl Drop for SensitiveValue {
    fn drop(&mut self) {
        SealedDocument::zeroize_value(&mut self.0);
    }
}

impl SealedDocument {
    fn decrypt(
        document: &str,
        algorithm: SealedAlgorithm,
        secret: &str,
        pgp_manager: &mut PgpManager,
    ) -> Result<String> {
        Self::decrypt_with(document, algorithm, |_marker_algorithm, ciphertext| {
            match algorithm {
                | SealedAlgorithm::Pgp => pgp_manager.decrypt_bytes(secret, ciphertext),
                | SealedAlgorithm::Argon2idXchacha20Poly1305 => PasswordCipher::decrypt(secret, ciphertext),
            }
        })
    }

    fn decrypt_with<F>(document: &str, algorithm: SealedAlgorithm, mut decrypt: F) -> Result<String>
    where F: FnMut(SealedAlgorithm, &[u8]) -> Result<String> {
        let mut value = Self::parse_value(document)?;
        let mut decrypted_count = 0;
        Self::decrypt_markers(value.as_value_mut(), "$", algorithm, &mut decrypted_count, &mut decrypt)?;
        if decrypted_count == 0 {
            anyhow::bail!("Document contains no supported ENC[<algorithm>,<base64>] values");
        }

        Self::render(&value)
    }

    fn parse_value(document: &str) -> Result<SensitiveValue> {
        if let Ok(value) = serde_json::from_str(document) {
            return Ok(SensitiveValue::new(value));
        }
        let value = Self::parse_document(document).context("Failed to parse document as HOCON or JSON")?;
        Self::convert(value, "$")
    }

    fn seal_path_with<F>(document: &str, json_pointer: &str, seal: F) -> Result<(String, String)>
    where F: FnOnce(&str) -> Result<String> {
        if document.contains("${") && serde_json::from_str::<Value>(document).is_err() {
            anyhow::bail!("JSON Pointer sealing does not support HOCON substitutions");
        }
        let mut value = Self::parse_value(document)?;
        let target = value
            .as_value_mut()
            .pointer_mut(json_pointer)
            .with_context(|| format!("JSON Pointer '{}' does not select a value", json_pointer))?;
        let Value::String(plaintext) = target else {
            anyhow::bail!("JSON Pointer '{}' must select a string value", json_pointer);
        };
        if plaintext.starts_with("ENC[") {
            anyhow::bail!("JSON Pointer '{}' already contains a sealed value", json_pointer);
        }

        let marker = seal(plaintext)?;
        plaintext.zeroize();
        *plaintext = marker.clone();
        Ok((Self::render(&value)?, marker))
    }

    fn render(value: &SensitiveValue) -> Result<String> {
        let mut rendered = serde_json::to_string_pretty(value.as_value()).context("Failed to serialize document")?;
        rendered.push('\n');
        Ok(rendered)
    }

    fn parse_document(document: &str) -> std::result::Result<Hocon, hocon::Error> {
        let parse = |document| {
            HoconLoader::new()
                .no_system()
                .strict()
                .load_str(document)
                .and_then(|loader| loader.hocon())
        };

        match parse(document) {
            | Ok(value) => Ok(value),
            | Err(_) if !document.trim_start().starts_with(['{', '[']) => parse(&format!("{{\n{}\n}}", document)),
            | Err(error) => Err(error),
        }
    }

    fn convert(value: Hocon, path: &str) -> Result<SensitiveValue> {
        match value {
            | Hocon::String(string) => Ok(SensitiveValue::new(Value::String(string))),
            | Hocon::Array(values) => {
                let mut converted = SensitiveValue::new(Value::Array(Vec::with_capacity(values.len())));
                for (index, value) in values.into_iter().enumerate() {
                    converted.push(Self::convert(value, &format!("{}[{}]", path, index))?)?;
                }
                Ok(converted)
            },
            | Hocon::Hash(values) => {
                let mut converted = SensitiveValue::new(Value::Object(serde_json::Map::with_capacity(values.len())));
                for (key, value) in values {
                    converted.insert(key.clone(), Self::convert(value, &format!("{}.{}", path, key))?)?;
                }
                Ok(converted)
            },
            | Hocon::Integer(value) => Ok(SensitiveValue::new(Value::Number(value.into()))),
            | Hocon::Real(value) => {
                let number = serde_json::Number::from_f64(value)
                    .with_context(|| format!("Non-finite number at {} cannot be represented as JSON", path))?;
                Ok(SensitiveValue::new(Value::Number(number)))
            },
            | Hocon::Boolean(value) => Ok(SensitiveValue::new(Value::Bool(value))),
            | Hocon::Null => Ok(SensitiveValue::new(Value::Null)),
            | Hocon::BadValue(error) => {
                Err(anyhow::anyhow!(error)).with_context(|| format!("Invalid value at {}", path))
            },
        }
    }

    fn decrypt_markers<F>(
        value: &mut Value,
        path: &str,
        expected_algorithm: SealedAlgorithm,
        decrypted_count: &mut usize,
        decrypt: &mut F,
    ) -> Result<()>
    where
        F: FnMut(SealedAlgorithm, &[u8]) -> Result<String>,
    {
        match value {
            | Value::String(string) => {
                if let Some((algorithm, ciphertext)) =
                    Self::decode_marker(string).with_context(|| format!("Invalid sealed value at {}", path))?
                {
                    if algorithm != expected_algorithm {
                        anyhow::bail!(
                            "Sealed value at {} uses {}, but the file is configured for {}",
                            path,
                            algorithm.name(),
                            expected_algorithm.name()
                        );
                    }
                    *string = decrypt(algorithm, &ciphertext)
                        .with_context(|| format!("Failed to decrypt sealed value at {}", path))?;
                    *decrypted_count += 1;
                }
            },
            | Value::Array(values) => {
                for (index, value) in values.iter_mut().enumerate() {
                    Self::decrypt_markers(
                        value,
                        &format!("{}[{}]", path, index),
                        expected_algorithm,
                        decrypted_count,
                        decrypt,
                    )?;
                }
            },
            | Value::Object(values) => {
                for (key, value) in values {
                    Self::decrypt_markers(
                        value,
                        &format!("{}.{}", path, key),
                        expected_algorithm,
                        decrypted_count,
                        decrypt,
                    )?;
                }
            },
            | _ => {},
        }
        Ok(())
    }

    fn decode_marker(value: &str) -> Result<Option<(SealedAlgorithm, Vec<u8>)>> {
        if !value.starts_with("ENC[") {
            return Ok(None);
        }

        let (algorithm, encoded) = if let Some(encoded) = value.strip_prefix(PGP_MARKER_PREFIX) {
            (SealedAlgorithm::Pgp, encoded)
        } else if let Some(encoded) = value.strip_prefix(ARGON2ID_XCHACHA20_POLY1305_MARKER_PREFIX) {
            (SealedAlgorithm::Argon2idXchacha20Poly1305, encoded)
        } else {
            anyhow::bail!("Expected ENC[PGP,<base64>] or ENC[ARGON2ID-XCHACHA20-POLY1305,<base64>] marker");
        };
        let encoded = encoded
            .strip_suffix(']')
            .context("Sealed marker is missing closing ']'")?;
        if encoded.is_empty() {
            anyhow::bail!("Encrypted payload is empty");
        }

        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .context("Encrypted payload is not valid base64")?;
        Ok(Some((algorithm, ciphertext)))
    }

    fn zeroize_value(value: &mut Value) {
        match value {
            | Value::String(value) => value.zeroize(),
            | Value::Array(values) => {
                for value in values {
                    Self::zeroize_value(value);
                }
            },
            | Value::Object(values) => {
                for value in values.values_mut() {
                    Self::zeroize_value(value);
                }
            },
            | _ => {},
        }
    }
}

struct FileStorage;

impl FileStorage {
    fn read_original(path: &Path) -> Result<(Vec<u8>, Permissions)> {
        let metadata = std::fs::symlink_metadata(path)
            .with_context(|| format!("Failed to inspect sealed target '{}'", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            anyhow::bail!("Sealed target '{}' is no longer a regular file", path.display());
        }
        Self::ensure_single_link(&metadata, path)?;
        let canonical = path
            .canonicalize()
            .with_context(|| format!("Failed to canonicalize sealed target '{}'", path.display()))?;
        if canonical != path {
            anyhow::bail!("Sealed target '{}' changed after validation", path.display());
        }
        let contents =
            std::fs::read(path).with_context(|| format!("Failed to read sealed target '{}'", path.display()))?;
        Ok((contents, metadata.permissions()))
    }

    #[cfg(unix)]
    fn ensure_single_link(metadata: &std::fs::Metadata, path: &Path) -> Result<()> {
        if metadata.nlink() > 1 {
            anyhow::bail!("Sealed path '{}' must not have hard-link aliases", path.display());
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn ensure_single_link(_metadata: &std::fs::Metadata, _path: &Path) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum ReplaceMode {
    Create,
    Overwrite,
}

impl FileStorage {
    fn write_atomic(
        path: &Path,
        contents: &[u8],
        restore_permissions: Option<Permissions>,
        replace_mode: ReplaceMode,
    ) -> Result<()> {
        let parent = path
            .parent()
            .with_context(|| format!("Path '{}' has no parent directory", path.display()))?;
        let canonical_parent = parent
            .canonicalize()
            .with_context(|| format!("Failed to canonicalize parent of '{}'", path.display()))?;
        if canonical_parent != parent {
            anyhow::bail!("Parent directory of '{}' changed after validation", path.display());
        }

        let mut temporary = tempfile::NamedTempFile::new_in(parent)
            .with_context(|| format!("Failed to create temporary file beside '{}'", path.display()))?;

        temporary
            .write_all(contents)
            .with_context(|| format!("Failed to write temporary file for '{}'", path.display()))?;
        if let Some(permissions) = restore_permissions {
            temporary
                .as_file()
                .set_permissions(permissions)
                .with_context(|| format!("Failed to set permissions for temporary file '{}'", path.display()))?;
        } else {
            #[cfg(unix)]
            temporary
                .as_file()
                .set_permissions(Permissions::from_mode(0o600))
                .with_context(|| format!("Failed to secure temporary file for '{}'", path.display()))?;
        }
        temporary
            .as_file_mut()
            .sync_all()
            .with_context(|| format!("Failed to sync temporary file for '{}'", path.display()))?;
        let persist_result = match replace_mode {
            | ReplaceMode::Create => temporary.persist_noclobber(path),
            | ReplaceMode::Overwrite => temporary.persist(path),
        };
        persist_result
            .map_err(|error| error.error)
            .with_context(|| format!("Failed to atomically replace '{}'", path.display()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::manifest::SecretAllocationWrapper,
        std::fs,
    };

    fn marker(value: &str) -> String {
        format!(
            "{}{}]",
            PGP_MARKER_PREFIX,
            base64::engine::general_purpose::STANDARD.encode(value)
        )
    }

    fn password_marker(value: &str, passphrase: &str) -> Result<String> {
        Ok(format!(
            "{}{}]",
            ARGON2ID_XCHACHA20_POLY1305_MARKER_PREFIX,
            base64::engine::general_purpose::STANDARD.encode(PasswordCipher::encrypt(passphrase, value)?)
        ))
    }

    fn fake_decrypt(document: &str) -> Result<String> {
        SealedDocument::decrypt_with(document, SealedAlgorithm::Pgp, |_algorithm, ciphertext| {
            let ciphertext = std::str::from_utf8(ciphertext)?;
            Ok(format!("decrypted:{}", ciphertext))
        })
    }

    fn fake_apply(_secret: &SealedSecretWrapper, document: &str) -> Result<String> {
        fake_decrypt(document)
    }

    fn remote_secret(name: &str) -> SealedSecretWrapper {
        SealedSecretWrapper {
            inner: SealedSecret::Pgp(SecretAllocationWrapper {
                inner: SecretAllocation::Gcp {
                    secret: format!("projects/example/secrets/{}", name),
                    version: None,
                },
            }),
        }
    }

    fn remote_password_secret(name: &str) -> SealedSecretWrapper {
        SealedSecretWrapper {
            inner: SealedSecret::Argon2idXchacha20Poly1305(SecretAllocationWrapper {
                inner: SecretAllocation::Gcp {
                    secret: format!("projects/example/secrets/{}", name),
                    version: None,
                },
            }),
        }
    }

    fn sealed_files(paths: &[&Path]) -> HashMap<String, SealedFile> {
        paths
            .iter()
            .enumerate()
            .map(|(index, path)| {
                (path.display().to_string(), SealedFile {
                    secret: remote_secret(&format!("file-key-{}", index)),
                })
            })
            .collect()
    }

    fn sealed_templates(paths: &[(&Path, &Path)]) -> HashMap<String, SealedTemplate> {
        paths
            .iter()
            .enumerate()
            .map(|(index, (destination, source))| {
                (destination.display().to_string(), SealedTemplate {
                    source: source.display().to_string(),
                    secret: remote_secret(&format!("template-key-{}", index)),
                })
            })
            .collect()
    }

    #[test]
    fn decrypts_marked_hocon_values() -> Result<()> {
        let document = format!(
            r#"
            database {{
              host = "localhost"
              password = "{}"
              replicas = [{{ password = "{}" }}]
              port = 5432
            }}
            "#,
            marker("primary"),
            marker("replica")
        );

        let rendered = fake_decrypt(&document)?;
        let value: Value = serde_json::from_str(&rendered)?;

        assert_eq!(value["database"]["host"], "localhost");
        assert_eq!(value["database"]["password"], "decrypted:primary");
        assert_eq!(value["database"]["replicas"][0]["password"], "decrypted:replica");
        assert_eq!(value["database"]["port"], 5432);
        Ok(())
    }

    #[test]
    fn decrypts_marked_json_values() -> Result<()> {
        let document = serde_json::json!({
            "enabled": true,
            "token": marker("json-token"),
            "untouched": "ordinary value",
        })
        .to_string();

        let rendered = fake_decrypt(&document)?;
        let value: Value = serde_json::from_str(&rendered)?;

        assert_eq!(value["enabled"], true);
        assert_eq!(value["token"], "decrypted:json-token");
        assert_eq!(value["untouched"], "ordinary value");
        Ok(())
    }

    #[test]
    fn decrypts_argon2id_xchacha20_poly1305_values() -> Result<()> {
        let passphrase = "correct horse battery staple";
        let document = serde_json::json!({
            "token": password_marker("password-encrypted", passphrase)?,
        })
        .to_string();
        let mut pgp_manager = PgpManager::default();

        let rendered = SealedDocument::decrypt(
            &document,
            SealedAlgorithm::Argon2idXchacha20Poly1305,
            passphrase,
            &mut pgp_manager,
        )?;
        let value: Value = serde_json::from_str(&rendered)?;
        assert_eq!(value["token"], "password-encrypted");

        let mismatch = SealedDocument::decrypt(&document, SealedAlgorithm::Pgp, "not-a-pgp-key", &mut pgp_manager);
        assert!(format!("{:#}", mismatch.unwrap_err()).contains("configured for PGP"));
        Ok(())
    }

    #[test]
    fn rejects_missing_and_malformed_markers() {
        let no_marker = fake_decrypt(r#"key = "ordinary value""#).unwrap_err();
        assert!(no_marker.to_string().contains("contains no supported"));

        let malformed = fake_decrypt(r#"key = "ENC[other,value]""#).unwrap_err();
        assert!(format!("{:#}", malformed).contains("Expected ENC[PGP,<base64>]"));

        let invalid_base64 = fake_decrypt(r#"key = "ENC[PGP,not-base64!]""#).unwrap_err();
        assert!(format!("{:#}", invalid_base64).contains("Encrypted payload is not valid base64"));

        let trailing_garbage = fake_decrypt(&format!(r#"{{ key = "{}" }} !!!"#, marker("secret"))).unwrap_err();
        assert!(format!("{:#}", trailing_garbage).contains("Failed to parse document"));
    }

    #[test]
    fn does_not_expand_system_environment_substitutions() {
        let document = format!("secret = \"{}\"\nparent_path = ${{PATH}}", marker("secret"));
        let error = fake_decrypt(&document).unwrap_err();
        assert!(format!("{:#}", error).contains("Failed to parse document"));
    }

    #[test]
    fn seals_a_string_selected_by_json_pointer() -> Result<()> {
        let existing_marker = marker("existing");
        let document = format!(
            r#"
            database {{
              password = "plaintext"
              existing = "{}"
            }}
            "#,
            existing_marker
        );

        let (rendered, new_marker) = SealedDocument::seal_path_with(&document, "/database/password", |plaintext| {
            assert_eq!(plaintext, "plaintext");
            Ok("ENC[PGP,new-marker]".to_string())
        })?;
        let value: Value = serde_json::from_str(&rendered)?;
        assert_eq!(new_marker, "ENC[PGP,new-marker]");
        assert_eq!(value["database"]["password"], new_marker);
        assert_eq!(value["database"]["existing"], existing_marker);
        Ok(())
    }

    #[test]
    fn json_pointer_sealing_rejects_non_strings_and_sealed_values() {
        let non_string = SealedDocument::seal_path_with(r#"value = 1"#, "/value", |_| Ok("unused".to_string()));
        assert!(format!("{:#}", non_string.unwrap_err()).contains("must select a string"));

        let already_sealed =
            SealedDocument::seal_path_with(&format!(r#"value = "{}""#, marker("existing")), "/value", |_| {
                Ok("unused".to_string())
            });
        assert!(format!("{:#}", already_sealed.unwrap_err()).contains("already contains a sealed value"));

        let substitution = SealedDocument::seal_path_with(
            r#"value = "plaintext"
               copy = ${value}"#,
            "/value",
            |_| Ok("unused".to_string()),
        );
        assert!(format!("{:#}", substitution.unwrap_err()).contains("does not support HOCON substitutions"));

        let json_literal = SealedDocument::seal_path_with(r#"{"value":"${literal}"}"#, "/value", |_| {
            Ok("ENC[PGP,new-marker]".to_string())
        });
        assert!(json_literal.is_ok());
    }

    #[test]
    fn restores_in_place_files_and_removes_template_outputs() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let in_place = directory.path().join("application.conf");
        let template = directory.path().join("credentials.json.sealed");
        let output = directory.path().join("credentials.json");
        let original = format!(r#"password = "{}""#, marker("in-place"));
        fs::write(&in_place, &original)?;
        fs::write(
            &template,
            serde_json::json!({ "token": marker("template") }).to_string(),
        )?;

        #[cfg(unix)]
        let original_mode = fs::metadata(&in_place)?.permissions().mode() & 0o777;

        let manager = SealedFileManager::new(directory.path().to_path_buf())?;
        let in_place_config = sealed_files(&[&in_place]);
        let templates = sealed_templates(&[(&output, &template)]);
        assert!(manager
            .prepare(&in_place_config, &templates, &[template.display().to_string()], false)
            .is_err());
        let prepared = manager.prepare(&in_place_config, &templates, &[], false)?;
        manager.apply(&prepared, fake_apply)?;

        let in_place_value: Value = serde_json::from_str(&fs::read_to_string(&in_place)?)?;
        let output_value: Value = serde_json::from_str(&fs::read_to_string(&output)?)?;
        assert_eq!(in_place_value["password"], "decrypted:in-place");
        assert_eq!(output_value["token"], "decrypted:template");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&in_place)?.permissions().mode() & 0o777, 0o600);
            assert_eq!(fs::metadata(&output)?.permissions().mode() & 0o777, 0o600);
        }

        manager.restore_all()?;
        assert_eq!(fs::read_to_string(&in_place)?, original);
        assert!(!output.exists());
        #[cfg(unix)]
        assert_eq!(fs::metadata(&in_place)?.permissions().mode() & 0o777, original_mode);
        Ok(())
    }

    #[test]
    fn drop_restores_materialized_files() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let in_place = directory.path().join("application.conf");
        let original = format!(r#"password = "{}""#, marker("in-place"));
        fs::write(&in_place, &original)?;

        {
            let manager = SealedFileManager::new(directory.path().to_path_buf())?;
            let prepared = manager.prepare(&sealed_files(&[&in_place]), &HashMap::new(), &[], false)?;
            manager.apply(&prepared, fake_apply)?;
            assert_ne!(fs::read_to_string(&in_place)?, original);
        }

        assert_eq!(fs::read_to_string(&in_place)?, original);
        Ok(())
    }

    #[test]
    fn generated_files_are_removed_or_restored() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let created = directory.path().join("created.secret");
        let existing = directory.path().join("existing.secret");
        fs::write(&existing, "original")?;

        let manager = SealedFileManager::new(directory.path().to_path_buf())?;
        manager.write_generated(&created.display().to_string(), "created plaintext", false)?;
        manager.write_generated(&existing.display().to_string(), "replacement plaintext", true)?;
        assert_eq!(fs::read_to_string(&created)?, "created plaintext");
        assert_eq!(fs::read_to_string(&existing)?, "replacement plaintext");

        manager.restore_all()?;
        assert!(!created.exists());
        assert_eq!(fs::read_to_string(&existing)?, "original");
        Ok(())
    }

    #[test]
    fn manifest_directory_is_the_sealed_path_base() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let project = directory.path().join("project");
        fs::create_dir(&project)?;
        let manifest = crate::manifest::Manifest::example(project.join("secenv.conf"));
        let manager = SealedFileManager::new(manifest.source_directory()?)?;

        let output = project.join("generated.secret");
        manager.write_generated("./generated.secret", "plaintext", false)?;
        assert_eq!(fs::read_to_string(&output)?, "plaintext");
        manager.restore_all()?;
        assert!(!output.exists());
        Ok(())
    }

    #[test]
    fn force_restores_an_existing_template_output() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let template = directory.path().join("credentials.json.sealed");
        let output = directory.path().join("credentials.json");
        let original_output = b"existing output\n";
        fs::write(
            &template,
            serde_json::json!({ "token": marker("template") }).to_string(),
        )?;
        fs::write(&output, original_output)?;

        let manager = SealedFileManager::new(directory.path().to_path_buf())?;
        let templates = sealed_templates(&[(&output, &template)]);
        assert!(manager.prepare(&HashMap::new(), &templates, &[], false).is_err());

        let prepared = manager.prepare(&HashMap::new(), &templates, &[], true)?;
        manager.apply(&prepared, fake_apply)?;
        assert_ne!(fs::read(&output)?, original_output);

        manager.restore_all()?;
        assert_eq!(fs::read(&output)?, original_output);
        Ok(())
    }

    #[test]
    fn rejects_a_template_source_shared_by_multiple_outputs() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("shared.json.sealed");
        let first_output = directory.path().join("first.json");
        let second_output = directory.path().join("second.json");
        fs::write(&source, serde_json::json!({ "token": marker("value") }).to_string())?;

        let manager = SealedFileManager::new(directory.path().to_path_buf())?;
        let templates = sealed_templates(&[(&first_output, &source), (&second_output, &source)]);
        assert!(manager.prepare(&HashMap::new(), &templates, &[], false).is_err());
        Ok(())
    }

    #[test]
    fn sealing_rejects_paths_owned_by_multiple_keys() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("shared.json");
        let output = directory.path().join("rendered.json");
        fs::write(&source, serde_json::json!({ "token": "plaintext" }).to_string())?;

        let config = SealedFiles {
            files: sealed_files(&[&source]),
            templates: sealed_templates(&[(&output, &source)]),
        };
        let manager = SealedFileManager::new(directory.path().to_path_buf())?;
        let pgp_manager = PgpManager::default();
        let error = manager
            .seal_value(&config, &source.display().to_string(), "plaintext", &pgp_manager, &[])
            .unwrap_err();
        assert!(format!("{:#}", error).contains("also configured as an output"));
        Ok(())
    }

    #[test]
    fn restores_files_after_a_partial_apply_error() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let first = directory.path().join("first.conf");
        let second = directory.path().join("second.conf");
        let first_original = format!(r#"secret = "{}""#, marker("first"));
        let second_original = format!(r#"secret = "{}""#, marker("second"));
        fs::write(&first, &first_original)?;
        fs::write(&second, &second_original)?;

        let manager = SealedFileManager::new(directory.path().to_path_buf())?;
        let files = sealed_files(&[&first, &second]);
        let prepared = manager.prepare(&files, &HashMap::new(), &[], false)?;
        let mut calls = 0;
        let error = manager
            .apply(&prepared, |_secret, document| {
                calls += 1;
                if calls == 2 {
                    anyhow::bail!("simulated decryption failure");
                }
                fake_decrypt(document)
            })
            .unwrap_err();
        assert!(format!("{:#}", error).contains("simulated decryption failure"));
        assert_eq!(fs::read_to_string(&first)?, first_original);
        assert_eq!(fs::read_to_string(&second)?, second_original);

        manager.restore_all()?;
        assert_eq!(fs::read_to_string(&first)?, first_original);
        assert_eq!(fs::read_to_string(&second)?, second_original);
        Ok(())
    }

    #[test]
    fn each_file_carries_its_own_key() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let first = directory.path().join("first.conf");
        let second = directory.path().join("second.conf");
        fs::write(&first, format!(r#"secret = "{}""#, marker("first")))?;
        fs::write(&second, format!(r#"secret = "{}""#, marker("second")))?;

        let manager = SealedFileManager::new(directory.path().to_path_buf())?;
        let files = sealed_files(&[&first, &second]);
        let prepared = manager.prepare(&files, &HashMap::new(), &[], false)?;
        let mut keys = Vec::new();
        manager.apply(&prepared, |secret, document| {
            let SealedSecret::Pgp(allocation) = &secret.inner else {
                panic!("test key is not PGP");
            };
            let SecretAllocation::Gcp { secret, .. } = &allocation.inner else {
                panic!("test key is not a GCP allocation");
            };
            keys.push(secret.clone());
            fake_decrypt(document)
        })?;

        assert_eq!(keys.len(), 2);
        assert_ne!(keys[0], keys[1]);
        manager.restore_all()?;
        Ok(())
    }

    #[test]
    fn files_can_select_different_encryption_algorithms() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let pgp_file = directory.path().join("pgp.conf");
        let password_file = directory.path().join("password.conf");
        fs::write(&pgp_file, format!(r#"secret = "{}""#, marker("pgp")))?;
        fs::write(&password_file, format!(r#"secret = "{}""#, marker("password")))?;

        let mut files = sealed_files(&[&pgp_file]);
        files.insert(password_file.display().to_string(), SealedFile {
            secret: remote_password_secret("password-key"),
        });
        let manager = SealedFileManager::new(directory.path().to_path_buf())?;
        let prepared = manager.prepare(&files, &HashMap::new(), &[], false)?;
        let algorithms: Vec<_> = prepared
            .in_place
            .iter()
            .map(|file| SealedFileManager::secret_allocation(&file.secret).0)
            .collect();

        assert!(algorithms.contains(&SealedAlgorithm::Pgp));
        assert!(algorithms.contains(&SealedAlgorithm::Argon2idXchacha20Poly1305));
        Ok(())
    }

    #[test]
    fn restoration_waits_for_an_active_replacement() -> Result<()> {
        use std::{
            sync::mpsc,
            thread,
        };

        let directory = tempfile::tempdir()?;
        let in_place = directory.path().join("application.conf");
        let original = format!(r#"secret = "{}""#, marker("value"));
        fs::write(&in_place, &original)?;

        let manager = Arc::new(SealedFileManager::new(directory.path().to_path_buf())?);
        let files = sealed_files(&[&in_place]);
        let prepared = manager.prepare(&files, &HashMap::new(), &[], false)?;
        let (started_tx, started_rx) = mpsc::channel();
        let (continue_tx, continue_rx) = mpsc::channel();
        let apply_manager = manager.clone();
        let apply_handle = thread::spawn(move || {
            apply_manager.apply(&prepared, |_secret, document| {
                started_tx.send(()).unwrap();
                continue_rx.recv().unwrap();
                fake_decrypt(document)
            })
        });

        started_rx.recv()?;
        let restorer = manager.restorer();
        let (restored_tx, restored_rx) = mpsc::channel();
        let restore_handle = thread::spawn(move || {
            let result = restorer.restore_all();
            restored_tx.send(()).unwrap();
            result
        });
        assert!(matches!(restored_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));

        continue_tx.send(())?;
        apply_handle.join().unwrap()?;
        restore_handle.join().unwrap()?;
        restored_rx.recv()?;
        assert_eq!(fs::read_to_string(&in_place)?, original);
        Ok(())
    }

    #[test]
    fn does_not_clobber_a_template_output_created_after_validation() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let template = directory.path().join("credentials.json.sealed");
        let output = directory.path().join("credentials.json");
        fs::write(
            &template,
            serde_json::json!({ "token": marker("template") }).to_string(),
        )?;

        let manager = SealedFileManager::new(directory.path().to_path_buf())?;
        let templates = sealed_templates(&[(&output, &template)]);
        let prepared = manager.prepare(&HashMap::new(), &templates, &[], false)?;
        fs::write(&output, "created concurrently")?;

        assert!(manager.apply(&prepared, fake_apply).is_err());
        manager.restore_all()?;
        assert_eq!(fs::read_to_string(&output)?, "created concurrently");
        Ok(())
    }

    #[test]
    fn restoration_prevents_later_secret_file_writes() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let in_place = directory.path().join("application.conf");
        let generated = directory.path().join("generated.txt");
        let original = format!(r#"secret = "{}""#, marker("value"));
        fs::write(&in_place, &original)?;

        let manager = SealedFileManager::new(directory.path().to_path_buf())?;
        let files = sealed_files(&[&in_place]);
        let prepared = manager.prepare(&files, &HashMap::new(), &[], false)?;
        manager.restore_all()?;

        assert!(manager.apply(&prepared, fake_apply).is_err());
        assert!(manager
            .while_active(|| {
                fs::write(&generated, "secret")?;
                Ok(())
            })
            .is_err());
        assert_eq!(fs::read_to_string(&in_place)?, original);
        assert!(!generated.exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_hard_linked_sealed_files() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let in_place = directory.path().join("application.conf");
        let alias = directory.path().join("application-alias.conf");
        fs::write(&in_place, format!(r#"secret = "{}""#, marker("value")))?;
        fs::hard_link(&in_place, &alias)?;

        let manager = SealedFileManager::new(directory.path().to_path_buf())?;
        let files = sealed_files(&[&in_place]);
        let Err(error) = manager.prepare(&files, &HashMap::new(), &[], false) else {
            panic!("hard-linked sealed file was accepted");
        };
        assert!(error.to_string().contains("hard-link aliases"));
        Ok(())
    }
}
