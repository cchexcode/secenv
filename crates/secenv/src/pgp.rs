use {
    anyhow::{
        Context,
        Result,
    },
    openpgp::{
        packet::{
            PKESK,
            SKESK,
        },
        parse::{
            stream::{
                DecryptionHelper,
                DecryptorBuilder,
                MessageStructure,
                VerificationHelper,
            },
            Parse,
        },
        policy::{
            Policy,
            StandardPolicy,
        },
        types::SymmetricAlgorithm,
        KeyHandle,
    },
    sequoia_openpgp::{
        self as openpgp,
    },
    std::{
        collections::HashMap,
        io::Read,
    },
};

// Cache entry for PGP keys
#[derive(Clone)]
struct CachedKey {
    cert: openpgp::Cert,
    password: Option<String>,
}

#[derive(Clone)]
pub struct UnlockedKey {
    pub cert: openpgp::Cert,
    #[allow(dead_code)]
    pub fingerprint: String,
    pub password: Option<String>,
}

pub struct PgpManager {
    cache: HashMap<String, CachedKey>,
}

impl PgpManager {
    pub fn new() -> Result<Self> {
        Ok(Self { cache: HashMap::new() })
    }

    fn policy() -> Box<dyn Policy+Send+Sync> {
        Box::new(StandardPolicy::new())
    }

    /// Extract the primary key fingerprint from a certificate
    fn get_fingerprint(cert: &openpgp::Cert) -> Result<String> {
        let fingerprint = cert.fingerprint().to_hex();
        Ok(fingerprint)
    }

    /// Unlock a PGP private key with password prompting if needed
    fn unlock_key(&mut self, private_key_asc: &str) -> Result<UnlockedKey> {
        // Parse the certificate first
        let cert = openpgp::Cert::from_bytes(private_key_asc.as_bytes()).context("Failed to parse PGP private key")?;

        let fingerprint = Self::get_fingerprint(&cert)?;

        // Check if we already have this key unlocked in cache
        if let Some(cached_key) = self.cache.get(&fingerprint) {
            return Ok(UnlockedKey {
                cert: cached_key.cert.clone(),
                fingerprint,
                password: cached_key.password.clone(),
            });
        }

        // Try to unlock the key
        let policy = Self::policy();
        let unlocked_cert = cert.clone();
        let mut needs_password = false;

        // Check if any secret keys are encrypted
        for key in cert.keys().secret().with_policy(&*policy, None) {
            if key.key().secret().is_encrypted() {
                needs_password = true;
                break;
            }
        }

        let password = if needs_password {
            // Prompt for password
            let pwd = rpassword::prompt_password(format!("Enter password for PGP key {}: ", &fingerprint[..16]))
                .context("Failed to read password")?;
            Some(pwd)
        } else {
            None
        };

        // Cache the key info
        self.cache.insert(fingerprint.clone(), CachedKey {
            cert: unlocked_cert.clone(),
            password: password.clone(),
        });

        Ok(UnlockedKey {
            cert: unlocked_cert,
            fingerprint,
            password,
        })
    }

    pub fn decrypt(&mut self, private_key_asc: &str, encrypted_data: &str) -> Result<String> {
        // Unlock the key (with caching and password prompting if needed)
        let unlocked_key = self.unlock_key(private_key_asc)?;

        // Decrypt using Sequoia's streaming API
        let policy = Self::policy();
        let helper = CachedKeyHelper {
            cert: unlocked_key.cert,
            password: unlocked_key.password,
        };

        let mut decryptor = DecryptorBuilder::from_bytes(encrypted_data.as_bytes())
            .context("Failed to parse encrypted PGP message")?
            .with_policy(&*policy, None, helper)
            .context("Failed to initialize PGP decryptor")?;

        let mut plaintext = Vec::new();
        decryptor
            .read_to_end(&mut plaintext)
            .context("Failed reading decrypted plaintext")?;

        let decrypted_data = String::from_utf8(plaintext).context("Decrypted data is not valid UTF-8")?;
        Ok(decrypted_data)
    }

    /// Clear the PGP key cache (useful for security or testing)
    #[allow(dead_code)]
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Get cache statistics for debugging
    #[allow(dead_code)]
    pub fn cache_stats(&self) -> usize {
        self.cache.len()
    }
}

struct CachedKeyHelper {
    cert: openpgp::Cert,
    password: Option<String>,
}

impl VerificationHelper for CachedKeyHelper {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        Ok(())
    }
}

impl DecryptionHelper for CachedKeyHelper {
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn for<'a> FnMut(Option<SymmetricAlgorithm>, &'a openpgp::crypto::SessionKey) -> bool,
    ) -> openpgp::Result<Option<openpgp::Cert>> {
        let policy = PgpManager::policy();
        for secret in self
            .cert
            .keys()
            .secret()
            .with_policy(&*policy, None)
            .alive()
            .revoked(false)
        {
            // Try to create a keypair using the improved parsing approach
            let keypair_result = if secret.key().secret().is_encrypted() {
                if let Some(ref password) = self.password {
                    // Use parts_into_secret() and decrypt_secret() for better compatibility
                    let result = secret.key().clone().parts_into_secret().and_then(|secret_key| {
                        let decrypted_key =
                            secret_key.decrypt_secret(&openpgp::crypto::Password::from(password.as_str()))?;
                        decrypted_key.into_keypair()
                    });

                    result
                } else {
                    // No password available for encrypted key
                    continue;
                }
            } else {
                secret
                    .key()
                    .clone()
                    .parts_into_secret()
                    .and_then(|secret_key| secret_key.into_keypair())
            };

            if let Ok(mut keypair) = keypair_result {
                for pkesk in pkesks {
                    if let Some((algo, session_key)) = pkesk.decrypt(&mut keypair, sym_algo) {
                        if decrypt(algo, &session_key) {
                            return Ok(Some(self.cert.clone()));
                        }
                    }
                }
            }
        }

        Ok(None)
    }
}
