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
    zeroize::Zeroize,
};

// Cache entry for PGP keys
#[derive(Clone)]
struct CachedKey {
    cert: openpgp::Cert,
    password: Option<String>,
}

impl Drop for CachedKey {
    fn drop(&mut self) {
        if let Some(ref mut pwd) = self.password {
            pwd.zeroize();
        }
    }
}

#[derive(Clone)]
pub struct UnlockedKey {
    pub cert: openpgp::Cert,
    #[allow(dead_code)]
    pub fingerprint: String,
    pub password: Option<String>,
}

impl Drop for UnlockedKey {
    fn drop(&mut self) {
        if let Some(ref mut pwd) = self.password {
            pwd.zeroize();
        }
    }
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
        let cert = openpgp::Cert::from_bytes(private_key_asc.as_bytes()).context("Failed to parse PGP private key")?;

        let fingerprint = Self::get_fingerprint(&cert)?;

        if let Some(cached_key) = self.cache.get(&fingerprint) {
            return Ok(UnlockedKey {
                cert: cached_key.cert.clone(),
                fingerprint,
                password: cached_key.password.clone(),
            });
        }

        let policy = Self::policy();
        let unlocked_cert = cert.clone();
        let mut needs_password = false;

        for key in cert.keys().secret().with_policy(&*policy, None) {
            if key.key().secret().is_encrypted() {
                needs_password = true;
                break;
            }
        }

        let password = if needs_password {
            let pwd = rpassword::prompt_password(format!("Enter password for PGP key {}: ", &fingerprint[..16]))
                .context("Failed to read password")?;
            Some(pwd)
        } else {
            None
        };

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
        let unlocked_key = self.unlock_key(private_key_asc)?;

        let policy = Self::policy();
        let helper = CachedKeyHelper {
            cert: unlocked_key.cert.clone(),
            password: unlocked_key.password.clone(),
        };

        let mut decryptor = DecryptorBuilder::from_bytes(encrypted_data.as_bytes())
            .context("Failed to parse encrypted PGP message")?
            .with_policy(&*policy, None, helper)
            .context("Failed to initialize PGP decryptor")?;

        let mut plaintext = Vec::new();
        decryptor
            .read_to_end(&mut plaintext)
            .context("Failed reading decrypted plaintext")?;

        let decrypted_data = String::from_utf8(plaintext.clone()).context("Decrypted data is not valid UTF-8")?;

        // Zeroize the raw bytes buffer
        plaintext.zeroize();

        Ok(decrypted_data)
    }

    /// Clear the PGP key cache, zeroizing cached passwords
    pub fn clear_cache(&mut self) {
        // Dropping CachedKey entries triggers zeroize via the Drop impl
        self.cache.clear();
    }

    /// Get cache statistics for debugging
    #[allow(dead_code)]
    pub fn cache_stats(&self) -> usize {
        self.cache.len()
    }
}

impl Drop for PgpManager {
    fn drop(&mut self) {
        self.clear_cache();
    }
}

struct CachedKeyHelper {
    cert: openpgp::Cert,
    password: Option<String>,
}

impl Drop for CachedKeyHelper {
    fn drop(&mut self) {
        if let Some(ref mut pwd) = self.password {
            pwd.zeroize();
        }
    }
}

impl VerificationHelper for CachedKeyHelper {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        // Note: secenv provides confidentiality (encryption) but does not verify
        // message signatures. If signature verification is needed, provide signing
        // certificates via get_certs() and validate the MessageStructure here.
        //
        // We still check that the message was successfully decrypted by verifying
        // the structure contains at least one encryption layer.
        for layer in structure {
            match layer {
                | openpgp::parse::stream::MessageLayer::Encryption { .. } => return Ok(()),
                | openpgp::parse::stream::MessageLayer::Compression { .. } => continue,
                | _ => continue,
            }
        }
        Err(anyhow::anyhow!("Message was not encrypted").into())
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
            let keypair_result = if secret.key().secret().is_encrypted() {
                if let Some(ref password) = self.password {
                    let result = secret.key().clone().parts_into_secret().and_then(|secret_key| {
                        let decrypted_key =
                            secret_key.decrypt_secret(&openpgp::crypto::Password::from(password.as_str()))?;
                        decrypted_key.into_keypair()
                    });

                    result
                } else {
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
