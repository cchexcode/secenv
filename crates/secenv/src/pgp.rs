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
        serialize::stream::{
            Encryptor,
            LiteralWriter,
            Message,
        },
        types::SymmetricAlgorithm,
        KeyHandle,
    },
    sequoia_openpgp::{
        self as openpgp,
    },
    std::{
        collections::HashMap,
        io::{
            Read,
            Write,
        },
    },
    zeroize::{
        Zeroize,
        Zeroizing,
    },
};

#[derive(Clone)]
struct KeyCredentials {
    cert: openpgp::Cert,
    password: Option<Zeroizing<String>>,
}

#[derive(Default)]
pub(crate) struct PgpManager {
    cache: HashMap<String, KeyCredentials>,
}

impl PgpManager {
    fn policy() -> Box<dyn Policy+Send+Sync> {
        Box::new(StandardPolicy::new())
    }

    fn key_credentials(&self, private_key_asc: &str) -> Result<(String, KeyCredentials)> {
        let cert = openpgp::Cert::from_bytes(private_key_asc.as_bytes()).context("Failed to parse PGP private key")?;
        let fingerprint = cert.fingerprint().to_hex();

        if let Some(cached_key) = self.cache.get(&fingerprint) {
            return Ok((fingerprint, cached_key.clone()));
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
            Some(Zeroizing::new(pwd))
        } else {
            None
        };

        Ok((fingerprint, KeyCredentials {
            cert: unlocked_cert,
            password,
        }))
    }

    pub(crate) fn decrypt(&mut self, private_key_asc: &str, encrypted_data: &str) -> Result<String> {
        self.decrypt_bytes(private_key_asc, encrypted_data.as_bytes())
    }

    pub(crate) fn encrypt(&self, certificate: &str, plaintext: &str) -> Result<Vec<u8>> {
        let cert = openpgp::Cert::from_bytes(certificate.as_bytes()).context("Failed to parse PGP certificate")?;
        let policy = Self::policy();
        let mut recipients: Vec<_> = cert
            .keys()
            .with_policy(&*policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_storage_encryption()
            .collect();
        if recipients.is_empty() {
            recipients = cert
                .keys()
                .with_policy(&*policy, None)
                .supported()
                .alive()
                .revoked(false)
                .for_transport_encryption()
                .collect();
        }
        if recipients.is_empty() {
            anyhow::bail!("PGP certificate has no supported, active encryption key");
        }
        let mut ciphertext = Vec::new();
        let message = Message::new(&mut ciphertext);
        let message = Encryptor::for_recipients(message, recipients)
            .build()
            .context("Failed to initialize PGP encryptor")?;
        let mut message = LiteralWriter::new(message)
            .build()
            .context("Failed to initialize PGP literal writer")?;
        message
            .write_all(plaintext.as_bytes())
            .context("Failed to encrypt plaintext")?;
        message.finalize().context("Failed to finalize PGP message")?;
        Ok(ciphertext)
    }

    pub(crate) fn decrypt_bytes(&mut self, private_key_asc: &str, encrypted_data: &[u8]) -> Result<String> {
        let (fingerprint, credentials) = self.key_credentials(private_key_asc)?;

        let policy = Self::policy();
        let helper = KeyCredentialsHelper {
            cert: credentials.cert.clone(),
            password: credentials.password.clone(),
        };

        let mut decryptor = DecryptorBuilder::from_bytes(encrypted_data)
            .context("Failed to parse encrypted PGP message")?
            .with_policy(&*policy, None, helper)
            .context("Failed to initialize PGP decryptor")?;

        let mut plaintext = Vec::new();
        if let Err(error) = decryptor.read_to_end(&mut plaintext) {
            plaintext.zeroize();
            return Err(error).context("Failed reading decrypted plaintext");
        }

        let plaintext = match String::from_utf8(plaintext) {
            | Ok(decrypted_data) => decrypted_data,
            | Err(error) => {
                let mut plaintext = error.into_bytes();
                plaintext.zeroize();
                anyhow::bail!("Decrypted data is not valid UTF-8");
            },
        };
        self.cache.insert(fingerprint, credentials);
        Ok(plaintext)
    }

    /// Clear the PGP key cache, zeroizing cached passwords
    pub(crate) fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

impl Drop for PgpManager {
    fn drop(&mut self) {
        self.clear_cache();
    }
}

struct KeyCredentialsHelper {
    cert: openpgp::Cert,
    password: Option<Zeroizing<String>>,
}

impl VerificationHelper for KeyCredentialsHelper {
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
        Err(anyhow::anyhow!("Message was not encrypted"))
    }
}

impl DecryptionHelper for KeyCredentialsHelper {
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

#[cfg(test)]
mod tests {
    use {
        super::*,
        openpgp::{
            cert::prelude::CertBuilder,
            serialize::SerializeInto,
        },
    };

    #[test]
    fn encrypts_with_public_certificate_and_decrypts_with_private_key() -> Result<()> {
        let (cert, _) = CertBuilder::new()
            .add_userid("secenv test")
            .add_storage_encryption_subkey()
            .generate()?;
        let public_cert = String::from_utf8(cert.armored().to_vec()?)?;
        let private_key = String::from_utf8(cert.as_tsk().armored().to_vec()?)?;
        let mut manager = PgpManager::default();

        let ciphertext = manager.encrypt(&public_cert, "sealed value")?;
        assert_eq!(manager.decrypt_bytes(&private_key, &ciphertext)?, "sealed value");
        Ok(())
    }
}
