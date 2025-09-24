use {
    anyhow::{Context, Result},
    std::io::{Read},
};

use sequoia_openpgp as openpgp;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::parse::stream::{DecryptorBuilder, DecryptionHelper, MessageStructure, VerificationHelper};
use openpgp::packet::{PKESK, SKESK};
use openpgp::KeyHandle;
use openpgp::types::SymmetricAlgorithm;

pub struct PgpManager;

impl PgpManager {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

    pub fn decrypt(&self, _key_fingerprint: &str, _encrypted_data: &str) -> Result<String> {
        Err(anyhow::anyhow!(
            "Decryption using a key fingerprint is not supported without an explicit private key. Provide a private key (e.g., via !gcp) and use decrypt_with_private_key."
        ))
    }

    pub fn decrypt_with_private_key(&self, private_key_asc: &str, encrypted_data: &str) -> Result<String> {
        // Parse the provided ASCII-armored private key as an OpenPGP certificate
        let cert = openpgp::Cert::from_bytes(private_key_asc.as_bytes())
            .context("Failed to parse PGP private key")?;

        // Decrypt using Sequoia's streaming API
        let policy = StandardPolicy::new();
        let helper = InMemoryHelper { cert };
        let mut decryptor = DecryptorBuilder::from_bytes(encrypted_data.as_bytes())
            .context("Failed to parse encrypted PGP message")?
            .with_policy(&policy, None, helper)
            .context("Failed to initialize PGP decryptor")?;

        let mut plaintext = Vec::new();
        decryptor
            .read_to_end(&mut plaintext)
            .context("Failed reading decrypted plaintext")?;

        let decrypted_data = String::from_utf8(plaintext)
            .context("Decrypted data is not valid UTF-8")?;
        Ok(decrypted_data)
    }
}

struct InMemoryHelper {
    cert: openpgp::Cert,
}

impl VerificationHelper for InMemoryHelper {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        Ok(())
    }
}

impl DecryptionHelper for InMemoryHelper {
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn for<'a> FnMut(Option<SymmetricAlgorithm>, &'a openpgp::crypto::SessionKey) -> bool,
    ) -> openpgp::Result<Option<openpgp::Cert>> {
        let policy = StandardPolicy::new();

        for secret in self
            .cert
            .keys()
            .secret()
            .with_policy(&policy, None)
            .alive()
            .revoked(false)
            .for_transport_encryption()
        {
            if let Ok(mut keypair) = secret.key().clone().into_keypair() {
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

