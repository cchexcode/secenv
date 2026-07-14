use {
    anyhow::Result,
    argon2::{
        Algorithm,
        Argon2,
        Block,
        Params,
        Version,
    },
    chacha20poly1305::{
        aead::{
            Aead,
            KeyInit,
            Payload,
        },
        Key,
        XChaCha20Poly1305,
        XNonce,
    },
    rand::{
        rngs::OsRng,
        RngCore,
    },
    zeroize::{
        Zeroize,
        Zeroizing,
    },
};

const FORMAT_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const MEMORY_KIB: u32 = 19 * 1024;
const ITERATIONS: u32 = 2;
const PARALLELISM: u32 = 1;
const AAD: &[u8] = b"secenv:argon2id-xchacha20-poly1305:v1";

pub(crate) struct PasswordCipher;

impl PasswordCipher {
    pub(crate) fn encrypt(passphrase: &str, plaintext: &str) -> Result<Vec<u8>> {
        Self::validate_passphrase(passphrase)?;

        let mut salt = [0_u8; SALT_LEN];
        let mut nonce = [0_u8; NONCE_LEN];
        OsRng
            .try_fill_bytes(&mut salt)
            .map_err(|error| anyhow::anyhow!("Failed to generate encryption salt: {}", error))?;
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|error| anyhow::anyhow!("Failed to generate encryption nonce: {}", error))?;

        let key = Self::derive_key(passphrase, &salt)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), Payload {
                msg: plaintext.as_bytes(),
                aad: AAD,
            })
            .map_err(|_| anyhow::anyhow!("Failed to encrypt value with Argon2id/XChaCha20-Poly1305"));
        let ciphertext = ciphertext?;

        let mut payload = Vec::with_capacity(1 + SALT_LEN + NONCE_LEN + ciphertext.len());
        payload.push(FORMAT_VERSION);
        payload.extend_from_slice(&salt);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&ciphertext);
        Ok(payload)
    }

    pub(crate) fn decrypt(passphrase: &str, payload: &[u8]) -> Result<String> {
        Self::validate_passphrase(passphrase)?;
        let minimum_len = 1 + SALT_LEN + NONCE_LEN + TAG_LEN;
        if payload.len() < minimum_len {
            anyhow::bail!("Argon2id/XChaCha20-Poly1305 payload is truncated");
        }
        if payload[0] != FORMAT_VERSION {
            anyhow::bail!("Unsupported Argon2id/XChaCha20-Poly1305 payload version");
        }

        let salt_start = 1;
        let nonce_start = salt_start + SALT_LEN;
        let ciphertext_start = nonce_start + NONCE_LEN;
        let salt = &payload[salt_start..nonce_start];
        let nonce = &payload[nonce_start..ciphertext_start];
        let ciphertext = &payload[ciphertext_start..];

        let key = Self::derive_key(passphrase, salt)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
        let plaintext = cipher
            .decrypt(XNonce::from_slice(nonce), Payload {
                msg: ciphertext,
                aad: AAD,
            })
            .map_err(|_| anyhow::anyhow!("Failed to decrypt Argon2id/XChaCha20-Poly1305 value"));
        let plaintext = plaintext?;

        match String::from_utf8(plaintext) {
            | Ok(plaintext) => Ok(plaintext),
            | Err(error) => {
                let mut plaintext = error.into_bytes();
                plaintext.zeroize();
                anyhow::bail!("Decrypted Argon2id/XChaCha20-Poly1305 value is not valid UTF-8");
            },
        }
    }

    fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, Some(KEY_LEN))
            .map_err(|error| anyhow::anyhow!("Invalid Argon2id parameters: {}", error))?;
        let mut memory = Zeroizing::new(vec![Block::default(); params.block_count()]);
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = Zeroizing::new([0_u8; KEY_LEN]);
        let result = argon2.hash_password_into_with_memory(passphrase.as_bytes(), salt, &mut key[..], &mut memory);
        result.map_err(|error| anyhow::anyhow!("Failed to derive Argon2id key: {}", error))?;
        Ok(key)
    }

    fn validate_passphrase(passphrase: &str) -> Result<()> {
        if passphrase.is_empty() {
            anyhow::bail!("Argon2id passphrase must not be empty");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_uses_random_salt_and_nonce() -> Result<()> {
        let first = PasswordCipher::encrypt("correct horse battery staple", "sealed value")?;
        let second = PasswordCipher::encrypt("correct horse battery staple", "sealed value")?;

        assert_ne!(first, second);
        assert_eq!(
            PasswordCipher::decrypt("correct horse battery staple", &first)?,
            "sealed value"
        );
        Ok(())
    }

    #[test]
    fn rejects_wrong_passphrase_tampering_and_invalid_format() -> Result<()> {
        let payload = PasswordCipher::encrypt("correct password", "sealed value")?;
        assert!(PasswordCipher::decrypt("wrong password", &payload).is_err());

        let mut tampered = payload.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(PasswordCipher::decrypt("correct password", &tampered).is_err());
        assert!(PasswordCipher::decrypt("correct password", &[FORMAT_VERSION]).is_err());

        let mut unsupported = payload;
        unsupported[0] = FORMAT_VERSION + 1;
        assert!(PasswordCipher::decrypt("correct password", &unsupported).is_err());
        Ok(())
    }
}
