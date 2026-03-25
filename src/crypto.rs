use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;

const PBKDF2_ITERATIONS: u32 = 600_000;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// Prompt the user for a password (hidden input), confirm it, return the password.
pub fn prompt_password() -> Result<String> {
    let password =
        rpassword::prompt_password("Enter password for encrypted output: ")
            .context("Failed to read password")?;

    if password.is_empty() {
        anyhow::bail!("Password cannot be empty");
    }

    let confirm =
        rpassword::prompt_password("Confirm password: ")
            .context("Failed to read password confirmation")?;

    if password != confirm {
        anyhow::bail!("Passwords do not match");
    }

    Ok(password)
}

/// Encrypt plaintext with AES-256-GCM using a password-derived key.
/// Output format: [16 bytes salt][12 bytes nonce][ciphertext+tag]
pub fn encrypt_and_write(plaintext: &str, password: &str, path: &Path) -> Result<()> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    // Derive 256-bit key from password using PBKDF2-HMAC-SHA256
    let mut key = [0u8; 32];
    pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), &salt, PBKDF2_ITERATIONS, &mut key);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("Failed to create AES-256-GCM cipher: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    // Write: salt || nonce || ciphertext
    let mut output = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    std::fs::write(path, &output)
        .with_context(|| format!("Failed to write encrypted file: {:?}", path))?;

    Ok(())
}

/// Decrypt a file that was encrypted with `encrypt_and_write`.
pub fn decrypt_file(path: &Path, password: &str) -> Result<String> {
    let data = std::fs::read(path)
        .with_context(|| format!("Failed to read encrypted file: {:?}", path))?;

    if data.len() < SALT_LEN + NONCE_LEN + 16 {
        anyhow::bail!("File too small to be a valid encrypted output");
    }

    let salt = &data[..SALT_LEN];
    let nonce_bytes = &data[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &data[SALT_LEN + NONCE_LEN..];

    let mut key = [0u8; 32];
    pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("Failed to create AES-256-GCM cipher: {}", e))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("Decryption failed — wrong password or corrupted file"))?;

    String::from_utf8(plaintext).context("Decrypted content is not valid UTF-8")
}
