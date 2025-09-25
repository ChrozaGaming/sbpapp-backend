use anyhow::Result;
use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rand::rngs::OsRng; // dari crate rand

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    // Map error argon2 -> anyhow secara eksplisit
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    Ok(hash.to_string())
}

pub fn verify_password(password: &str, password_hash: &str) -> Result<bool> {
    // Map error parsing hash -> anyhow
    let parsed = PasswordHash::new(password_hash)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    // verify_password mengembalikan Result<(), _>; is_ok() -> bool
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}
