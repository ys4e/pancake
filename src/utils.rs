use std::time::{SystemTime, UNIX_EPOCH};

use bcrypt::{BcryptError, DEFAULT_COST};

/// Uses BCrypt standard to hash the password.
pub fn hash_password<'a>(plain_text: &'a str) -> Result<String, BcryptError> {
    bcrypt::hash(plain_text, DEFAULT_COST)
}

/// Verifies the BCrypt hash against the plain text password.
/// 
/// If this errors at any point, `false` will always be returned.
pub fn verify_password<'a>(plain_text: &'a str, hashed: &String) -> bool {
    bcrypt::verify(plain_text, hashed).unwrap_or(false)
}

/// Returns the current UNIX timestamp in seconds.
pub fn current_time() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs() as u32
}