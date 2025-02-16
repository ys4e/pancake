use std::time::{SystemTime, UNIX_EPOCH};

use bcrypt::{BcryptError, DEFAULT_COST};
use rand::{distr::Alphanumeric, Rng};
use rocket::response::content::RawJson;
use serde::Serialize;
use serde_json::json;

use crate::constants;

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

/// Creates a JSON value for SDK-specific JSON responses.
pub fn message_response(
    code: i16, 
    message: &'static str, 
    data: impl Serialize
) -> RawJson<String> {
    let encoded = serde_json::to_string(&data).unwrap();

    RawJson(serde_json::to_string(
        &json!({
            "retcode": code,
            "message": message,
            "data": encoded
        })
    ).unwrap())
}

/// Generates a random, alphanumeric 32-character token.
pub fn random_token() -> String {
    String::from_utf8(rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .collect()
    ).unwrap()
}

/// Masks a string.
/// 
/// A mask is a string, with the content in the middle being replaced with asterisks.
pub fn mask_string<S: AsRef<str>>(string: S) -> String {
    let string = string.as_ref();
    let len = string.len();

    if len < 4 {
        return "*".repeat(len);
    }

    let start = if len >= 10 { 2 } else { 1 };
    let end = if len > 5 { 2 } else { 1 };
    format!("{}****{}", &string[..start], &string[len - end..])
}

/// Attempts to map an IP address to a country.
/// 
/// If this fails, the default country, ZZ, is used instead.
pub fn ip_to_country(address: String) -> String {
    let reader = maxminddb::Reader::from_source(constants::IP_DB).unwrap();
    match address.parse() {
        Ok(address) => reader.lookup(address).unwrap_or("ZZ".to_string()),
        Err(_) => "ZZ".to_string()
    }
}