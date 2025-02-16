use lazy_static::lazy_static;
use rsa::{RsaPrivateKey, pkcs1::DecodeRsaPrivateKey};

/// The MaxMind database which stores information mapping IPs to countries.
pub const IP_DB: &[u8] = include_bytes!("../resources/GeoLite2-Country.mmdb");
/// The RSA private key used in Grasscutter.
const PRIVATE_KEY: &str = include_str!("../resources/private-key.pem");

lazy_static! {
    /// The private key used for decrypting client-encrypted data.
    pub static ref RSA_PRIVATE_KEY: RsaPrivateKey = RsaPrivateKey::from_pkcs1_pem(PRIVATE_KEY).unwrap();
}

/// Used in the account registration handler.
pub const WEBVIEW_REQUEST_TYPE_SDK: &str = "sdk";
/// Used in the account registration handler.
pub const WEBVIEW_URL_REGISTER: &str = "register";
/// Used in account login responses.
pub const REALNAME_OP_NONE: &str = "None";

pub const RESPONSE_SUCCESS: i16 = 0;
pub const RESPONSE_FAILURE: i16 = -1;
pub const RESPONSE_LOGIN_FAILED: i16 = -101;

/// This is the default message used in conjunction with `RESPONSE_SUCCESS`.
pub const MESSAGE_SUCCESS: &str = "OK";
/// Used whenever the user provides an invalid or bad token.
pub const MESSAGE_BAD_TOKEN: &str = "Game account cache information error.";
/// Used whenever the stored token's device ID does not match the given device ID.
pub const MESSAGE_NEW_DEVICE: &str = "For your security, please login again.";
/// Used whenever the user's password or username doesn't match.
pub const MESSAGE_INVALID_CREDS: &str = "Incorrect username or password.";

/// Represents the account state.
#[derive(Clone, Copy)]
pub enum AccountState {
    Deleted = 0,
    Active = 1,
    PendingDelete = 2,
    LegalHold = 3
}

impl TryFrom<i32> for AccountState {
    type Error = ();

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AccountState::Deleted),
            1 => Ok(AccountState::Active),
            2 => Ok(AccountState::PendingDelete),
            3 => Ok(AccountState::LegalHold),
            _ => Err(())
        }
    }
}

impl PartialEq<i32> for AccountState {
    fn eq(&self, other: &i32) -> bool {
        *self as i32 == *other
    }
}

impl PartialEq<AccountState> for i32 {
    fn eq(&self, other: &AccountState) -> bool {
        *self == *other as i32
    }
}