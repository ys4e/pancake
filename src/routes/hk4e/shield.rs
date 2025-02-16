use base64::{prelude::BASE64_STANDARD, Engine};
use rocket::{response::content::RawJson, serde::json::Json, Route};
use rocket_db_pools::Connection;
use rsa::Pkcs1v15Encrypt;
use serde::{Deserialize, Serialize};
use sqlx::{Error, MySqlConnection};

use crate::{constants::{self, AccountState, RSA_PRIVATE_KEY}, db::SDK, guards::{device_id::DeviceId, ip_address::IpAddress}, utils};

/// Mounts all routes.
pub fn mount() -> Vec<Route> {
    routes![
        shield_login,
        shield_verify
    ]
}

/// Checks if the given device needs to be authenticated.
async fn needs_grant(db: &mut MySqlConnection, uid: i32, device_id: &String) -> bool {
    // Check the database for an existing device entry.
    let Ok(result) = sqlx::query!(
        "SELECT * FROM `devices` WHERE `uid` = ? AND `device` = ?",
        uid, device_id
    ).fetch_optional(&mut *db).await else {
        return true;
    };

    // If the device entry exists, then we are good to go.
    if result.is_some() {
        return false;
    }

    // Check if this is the first device grant.
    let Ok(result) = sqlx::query!(
        "SELECT * FROM `devices` WHERE `uid` = ?",
        uid
    ).fetch_all(&mut *db).await else {
        return true;
    };

    !result.is_empty()
}

#[derive(Serialize)]
struct LoginResult {
    account: AccountData,

    /// Does the user need to perform an ID check?
    realperson_required: bool,

    /// Does the device need to pass a multi-factor authentication check?
    device_grant_required: bool,

    /// Does the user need to verify a mobile number?
    safe_mobile_required: bool,

    /// Is the user's account pending deletion?
    reactivate_required: bool,

    /// The state of the identity verification.
    realname_operation: String
}

#[derive(Serialize, Default)]
struct AccountData {
    /// The account's game (hk4e) unique ID.
    uid: i32,

    /// The account's username.
    /// 
    /// This value should be masked.
    name: String,

    /// This value should be masked.
    email: String,

    /// This value should be masked.
    mobile: String,

    /// Whether the account has verified their email.
    is_email_verify: bool,

    /// The real name of the account holder.
    /// 
    /// This value should be masked.
    realname: String,

    /// The 'identity card' of the account holder.
    /// 
    /// This only applies to certain login methods.
    /// 
    /// THis value should be masked.
    identity_card: String,

    /// This value is a token that is used to authenticate the user.
    /// 
    /// It is derived from the user's ID and device ID.
    token: String,

    /// The country of the account holder.
    /// 
    /// This is derived from the requesting IP address.
    /// 
    /// # Default
    /// 
    /// This falls back to `ZZ`.
    country: String,

    /// This value is dictated by whether the device needs multi-factor authentication.
    /// 
    /// This usually comes in the form of a code, and is based on the device ID in the header.
    device_grant_ticket: Option<String>,

    /// This value is used when an account goes through a reactivation process.
    /// 
    /// A reactivation is trigged when the account is disabled or goes vacant.
    reactivate_ticket: Option<String>
}

#[derive(Deserialize)]
struct LoginRequest {
    /// This is the username or email address of the account.
    pub account: String,

    /// This is a (sometimes) encrypted password.
    /// 
    /// The password is encrypted using RSA, and should be decrypted before checking.
    /// 
    /// This becomes a plaintext string.
    pub password: String,

    /// A flag used to dictate whether the password is encrypted.
    pub is_crypto: bool
}

/// A response type for shield-related responses.
#[derive(Responder)]
enum ShieldResponse {
    /// This is returned when an error occurs.
    #[response(status = 200)]
    CodedError(RawJson<String>),

    /// This is returned in all instances of where a `retcode` is provided.
    #[response(status = 200)]
    CodedResponse(RawJson<String>)
}

/// Performs database queries to complete a login request.
async fn do_login(
    db: &mut MySqlConnection,
    device_id: String,
    ip_address: String,
    account: AccountData,
    account_state: i32
) -> ShieldResponse {
    // Check if the account needs to be reactivated.
    let reactivate_ticket = match account_state.try_into().unwrap() {
        AccountState::PendingDelete => {
            // Generate a reactivation ticket.
            let ticket = utils::random_token();
            // Insert the ticket into the database.
            sqlx::query!(
                "INSERT INTO `reactivate_tickets` (`ticket`, `uid`) VALUES (?, ?) ON DUPLICATE KEY UPDATE `ticket` = ?",
                ticket, account.uid, ticket
            ).execute(&mut *db).await.ok();

            Some(ticket)
        },
        _ => None
    };

    // Check if the device needs a grant.
    let grant_ticket = {
        if needs_grant(&mut *db, account.uid, &device_id).await {
            // Generate a grant ticket.
            let ticket = utils::random_token();
            // Insert the ticket into the database.
            sqlx::query!(
                "INSERT INTO `grant_tickets` (`ticket`, `uid`) VALUES (?, ?) ON DUPLICATE KEY UPDATE `ticket` = ?",
                ticket, account.uid, ticket
            ).execute(&mut *db).await.ok();

            Some(ticket)
        } else {
            // Add the device to the database.
            let current_time = utils::current_time();
            sqlx::query!(
                "INSERT INTO `devices` (`uid`, `device`, `epoch_lastseen`) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE `epoch_lastseen` = ?",
                account.uid, device_id, current_time, current_time
            ).execute(&mut *db).await.ok();

            None
        }
    };

    // Generate the login token.
    let token = {
        // Check if an existing token is present.
        let result = match sqlx::query!(
            "SELECT * FROM `login_tokens` WHERE `uid` = ? AND `device` = ?",
            account.uid, device_id
        ).fetch_optional(&mut *db).await {
            Ok(Some(entry)) => Some(entry),
            _ => None
        };

        match result {
            Some(entry) => entry.token,
            None => {
                // Generate a new token.
                let token = utils::random_token();
                // Insert the token into the database.
                sqlx::query!(
                    "INSERT INTO `login_tokens` (`uid`, `device`, `token`) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE `token` = ?",
                    account.uid, device_id, token, token
                ).execute(&mut *db).await.ok();

                token
            }
        }
    };
    
    // Determine the country code.
    let country = utils::ip_to_country(ip_address);

    let login_data = LoginResult {
        account: AccountData {
            token, country,
            device_grant_ticket: match grant_ticket {
                Some(ref ticket) => Some(ticket.clone()),
                None => None
            },
            reactivate_ticket: match reactivate_ticket {
                Some(ref ticket) => Some(ticket.clone()),
                None => None
            },
            ..account
        },
        realperson_required: false,
        device_grant_required: grant_ticket.is_some(),
        safe_mobile_required: false,
        reactivate_required: reactivate_ticket.is_some(),
        realname_operation: constants::REALNAME_OP_NONE.to_string()
    };

    ShieldResponse::CodedResponse(utils::message_response(constants::RESPONSE_SUCCESS, constants::MESSAGE_SUCCESS, login_data))
}

/// Handles a full login request from the user.
#[post("/mdk/shield/api/login", data = "<body>")]
async fn shield_login(
    mut db: Connection<SDK>,
    body: Json<LoginRequest>, 
    device_id: DeviceId,
    ip_address: IpAddress
) -> ShieldResponse {
    // Fetch the account data from the database.
    let Ok(account) = sqlx::query!(
        "SELECT * FROM `accounts` WHERE `name` = ? OR `email` = ?",
        body.account, body.account
    ).fetch_one(&mut **db).await else {
        return ShieldResponse::CodedError(utils::system_error());
    };

    // Check the account's satte.
    if account.state != AccountState::Active || account.state != AccountState::PendingDelete {
        return ShieldResponse::CodedError(
            utils::message_response(constants::RESPONSE_LOGIN_FAILED, constants::MESSAGE_INVALID_CREDS, ())
        );
    }

    // Verify the password of the account.
    let Ok(password) = BASE64_STANDARD.decode(&body.password) else {
        return ShieldResponse::CodedError(utils::system_error());
    };
    let password = if body.is_crypto {
        match RSA_PRIVATE_KEY.decrypt(
            Pkcs1v15Encrypt, &password
        ) {
            Ok(password) => password,
            _ => return ShieldResponse::CodedError(utils::system_error())
        }
    } else {
        password
    };
    let password = String::from_utf8(password).unwrap_or_default();
    
    if let Some(hashed_password) = account.password {
        // This will only verify the password if one is set.
        if !utils::verify_password(&password, &hashed_password) {
            return ShieldResponse::CodedError(
                utils::message_response(constants::RESPONSE_LOGIN_FAILED, constants::MESSAGE_INVALID_CREDS, ())
            );
        }
    }

    // Prepare initial account data.
    let account_data = AccountData {
        uid: account.uid,
        name: utils::mask_string(&account.name.unwrap_or_default()),
        email: utils::mask_string(&account.email.unwrap_or_default()),
        mobile: utils::mask_string(&account.mobile.unwrap_or_default()),
        is_email_verify: false,
        ..Default::default()
    };
    do_login(&mut **db, device_id.0, ip_address.0, account_data, account.state).await
}

#[derive(Deserialize)]
struct VerifyRequest {
    /// The account's unique ID.
    uid: u32,

    /// The login token given in `shield_login`.
    token: String
}

/// Verifies a user's identity, given a token and device ID.
#[post("/mdk/shield/api/verify", data = "<body>")]
async fn shield_verify(
    mut db: Connection<SDK>,
    body: Json<VerifyRequest>,
    device_id: DeviceId,
    ip_address: IpAddress
) -> ShieldResponse {
    // Check if the login token exists.
    let result = match sqlx::query!(
        "SELECT * FROM `login_tokens` WHERE `uid` = ? AND `token` = ? AND `device` = ?",
        body.uid, body.token, device_id.0
    ).fetch_one(&mut **db).await {
        Ok(result) => result,
        Err(Error::RowNotFound) => return ShieldResponse::CodedResponse(
            utils::message_response(constants::RESPONSE_LOGIN_FAILED, constants::MESSAGE_BAD_TOKEN, ())
        ),
        Err(_) => return ShieldResponse::CodedResponse(utils::system_error())
    };

    // Get the account associated with the token.
    let account = match sqlx::query!(
        "SELECT * FROM `accounts` WHERE `uid` = ?",
        result.uid
    ).fetch_one(&mut **db).await {
        Ok(account) => account,
        _ => return ShieldResponse::CodedResponse(utils::system_error())
    };

    // Check the account state.
    if account.state != AccountState::Active {
        return ShieldResponse::CodedResponse(
            utils::message_response(constants::RESPONSE_LOGIN_FAILED, constants::MESSAGE_BAD_TOKEN, ())
        );
    }

    // Compare the device ID to the stored one.
    if result.device != device_id.0 {
        return ShieldResponse::CodedResponse(
            utils::message_response(constants::RESPONSE_LOGIN_FAILED, constants::MESSAGE_NEW_DEVICE, ())
        );
    }

    // Prepare the account data.
    let account_data = AccountData {
        uid: account.uid,
        name: utils::mask_string(&account.name.unwrap_or_default()),
        email: utils::mask_string(&account.email.unwrap_or_default()),
        mobile: utils::mask_string(&account.mobile.unwrap_or_default()),
        is_email_verify: false,
        ..Default::default()
    };
    do_login(&mut **db, device_id.0, ip_address.0, account_data, account.state).await
}