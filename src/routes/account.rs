use rocket::{form::Form, response::Redirect};
use rocket::Route;
use rocket_db_pools::{sqlx, Connection};
use sqlx::Error;
use validator::Validate;
use crate::constants;
use crate::{db::SDK, utils};

/// Mounts all routes.
pub fn mount() -> Vec<Route> {
    routes![
        account_register_page,
        account_register
    ]
}

/// A response type for account-related responses.
#[derive(Responder)]
enum AccountResponse<'a> {
    /// This should be returned when the user provides invalid data.
    #[response(status = 400)]
    BadRequest(&'a str),

    /// This should be returned if an internal server error occurs.
    #[response(status = 500)]
    ServerError(&'a str),

    /// This should be returned when the user is redirected.
    #[response(status = 303)]
    Redirect(Redirect),

    /// This should be returned if the request was handled successfully.
    #[response(status = 200)]
    Successful(&'a str)
}

/// Form data sent by the client when registering an account.
#[derive(Debug, Validate, FromForm)]
struct RegisterForm<'v> {
    #[validate(length(min = 2, max = 64))]
    username: &'v str,

    #[validate(email, length(max = 128))]
    email: &'v str,

    #[validate(length(min = 8, max = 128))]
    passwordv1: &'v str,
    
    /// This is used for confirming the first password.
    passwordv2: &'v str
}

/// Handles sending the account registration HTML to the client.
#[get("/register")]
fn account_register_page() -> &'static str {
    "page"
}

/// Handles registering an account internally.
///
/// See the `RegisterForm` struct for the form data.
#[post("/register?<type>", data = "<form>")]
async fn account_register<'a>(
    mut db: Connection<SDK>,
    r#type: Option<&'_ str>,
    form: Form<RegisterForm<'_>>
) -> AccountResponse<'a> {
    // Check if the user already exists.
    match sqlx::query!(
        "SELECT * from `accounts` where `name` = ? OR `email` = ?",
        form.username, form.email
    ).fetch_one(&mut **db).await {
        Err(Error::RowNotFound) => (),
        Ok(_) => return AccountResponse::BadRequest("An account with that username or email already exists."),
        _ => return AccountResponse::ServerError("An internal server error has occurred.")
    }

    // Validate the user provided data.
    match form.validate() {
        Ok(_) => (),
        Err(_) => return AccountResponse::BadRequest("Invalid account data specified."),
    }

    // Check if the passwords match.
    let password = form.passwordv1.trim();
    if password != form.passwordv2 {
        return AccountResponse::BadRequest("The passwords do not match.");
    }

    // Hash the password for storage in the database.
    let hashed = match utils::hash_password(password) {
        Ok(hash) => hash,
        Err(_) => return AccountResponse::ServerError("An internal server error has occurred.")
    };

    // Insert the user into the database.
    let Ok(_) = sqlx::query!(
        "INSERT INTO `accounts` (`name`, `email`, `password`, `epoch_created`) VALUES (?, ?, ?, ?)",
        form.username, form.email, hashed, utils::current_time()
    ).execute(&mut **db).await else {
        return AccountResponse::ServerError("An internal server error has occurred.");
    };

    // If the type is `sdk`, redirect the user.
    if let Some(r#type) = r#type {
        if r#type == constants::WEBVIEW_REQUEST_TYPE_SDK {
            let params = format!(
                "username={}&password={}", 
                urlencoding::encode(form.username),
                urlencoding::encode(password)
            );

            return AccountResponse::Redirect(Redirect::found(
                format!("uniwebview://{}?{}", constants::WEBVIEW_URL_REGISTER, params)
            ));
        }
    }

    AccountResponse::Successful("Account created. Please close this page and login in the game.")
}