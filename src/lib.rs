#[macro_use] extern crate rocket;

mod db;
mod utils;
mod routes;
mod guards;
mod constants;

use rocket_db_pools::Database;
use crate::db::SDK;

/// A result type for request handlers that returns a message for an error.
pub type MessageResult<R> = Result<R, &'static str>;

/// Health route to check if the server is running.
#[get("/health")]
fn health() -> &'static str {
    "OK"
}

/// Returns the server's favicon.
#[get("/favicon.ico")]
fn favicon() -> &'static [u8] {
    include_bytes!("../resources/assets/favicon.ico")
}

/// Launches the SDK server.
///
/// This should be called from a `tokio` runtime.
pub async fn launch() -> Result<(), rocket::Error> {
    // Create the web app.
    let _rocket = rocket::build()
        .attach(SDK::init())
        .mount("/", routes![health, favicon])
        .mount("/hk4e_global", routes::hk4e::shield::mount())
        .mount("/hk4e_cn", routes::hk4e::shield::mount())
        .mount("/account", routes::account::mount())
        .launch()
        .await?;

    Ok(())
}