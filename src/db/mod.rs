use rocket_db_pools::{sqlx, Database};

/// SDK server database connection pool.
///
/// This hooks to the MySQL database: `sdk`.
#[derive(Database)]
#[database("sdk")]
pub struct SDK(sqlx::MySqlPool);