#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    pancake::launch().await
}