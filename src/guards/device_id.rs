use rocket::{http::Status, request::{FromRequest, Outcome}, Request};

const HEADER: &str = "x-rpc-device_id";
const MISSING_ERROR: &str = "Invalid request, missing 'x-rpc-device_id' header.";

/// Rocket guard which enforces the `x-rpc-device_id` header.
/// 
/// The header is placed in the `0` part of the struct.
pub struct DeviceId(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for DeviceId {
    type Error = &'r str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.headers().get_one(HEADER) {
            Some(device_id) => Outcome::Success(DeviceId(device_id.to_string())),
            None => Outcome::Error((Status::BadRequest, MISSING_ERROR))
        }
    }
}