use rocket::{request::{FromRequest, Outcome}, Request};

const PROXY_HEADER: &str = "X-Real-IP";
const CF_HEADER: &str = "CF-Connecting-IP";
const NO_IP_ADDRESS: &str = "Invalid request, missing client IP address.";

/// Rocket guard which fetches the client's IP address.
/// 
/// The IP address is placed in the `0` part of the struct.
pub struct IpAddress(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for IpAddress {
    type Error = &'r str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        // Check for the CloudFlare header.
        if let Some(ip) = request.headers().get_one(CF_HEADER) {
            return Outcome::Success(IpAddress(ip.to_string()));
        }

        // Check for the proxy header.
        if let Some(ip) = request.headers().get_one(PROXY_HEADER) {
            return Outcome::Success(IpAddress(ip.to_string()));
        }

        // Get the client's IP address.
        match request.client_ip() {
            Some(ip) => Outcome::Success(IpAddress(ip.to_string())),
            None => Outcome::Error((rocket::http::Status::BadRequest, NO_IP_ADDRESS))
        }
    }
}