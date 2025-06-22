mod get_header;
mod register_validator;
mod reload;
mod router;
mod status;
mod submit_block;

use get_header::handle_get_header;
use register_validator::handle_register_validator;
pub use router::create_app_router;
use status::handle_get_status;
use submit_block::handle_submit_block;

use axum::{http::StatusCode, response::IntoResponse};

#[derive(Debug)]
/// Errors that the PbsService returns to client
pub enum PbsClientError {
    NoResponse,
    NoPayload,
    Internal,
}

impl PbsClientError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            PbsClientError::NoResponse => StatusCode::BAD_GATEWAY,
            PbsClientError::NoPayload => StatusCode::BAD_GATEWAY,
            PbsClientError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for PbsClientError {
    fn into_response(self) -> axum::response::Response {
        let msg = match &self {
            PbsClientError::NoResponse => "no response from relays".to_string(),
            PbsClientError::NoPayload => "no payload from relays".to_string(),
            PbsClientError::Internal => "internal server error".to_string(),
        };

        (self.status_code(), msg).into_response()
    }
}
