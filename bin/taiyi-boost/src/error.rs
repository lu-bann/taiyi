use axum::{http::StatusCode, response::IntoResponse};

#[derive(Debug)]
#[allow(unused)]
/// Errors that the PbsService returns to client
pub enum PbsClientError {
    NoResponse,
    NoPayload,
    BadRequest,
}

impl PbsClientError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::NoResponse => StatusCode::SERVICE_UNAVAILABLE,
            Self::NoPayload => StatusCode::BAD_GATEWAY,
            Self::BadRequest => StatusCode::BAD_REQUEST,
        }
    }
}

impl IntoResponse for PbsClientError {
    fn into_response(self) -> axum::response::Response {
        let msg = match self {
            Self::NoResponse => "no response from relays",
            Self::NoPayload => "no payload from relays",
            Self::BadRequest => "bad request",
        };

        (self.status_code(), msg).into_response()
    }
}
