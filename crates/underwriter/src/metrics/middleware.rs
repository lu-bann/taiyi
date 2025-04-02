use axum::{
    body::{to_bytes, Body},
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

use super::models::APIMetrics;

const MAX_PAYLOAD_LENGTH: usize = 1024 * 1024 * 10;

pub async fn metrics_middleware(req: Request, next: Next) -> Response {
    let endpoint = req.uri().path();
    let endpoint = endpoint.to_string();
    APIMetrics::count(&endpoint);
    let _timer = APIMetrics::timer(&endpoint);

    let (req_parts, req_body) = req.into_parts();

    // we can probably remove the RequestBodyLimitLayer with this
    let response = match to_bytes(req_body, MAX_PAYLOAD_LENGTH).await {
        Ok(bytes) => {
            APIMetrics::size(&endpoint, bytes.len());

            let req = Request::from_parts(req_parts, Body::from(bytes));
            next.run(req).await
        }
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };

    APIMetrics::status(&endpoint, response.status().as_str());

    response
}
