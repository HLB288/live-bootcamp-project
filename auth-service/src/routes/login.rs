use axum::http::StatusCode;
use axum::response::IntoResponse;


pub async fn login() -> impl IntoResponse {
    StatusCode::OK
}