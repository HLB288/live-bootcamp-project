use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(Debug)]
pub enum AuthAPIError {
    UserAlreadyExists, 
    InvalidCredentials, 
    UnexpectedError,
    IncorrectCredentials,
    MissingToken, 
    InvalidToken,
}

#[derive(Serialize, serde::Deserialize)] 
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for AuthAPIError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthAPIError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AuthAPIError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
            AuthAPIError::IncorrectCredentials => (StatusCode::UNAUTHORIZED, "Authentication failed"),
            AuthAPIError::MissingToken => (StatusCode::BAD_REQUEST, "JWT cookie missing"),
            AuthAPIError::InvalidToken => (StatusCode::UNAUTHORIZED, "JWT is not valid"),
            AuthAPIError::UnexpectedError => (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error"),
        };

        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });

        (status, body).into_response()
    }
}