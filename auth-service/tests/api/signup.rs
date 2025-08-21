use crate::helper::TestApp;
use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use auth_service::domain::error::ErrorResponse; // CORRECTION: import correct

pub async fn signup(Json(_request): Json<SignupRequest>) -> impl IntoResponse { // CORRECTION: préfixe avec _
    StatusCode::OK.into_response()
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;
    let test_cases = [
        serde_json::json!({
            "email": "",
            "password": "password123",
            "requires2FA": false
        }),
        serde_json::json!({
            "email": "invalid-email",
            "password": "password123",
            "requires2FA": false
        }),
        serde_json::json!({
            "email": "test@example.com",
            "password": "short",
            "requires2FA": false
        })
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            test_case
        );
        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid credentials".to_owned()
        );
    }
}

#[tokio::test]
async fn should_return_409_if_email_already_exists() {
    let app = TestApp::new().await;
    let random_email = TestApp::get_random_email();
    let request_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });

    // First request should succeed
    let response = app.post_signup(&request_body).await;
    assert_eq!(response.status().as_u16(), 201);

    // Second request with the same email should fail with 409
    let response = app.post_signup(&request_body).await;
    assert_eq!(response.status().as_u16(), 409);
    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "User already exists".to_owned()
    );
}