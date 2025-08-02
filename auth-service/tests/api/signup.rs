use crate::helper::TestApp;
use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;


pub async fn signup(Json(request): Json<SignupRequest>) -> impl IntoResponse {
    StatusCode::OK.into_response()
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String, 
    pub password: String, 
    #[serde(rename= "requires2FA")]
    pub requires_2FA: bool
}


// #[tokio::test]
// async fn signup_returns_success() {
//     let app = TestApp::new().await;
//     let response = app.post_signup().await;
//     assert_eq!(response.status().as_u16(), 200);
// }

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;
    let random_email = TestApp::get_random_email();
    let test_cases = [
        serde_json::json!({
            "password": "password123", 
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email, 
            "password": "password123"
        }),
                serde_json::json!({
            "email": "fezfezgrgza",
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "password": "",
            "requires2FA": true
        }),

    ];
    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn should_return_201_if_valid_input() {
    let app = TestApp::new().await;
    let random_email = TestApp::get_random_email();
    let request_body = serde_json::json!({
        "email": random_email, 
        "password": "password123",
    });
}