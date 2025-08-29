use crate::helper::{get_random_email, TestApp}; // CORRECTION: helper au lieu de helpers
use auth_service::utils::constants::JWT_COOKIE_NAME; // AJOUT: import du trait BannedTokenStore
use secrecy::Secret;

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;
    // Send malformed input, e.g., an empty JSON object or an object with an incorrect field
    let malformed_body = serde_json::json!({});
    let response = app.post_verify_token(&malformed_body).await;
    // Assert that the response status code is 422 Unprocessable Entity
    assert_eq!(response.status().as_u16(), 422);
}

#[tokio::test]
async fn should_return_200_valid_token() {
    // Create a new test application instance
    let app = TestApp::new().await;
    // Simulate a user login to get a valid JWT cookie
    let email = get_random_email();
    let password = "password123"; // Use a valid password as per your test setup
    let _ = app.post_signup(&serde_json::json!({
        "email": email,
        "password": password,
        "requires2FA": false // AJOUT: champ manquant
    })).await;
    let response = app.post_login(&serde_json::json!({
        "email": email,
        "password": password
    })).await;
    // Ensure login was successful
    assert_eq!(response.status().as_u16(), 200);
    
    // Extract the JWT token from the cookie header
    let cookies = response.headers().get_all("set-cookie");
    let mut token = String::new();
    for cookie in cookies.iter() {
        let cookie_str = cookie.to_str().unwrap_or("");
        if cookie_str.starts_with(&format!("{}=", JWT_COOKIE_NAME)) {
            token = cookie_str
                .split('=')
                .nth(1)
                .unwrap_or("")
                .split(';')
                .next()
                .unwrap_or("")
                .to_string();
            break;
        }
    }
    
    // Verify the token
    let verify_response = app.post_verify_token(&serde_json::json!({
        "token": token
    })).await;
    // Assert that the response status code is 200 OK
    assert_eq!(verify_response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    // Create a new test application instance
    let app = TestApp::new().await;
    // Attempt to verify an invalid token
    let verify_response = app.post_verify_token(&serde_json::json!({
        "token": "invalid_token"
    })).await;
    // Assert that the response status code is 401 Unauthorized
    assert_eq!(verify_response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_401_if_banned_token() {
    // Create a new test application instance
    let app = TestApp::new().await;

    // Simulate a user login to get a valid JWT cookie
    let email = get_random_email();
    let password = "password123";
    let _ = app.post_signup(&serde_json::json!({
        "email": email,
        "password": password,
        "requires2FA": false // AJOUT: champ manquant
    })).await;

    let response = app.post_login(&serde_json::json!({
        "email": email,
        "password": password
    })).await;

    // Ensure login was successful
    assert_eq!(response.status().as_u16(), 200);

    // Extract the JWT token from the cookie header
    let cookies = response.headers().get_all("set-cookie");
    let mut token = String::new();
    for cookie in cookies.iter() {
        let cookie_str = cookie.to_str().unwrap_or("");
        if cookie_str.starts_with(&format!("{}=", JWT_COOKIE_NAME)) {
            token = cookie_str
                .split('=')
                .nth(1)
                .unwrap_or("")
                .split(';')
                .next()
                .unwrap_or("")
                .to_string();
            break;
        }
    }

    // Ban the token by adding it to the banned token store
    let mut banned_token_store = app.banned_token_store.write().await;
    let _ = banned_token_store.add_token(Secret::new(token.clone())).await;
    drop(banned_token_store); // Release the lock

    // Attempt to verify the banned token
    let verify_response = app.post_verify_token(&serde_json::json!({
        "token": token
    })).await;

    // Assert that the response status code is 401 Unauthorized
    assert_eq!(verify_response.status().as_u16(), 401);
}