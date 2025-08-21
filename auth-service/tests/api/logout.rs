use crate::helper::{get_random_email, TestApp}; // CORRECTION: helper au lieu de helpers
use auth_service::{utils::constants::JWT_COOKIE_NAME, domain::data_stores::BannedTokenStore}; // AJOUT: import du trait BannedTokenStore

#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
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
    assert_eq!(response.status().as_u16(), 200); // CORRECTION: comparaison avec u16

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

    // Attempt to logout using a client with the cookie
    let logout_client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();

    let logout_response = logout_client
        .post(&format!("{}/logout", &app.address))
        .header("Cookie", &format!("{}={}", JWT_COOKIE_NAME, token))
        .send()
        .await
        .unwrap();

    // Assert that the response status code is 200 OK
    assert_eq!(logout_response.status().as_u16(), 200); // CORRECTION: comparaison avec u16

    // Check that the token was added to the banned token store
    let banned_token_store = app.banned_token_store.read().await;
    let is_banned = banned_token_store.contains_token(&token).await.unwrap();
    assert!(is_banned, "Token should be banned after logout");
}

#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row() {
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
    assert_eq!(response.status().as_u16(), 200); // CORRECTION: comparaison avec u16

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

    let logout_client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();

    // Attempt to logout
    let first_logout_response = logout_client
        .post(&format!("{}/logout", &app.address))
        .header("Cookie", &format!("{}={}", JWT_COOKIE_NAME, token.clone()))
        .send()
        .await
        .unwrap();
    assert_eq!(first_logout_response.status().as_u16(), 200); // CORRECTION: comparaison avec u16

    // Attempt to logout again with the same token
    let second_logout_response = logout_client
        .post(&format!("{}/logout", &app.address))
        .header("Cookie", &format!("{}={}", JWT_COOKIE_NAME, token))
        .send()
        .await
        .unwrap();

    // Assert that the response status code is 401 (token is now banned)
    assert_eq!(second_logout_response.status().as_u16(), 401); // CORRECTION: comparaison avec u16
}