use crate::helper::{get_random_email, TestApp};
use auth_service::{
    domain::{
        Email, 
        data_stores::{LoginAttemptId, TwoFACode},
        error::ErrorResponse,
    },
    routes::login::TwoFactorAuthResponse,
    utils::constants::JWT_COOKIE_NAME,
};
use secrecy::{ExposeSecret, Secret};
use wiremock::{matchers::{method, path}, Mock, ResponseTemplate};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let malformed_body = serde_json::json!({});
    let response = app.post_verify_2fa(&malformed_body).await;
    assert_eq!(response.status().as_u16(), 422);
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

    // Test case 1: Email avec format invalide
    let response = app.post_verify_2fa(&serde_json::json!({
        "email": "not-an-email",
        "loginAttemptId": LoginAttemptId::default().as_ref().expose_secret(),
        "2FACode": TwoFACode::default().as_ref().expose_secret()
    })).await;
    assert_eq!(response.status().as_u16(), 400);

    // Test case 2: LoginAttemptId invalide (pas un UUID)
    let response = app.post_verify_2fa(&serde_json::json!({
        "email": get_random_email(),
        "loginAttemptId": "not-a-uuid",
        "2FACode": TwoFACode::default().as_ref().expose_secret()
    })).await;
    assert_eq!(response.status().as_u16(), 400);

    // Test case 3: Code 2FA avec format invalide (trop court)
    let response = app.post_verify_2fa(&serde_json::json!({
        "email": get_random_email(),
        "loginAttemptId": LoginAttemptId::default().as_ref().expose_secret(),
        "2FACode": "123"
    })).await;
    assert_eq!(response.status().as_u16(), 400);

    // Test case 4: Code 2FA avec format invalide (trop long)
    let response = app.post_verify_2fa(&serde_json::json!({
        "email": get_random_email(),
        "loginAttemptId": LoginAttemptId::default().as_ref().expose_secret(),
        "2FACode": "1234567"
    })).await;
    assert_eq!(response.status().as_u16(), 400);

    // Test case 5: Code 2FA avec caractères non numériques
    let response = app.post_verify_2fa(&serde_json::json!({
        "email": get_random_email(),
        "loginAttemptId": LoginAttemptId::default().as_ref().expose_secret(),
        "2FACode": "12345a"
    })).await;
    assert_eq!(response.status().as_u16(), 400);

    let error_response: ErrorResponse = response.json().await.expect("Failed to parse response body");
    assert!(!error_response.error.is_empty());
}

#[tokio::test]
async fn should_return_200_if_correct_code() {
    let app = TestApp::new().await;
    
    let email = get_random_email();
    let password = "password123";
    
    let response = app.post_signup(&serde_json::json!({
        "email": email,
        "password": password,
        "requires2FA": true
    })).await;

    assert_eq!(response.status().as_u16(), 201);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    let login_response = app.post_login(&serde_json::json!({
        "email": email,
        "password": password
    })).await;
    
    assert_eq!(login_response.status().as_u16(), 206);
    let login_response_body: TwoFactorAuthResponse = login_response.json().await.unwrap();
    
    let two_fa_store = app.two_fa_code_store.read().await;
    let email_obj = Email::parse(Secret::new(email.clone())).unwrap();
    let (stored_login_attempt_id, stored_code) = two_fa_store.get_code(&email_obj).await.unwrap();
    drop(two_fa_store);

    let response = app.post_verify_2fa(&serde_json::json!({
        "email": email,
        "loginAttemptId": login_response_body.login_attempt_id,
        "2FACode": stored_code.as_ref().expose_secret()
    })).await;
    
    assert_eq!(response.status().as_u16(), 200);
    
    let auth_cookie = response.headers()
        .get_all("set-cookie")
        .iter()
        .find(|cookie| {
            cookie.to_str()
                .unwrap_or("")
                .starts_with(&format!("{}=", JWT_COOKIE_NAME))
        });
    
    assert!(auth_cookie.is_some(), "Auth cookie should be set");
}

#[tokio::test]
async fn should_return_401_if_same_code_twice() {
    let app = TestApp::new().await;
    
    let email = get_random_email();
    let password = "password123";
    
    let response = app.post_signup(&serde_json::json!({
        "email": email,
        "password": password,
        "requires2FA": true
    })).await;

    assert_eq!(response.status().as_u16(), 201);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    let login_response = app.post_login(&serde_json::json!({
        "email": email,
        "password": password
    })).await;
    
    assert_eq!(login_response.status().as_u16(), 206);
    let login_response_body: TwoFactorAuthResponse = login_response.json().await.unwrap();
    
    let two_fa_store = app.two_fa_code_store.read().await;
    let email_obj = Email::parse(Secret::new(email.clone())).unwrap();
    let (_, stored_code) = two_fa_store.get_code(&email_obj).await.unwrap();
    drop(two_fa_store);

    let first_response = app.post_verify_2fa(&serde_json::json!({
        "email": email,
        "loginAttemptId": login_response_body.login_attempt_id,
        "2FACode": stored_code.as_ref().expose_secret()
    })).await;
    
    assert_eq!(first_response.status().as_u16(), 200);

    let second_response = app.post_verify_2fa(&serde_json::json!({
        "email": email,
        "loginAttemptId": login_response_body.login_attempt_id,
        "2FACode": stored_code.as_ref().expose_secret()
    })).await;
    
    assert_eq!(second_response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new().await;
    
    let email = get_random_email();
    let password = "password123";
    
    let response = app.post_signup(&serde_json::json!({
        "email": email,
        "password": password,
        "requires2FA": true
    })).await;

    assert_eq!(response.status().as_u16(), 201);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    let login_response = app.post_login(&serde_json::json!({
        "email": email,
        "password": password
    })).await;
    
    assert_eq!(login_response.status().as_u16(), 206);
    let login_response_body: TwoFactorAuthResponse = login_response.json().await.unwrap();

    // Use wrong code
    let response = app.post_verify_2fa(&serde_json::json!({
        "email": email,
        "loginAttemptId": login_response_body.login_attempt_id,
        "2FACode": "999999"
    })).await;
    
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    let app = TestApp::new().await;
    
    let email = get_random_email();
    let password = "password123";
    
    let response = app.post_signup(&serde_json::json!({
        "email": email,
        "password": password,
        "requires2FA": true
    })).await;

    assert_eq!(response.status().as_u16(), 201);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&app.email_server)
        .await;

    // Premier login pour obtenir un premier code
    let first_login_response = app.post_login(&serde_json::json!({
        "email": email,
        "password": password
    })).await;
    
    assert_eq!(first_login_response.status().as_u16(), 206);
    let first_login_body: TwoFactorAuthResponse = first_login_response.json().await.unwrap();
    
    let two_fa_store = app.two_fa_code_store.read().await;
    let email_obj = Email::parse(Secret::new(email.clone())).unwrap();
    let (_, first_code) = two_fa_store.get_code(&email_obj).await.unwrap();
    drop(two_fa_store);

    // Deuxième login qui va générer un nouveau code
    let second_login_response = app.post_login(&serde_json::json!({
        "email": email,
        "password": password
    })).await;
    
    assert_eq!(second_login_response.status().as_u16(), 206);

    // Essayer d'utiliser l'ancien code
    let response = app.post_verify_2fa(&serde_json::json!({
        "email": email,
        "loginAttemptId": first_login_body.login_attempt_id,
        "2FACode": first_code.as_ref().expose_secret()
    })).await;
    
    assert_eq!(response.status().as_u16(), 401);
}