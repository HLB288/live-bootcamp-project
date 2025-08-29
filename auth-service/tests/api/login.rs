use crate::helper::{get_random_email, TestApp};
use auth_service::{
    utils::constants::JWT_COOKIE_NAME, 
    domain::{error::ErrorResponse, Email},
    routes::login::TwoFactorAuthResponse
};
use secrecy::ExposeSecret;
use wiremock::{matchers::{method, path}, Mock, ResponseTemplate};

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let app = TestApp::new().await;
    let response = app.post_login_malformed().await; 
    assert_eq!(response.status().as_u16(), 422);
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;
    let invalid_credentials = serde_json::json!({
        "email": "", 
        "password": ""
    });
    let response = app.post_login_with_body(&invalid_credentials).await;
    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new().await;
    let incorrect_credentials = serde_json::json!({
        "email": "nonexistent@example.com",
        "password": "wrongpassword"
    });
    let response = app.post_login_with_body(&incorrect_credentials).await;
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let app = TestApp::new().await;
    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });

    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 200);

    let cookies = response.headers().get_all("set-cookie");
    let auth_cookie_found = cookies.iter().any(|cookie| {
        let cookie_str = cookie.to_str().unwrap_or("");
        cookie_str.starts_with(&format!("{}=", JWT_COOKIE_NAME))
    });
    
    assert!(auth_cookie_found, "Auth cookie should be set");
}

#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let app = TestApp::new().await;
    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;
    
    // Test sur logout avec un token invalide
    let invalid_cookie_client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();

    let response = invalid_cookie_client
        .post(&format!("{}/logout", &app.address))
        .header("Cookie", &format!("{}=invalid", JWT_COOKIE_NAME))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 401); // La route logout doit valider le token
}

#[tokio::test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    let app = TestApp::new().await;
    let random_email = get_random_email();

    // Créer un utilisateur AVEC 2FA activée
    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    // Define an expectation for the mock server
    Mock::given(path("/email")) // Expect an HTTP request to the "/email" path
        .and(method("POST")) // Expect the HTTP method to be POST
        .respond_with(ResponseTemplate::new(200)) // Respond with an HTTP 200 OK status
        .expect(1) // Expect this request to be made exactly once
        .mount(&app.email_server) // Mount this expectation on the mock email server
        .await; // Await the asynchronous operation to ensure the mock server is set up before proceeding

    // Tenter de se connecter avec les bonnes credentials
    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;
    
    // Vérifier le status 206 (2FA required)
    assert_eq!(response.status().as_u16(), 206);
    
    // Vérifier le body JSON avec le bon type
    let json_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");
        
    assert_eq!(json_body.message, "2FA required".to_owned());

    // NOUVEAU: Vérifier que le login_attempt_id est stocké dans le 2FA code store
    let email = Email::parse(random_email.into()).unwrap();
    let two_fa_store = app.two_fa_code_store.read().await;
    
    // Vérifier que le code 2FA existe pour cet email
    let result = two_fa_store.get_code(&email).await;
    assert!(result.is_ok(), "2FA code should be stored for the email");
    
    let (stored_login_attempt_id, _stored_code) = result.unwrap();
    
    // Vérifier que l'ID de tentative de connexion correspond à celui retourné dans la réponse
    assert_eq!(
        stored_login_attempt_id.as_ref().expose_secret(), 
        &json_body.login_attempt_id,
        "Login attempt ID in response should match the one stored in 2FA code store"
    );
}