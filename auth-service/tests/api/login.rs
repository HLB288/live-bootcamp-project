use crate::helper::{get_random_email, TestApp};


// #[tokio::test]
// async fn login_returns_success() {
//     let app = TestApp::new().await;
//     let response = app.post_login().await;
//     assert_eq!(response.status().as_u16(), 200);
// }

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let app = TestApp::new().await;
    let response = app.post_login().await;
    assert_eq!(response.status().as_u16(), 422);
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;
    let invalid_credentials = serde_json::json!({
        "username": "", 
        "password": ""
    });
    let response = app.post_login_with_body(&invalid_credentials).await;
    assert_eq!(response.status().as_u16(),400);
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new().await;

    // Define incorrect credentials
    let incorrect_credentials = serde_json::json!({
        "email": "nonexistent@example.com",
        "password": "wrongpassword"
    });

    // Call the login route with incorrect credentials
    let response = app.post_login_with_body(&incorrect_credentials).await;

    // Assert that a 401 HTTP status code is returned
    assert_eq!(response.status().as_u16(), 401);

}