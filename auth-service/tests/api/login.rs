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
