use axum::{extract::State, Json};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use secrecy::{Secret, ExposeSecret};
use crate::{
    app_state::AppState,
    domain::{error::AuthAPIError, Email, data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore}},
    utils::auth::generate_auth_cookie,
};
use color_eyre::eyre::eyre;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}

#[tracing::instrument(name = "Login", skip_all)]
pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    if request.email.trim().is_empty() || request.password.expose_secret().trim().is_empty() {
        return (jar, Err(AuthAPIError::InvalidCredentials));
    }
    
    if !request.email.contains('@') || request.email.len() < 3 {
        return (jar, Err(AuthAPIError::InvalidCredentials));
    }

    let email = request.email.as_str();

    let user_store = state.user_store.read().await;
    if let Err(_) = user_store.validate_user(email, request.password.expose_secret()).await {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    let user = match user_store.get_user(email).await {
        Ok(user) => user,
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
    };

    drop(user_store);

    match user.requires_2fa {
        true => handle_2fa(&user.email, &state, jar).await,  
        false => handle_no_2fa(&user.email, jar).await,    
    }
}

#[tracing::instrument(name = "Handle 2FA", skip_all)]
async fn handle_2fa(
    email: &Email,
    state: &AppState,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    let login_attempt_id = LoginAttemptId::default();
    let two_fa_code = TwoFACode::default();

    {
        let mut two_fa_store = state.two_fa_code_store.write().await;
        if let Err(e) = two_fa_store.add_code(email.clone(), login_attempt_id.clone(), two_fa_code.clone()).await {
            return (jar, Err(AuthAPIError::UnexpectedError(e.into())));
        }
    }

    if let Err(e) = state
        .email_client
        .send_email(email, "2FA Code", two_fa_code.as_ref().expose_secret())
        .await
    {
        return (jar, Err(AuthAPIError::UnexpectedError(e.into())));
    }

    let response = Json(LoginResponse::TwoFactorAuth(TwoFactorAuthResponse {
        message: "2FA required".to_owned(),
        login_attempt_id: login_attempt_id.as_ref().expose_secret().clone(),
    }));

    (jar, Ok((StatusCode::PARTIAL_CONTENT, response)))
}

#[tracing::instrument(name = "Handle no 2FA", skip_all)]
async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    let auth_cookie = match generate_auth_cookie(email) {
        Ok(cookie) => cookie,
        Err(e) => return (jar, Err(AuthAPIError::UnexpectedError(e.into()))),
    };

    let updated_jar = jar.add(auth_cookie);
    (
        updated_jar,
        Ok((StatusCode::OK, Json(LoginResponse::RegularAuth))),
    )
}