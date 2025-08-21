#[derive(Clone)] // AJOUT: Clone pour pouvoir cloner User
pub struct User {
    pub email: String,
    pub password: String,
    pub require_2fa: bool,
}

#[derive(Debug, Clone)]
pub struct Email(pub String);

impl Email {
    pub fn parse(email: String) -> Result<Self, String> {
        if email.contains('@') {
            Ok(Email(email))
        } else {
            Err("Invalid email format".to_string())
        }
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl User {
    pub fn new(email: String, password: String, require_2fa: bool) -> Self {
        User {
            email,
            password,
            require_2fa,
        }
    }
}