pub struct User {
    pub email: String,
    pub password: String,
    pub require_2fa: bool,
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

