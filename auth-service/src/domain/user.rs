

pub struct User {
    email: String, 
    passwor: String, 
    require_2fa: bool,
}

impl user {
    pub fn new(email: String, password: String, require_2fa: bool) -> Self {
        User {
            email, 
            password, 
            require_2fa,
        }
    }
}