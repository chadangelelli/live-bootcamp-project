#[derive(Clone, Debug, PartialEq)] 
pub struct User {
    pub email: String,
    password: String,
    requires_2fa: bool, 
}

impl User {
    pub fn new(email: String, password: String, requires_2fa: bool) -> Self {
        User { email, password, requires_2fa }
    }

    pub fn get_password(&self) -> &str { &self.password }

    pub fn requires_2fa(&self) -> &bool { &self.requires_2fa }
}
