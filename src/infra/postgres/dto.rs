use sqlx;

#[derive(sqlx::FromRow)]
pub struct UserIdentityRow {
    sub_id: String,
    email: String,
    phone_number: String,
    authentication_method: String,
    role: String,
}

impl UserIdentityRow {
    pub fn sub_id(&self) -> String {
        self.sub_id.clone()
    }

    pub fn email(&self) -> String {
        self.email.clone()
    }

    pub fn phone_number(&self) -> String {
        self.phone_number.clone()
    }

    pub fn authentication_method(&self) -> String {
        self.authentication_method.clone()
    }

    pub fn role(&self) -> String {
        self.role.clone()
    }
}
