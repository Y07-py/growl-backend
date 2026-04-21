use async_trait::async_trait;
use sqlx;

use crate::domain::entities;

#[async_trait]
pub trait AuthenticationRepository {
    async fn upsert_guest_user(
        &self,
        guset: &entities::auth::AuthenticationUser,
    ) -> Result<(), sqlx::Error>;

    async fn upsert_authenticated_user(
        &self,
        user: &entities::auth::AuthenticationUser,
    ) -> Result<(), sqlx::Error>;
}
