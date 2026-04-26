use async_trait::async_trait;
use sqlx;

use crate::domain::entities;
use crate::domain::interface;

#[async_trait]
pub trait AuthenticationRepository: Send + Sync {
    async fn insert_guest_user(
        &self,
        guset: &entities::auth::UserIdentity,
    ) -> Result<(), sqlx::Error>;

    async fn update_authenticated_user(
        &self,
        user: &entities::auth::UserIdentity,
    ) -> Result<(), sqlx::Error>;

    async fn find_user_by_sub_id(
        &self,
        sub_id: &str,
    ) -> Result<Option<entities::auth::UserIdentity>, sqlx::Error>;

    async fn find_user_by_username(
        &self,
        auth_method: &interface::auth::AuthenticationMethod,
    ) -> Result<Option<entities::auth::UserIdentity>, sqlx::Error>;
}
