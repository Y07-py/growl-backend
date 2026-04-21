use async_trait::async_trait;
use slog;
use sqlx;

use crate::domain::{entities, interface};
use crate::infra::repository::postgres;

#[async_trait]
impl interface::repository::AuthenticationRepository for postgres::PostgresHandler {
    async fn insert_guest_user(
        &self,
        guest: &entities::auth::AuthenticationUser,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "
            INSERT INTO authentication_users (sud_id, email, phone_number, authentication_method, role) \
            VALUES ($1, $2, $3, $4, $5) \
            ON CONFLICT (sub_id) DO NOTHING \
            ",
        )
        .bind(&guest.sub_id)
        .bind(&guest.email)
        .bind(&guest.phone_number)
        .bind(&guest.authentication_method)
        .bind(&guest.role)
        .execute(self.get_pool())
        .await?;

        let sub_logger = self.get_sub_logger();
        slog::info!(
            sub_logger,
            "successfully to insert guest user into authenticated_users."
        );

        Ok(())
    }

    async fn update_authenticated_user(
        &self,
        user: &entities::auth::AuthenticationUser,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "
            UPDATE authentication_users \
            SET role = $1 \
            WHERE sub_id = $2
            ",
        )
        .bind(&user.role)
        .bind(&user.sub_id)
        .execute(self.get_pool())
        .await?;

        let sub_logger = self.get_sub_logger();
        slog::info!(
            sub_logger,
            "successfully to update guest user in authenticated_users"
        );

        Ok(())
    }
}
