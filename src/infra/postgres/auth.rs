use async_trait::async_trait;
use slog;
use sqlx;

use crate::domain::{entities, interface};
use crate::infra::postgres::dto;
use crate::infra::postgres::handler;

#[async_trait]
impl interface::repository::AuthenticationRepository for handler::PostgresHandler {
    async fn insert_guest_user(
        &self,
        guest: &entities::auth::UserIdentity,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "
            INSERT INTO user_identities (sub_id, email, phone_number, authentication_method, role) \
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
            "successfully to insert guest user into user_identities."
        );

        Ok(())
    }

    async fn update_authenticated_user(
        &self,
        user: &entities::auth::UserIdentity,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "
            UPDATE user_identities \
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

    async fn find_user_by_sub_id(
        &self,
        sub_id: &str,
    ) -> Result<Option<entities::auth::UserIdentity>, sqlx::Error> {
        let row = sqlx::query_as::<_, dto::UserIdentityRow>(
            "
            SELECT sub_id, email, phone_number, authentication_method, role \
            FROM user_identities \
            WHERE sub_id = $1
            ",
        )
        .bind(sub_id)
        .fetch_optional(self.get_pool())
        .await?;

        Ok(row.map(|r| {
            entities::auth::UserIdentity::new(
                r.sub_id(),
                r.email(),
                r.phone_number(),
                r.authentication_method(),
                r.role(),
            )
        }))
    }

    async fn find_user_by_username(
        &self,
        method: &interface::auth::AuthenticationMethod,
    ) -> Result<Option<entities::auth::UserIdentity>, sqlx::Error> {
        let row = match method {
            interface::auth::AuthenticationMethod::Email { email, .. } => {
                sqlx::query_as::<_, dto::UserIdentityRow>(
                    "
                    SELECT sub_id, email, phone_number, authentication_method, role \
                    FROM user_identities \
                    WHERE email = $1
                    ",
                )
                .bind(email)
                .fetch_optional(self.get_pool())
                .await?
            }
            interface::auth::AuthenticationMethod::PhoneNumber { phone_number, .. } => {
                sqlx::query_as::<_, dto::UserIdentityRow>(
                    "
                    SELECT sub_id, email, phone_number, authentication_method, role \
                    FROM user_identities \
                    WHERE phone_number = $1
                    ",
                )
                .bind(phone_number)
                .fetch_optional(self.get_pool())
                .await?
            }
            _ => None,
        };

        Ok(row.map(|r| {
            entities::auth::UserIdentity::new(
                r.sub_id(),
                r.email(),
                r.phone_number(),
                r.authentication_method(),
                r.role(),
            )
        }))
    }
}
