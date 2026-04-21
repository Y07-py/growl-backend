use slog;
use sqlx;
use std::{env, panic, sync::Arc};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct PostgresHandler {
    pool: sqlx::Pool<sqlx::Postgres>,
    sub_logger: slog::Logger,
}

impl PostgresHandler {
    pub async fn new(max_connection: u32, root_logger: &slog::Logger) -> Arc<RwLock<Self>> {
        // Build sub logger for `PostgresHandler`
        let sub_logger = root_logger.new(slog::o!("infra" => "repository"));

        let db_endpoint = env::var("DATABASE_ENDPOINT").unwrap();

        match sqlx::postgres::PgPoolOptions::new()
            .max_connections(max_connection)
            .connect(&db_endpoint)
            .await
        {
            Ok(pool) => {
                slog::info!(sub_logger, "Successfully connected to the database."; "endpoint" => &db_endpoint);
                Arc::new(RwLock::new(Self { pool, sub_logger }))
            }
            Err(e) => {
                slog::error!(sub_logger, "Failed to connect to the database."; "endpoint" => &db_endpoint, "error" => ?e);
                panic!("Failed to connect the database: {:?}", e);
            }
        }
    }

    pub fn get_pool(&self) -> &sqlx::Pool<sqlx::Postgres> {
        &self.pool
    }

    pub fn get_sub_logger(&self) -> &slog::Logger {
        &self.sub_logger
    }
}
