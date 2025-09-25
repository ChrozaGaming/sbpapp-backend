use anyhow::Result;
use sqlx::{mysql::MySqlPoolOptions, MySqlPool};

pub async fn init_pool(database_url: &str) -> Result<MySqlPool> {
    let pool = MySqlPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await?;
    Ok(pool)
}
