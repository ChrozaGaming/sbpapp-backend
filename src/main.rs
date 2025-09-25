use actix_cors::Cors;
use actix_web::{http::header, middleware::Logger, web::Data, App, HttpServer};
use dotenvy::dotenv;
use env_logger::Env;
use ipnet::IpNet;
use sqlx::MySqlPool;
use std::{env, net::IpAddr};

mod db;
mod errors;
mod models;
mod routes;
mod security;

use db::init_pool;
use models::AppState;
use routes::config_routes;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let database_url = match env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            let host = env::var("DB_HOST").unwrap_or_else(|_| "localhost".into());
            let port = env::var("DB_PORT").unwrap_or_else(|_| "3306".into());
            let name = env::var("DB_NAME").unwrap_or_else(|_| "sbpapp".into());
            let user = env::var("DB_USER").unwrap_or_else(|_| "root".into());
            let pass = env::var("DB_PASSWORD").unwrap_or_else(|_| "".into());
            format!("mysql://{}:{}@{}:{}/{}", user, pass, host, port, name)
        }
    };

    let pool: MySqlPool = init_pool(&database_url)
        .await
        .expect("Failed to create DB pool");

    let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| "dev_secret".into());

    let allowed_public_ip: Option<IpAddr> = env::var("ALLOWED_PUBLIC_IP")
        .ok()
        .and_then(|s| s.parse().ok());

    let allowed_subnet: Option<IpNet> = env::var("ALLOWED_SUBNET")
        .ok()
        .and_then(|s| s.parse().ok());

    let trust_x_forwarded_for =
        env::var("TRUST_X_FORWARDED_FOR").unwrap_or_else(|_| "0".into()) == "1";


    let allowed_origins =
        env::var("ALLOWED_ORIGINS").unwrap_or_else(|_| "http://localhost:3000".into());
    let origins: Vec<String> = allowed_origins
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // --- Bind host/port ---
    let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port = env::var("PORT").unwrap_or_else(|_| "8080".into());
    let addr = format!("{}:{}", host, port);

    log::info!("Server starting at http://{}", &addr);
    log::info!("CORS allowed origins: {:?}", origins);
    log::info!("ALLOWED_PUBLIC_IP: {:?}", allowed_public_ip);
    log::info!("ALLOWED_SUBNET: {:?}", allowed_subnet);
    log::info!("TRUST_X_FORWARDED_FOR: {}", trust_x_forwarded_for);

    let app_state = AppState {
        pool,
        jwt_secret,
        allowed_public_ip,
        allowed_subnet,
        trust_x_forwarded_for,
    };

    HttpServer::new(move || {
        let cors = origins.iter().fold(
            Cors::default()
                .allowed_methods(vec!["GET", "POST", "OPTIONS"])
                .allowed_headers(vec![
                    header::CONTENT_TYPE,
                    header::AUTHORIZATION,
                    header::ACCEPT,
                ])
                .max_age(3600),
            |c, origin| c.allowed_origin(origin),
        );

        App::new()
            .wrap(Logger::default())
            .wrap(cors)
            .app_data(Data::new(app_state.clone()))
            .configure(config_routes)
    })
    .bind(addr)?
    .run()
    .await
}
