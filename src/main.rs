use actix_cors::Cors;
use actix_web::{middleware::Logger, web::Data, App, HttpServer};
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

fn parse_list_env(key: &str) -> Vec<String> {
    env::var(key)
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_ip_list(key: &str) -> Vec<IpAddr> {
    parse_list_env(key)
        .into_iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .collect()
}

fn parse_subnet_list(key: &str) -> Vec<IpNet> {
    parse_list_env(key)
        .into_iter()
        .filter_map(|mut s| {
            if !s.contains('/') {
                // treat single IP as /32 (IPv4) or /128 (IPv6)
                if s.contains(':') { s.push_str("/128"); } else { s.push_str("/32"); }
            }
            s.parse::<IpNet>().ok()
        })
        .collect()
}

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

    let allowed_public_ips: Vec<IpAddr> = parse_ip_list("ALLOWED_PUBLIC_IP");
    let allowed_subnets: Vec<IpNet> = parse_subnet_list("ALLOWED_SUBNET");
    let trust_x_forwarded_for = env::var("TRUST_X_FORWARDED_FOR")
        .unwrap_or_else(|_| "0".into()) == "1";

    let allowed_origins = parse_list_env("ALLOWED_ORIGINS");

    let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port = env::var("PORT").unwrap_or_else(|_| "8080".into());
    let addr = format!("{}:{}", host, port);

    log::info!("Server http://{}", &addr);
    log::info!("CORS origins: {:?}", allowed_origins);
    log::info!("Allowed IPs: {:?}", allowed_public_ips);
    log::info!("Allowed subnets: {:?}", allowed_subnets);
    log::info!("TRUST_X_FORWARDED_FOR: {}", trust_x_forwarded_for);

    let app_state = AppState {
        pool,
        jwt_secret,
        allowed_public_ips,
        allowed_subnets,
        trust_x_forwarded_for,
    };

    HttpServer::new(move || {
        let mut cors = Cors::default()
            .allow_any_header()
            .allowed_methods(vec!["GET", "POST", "OPTIONS"]);
        for o in &allowed_origins {
            cors = cors.allowed_origin(o);
        }

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
