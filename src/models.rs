use chrono::{NaiveDate, NaiveDateTime};
use serde::{Deserialize, Serialize};
use sqlx::MySqlPool;
use std::net::IpAddr;
use ipnet::IpNet;

#[derive(Clone)]
pub struct AppState {
    pub pool: MySqlPool,
    pub jwt_secret: String,
    pub allowed_public_ips: Vec<IpAddr>,
    pub allowed_subnets: Vec<IpNet>,
    pub trust_x_forwarded_for: bool,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub token: String,
    pub user: UserPublic,
}

#[derive(Debug, sqlx::FromRow)]
pub struct User {
    pub id: u64,
    pub name: String,
    pub email: String,
    pub password_hash: String,
    #[allow(dead_code)]
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Serialize)]
pub struct UserPublic {
    pub id: u64,
    pub name: String,
    pub email: String,
}

impl From<User> for UserPublic {
    fn from(u: User) -> Self {
        Self { id: u.id, name: u.name, email: u.email }
    }
}

#[derive(Debug, Deserialize)]
pub struct AbsensiRequest {
    pub tanggal_absensi: String,
    pub nama_lengkap: String,
    pub email: String,
    pub waktu_absensi: String,
    pub location_device_lat: Option<f64>,
    pub location_device_lng: Option<f64>,
    pub status: String,
    pub ip_device: Option<String>
}

#[derive(Debug, sqlx::FromRow)]
pub struct AbsensiRow {
    pub id: u64,
    pub tanggal_absensi: NaiveDate,
    pub nama_lengkap: String,
    pub email: String,
    pub waktu_absensi: NaiveDateTime,
    pub ipverified: bool,
    pub ip_device: Option<String>,
    pub location_device_lat: Option<f64>,
    pub location_device_lng: Option<f64>,
    pub status: String,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Serialize)]
pub struct AbsensiPublic {
    pub id: u64,
    pub tanggal_absensi: String,
    pub nama_lengkap: String,
    pub email: String,
    pub waktu_absensi: String,
    pub ipverified: bool,
    pub ip_device: Option<String>,
    pub location_device_lat: Option<f64>,
    pub location_device_lng: Option<f64>,
    pub status: String,
    pub created_at: String,
}
