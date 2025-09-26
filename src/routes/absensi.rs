use actix_web::{web, HttpRequest, HttpResponse};
use chrono::{NaiveDate, NaiveDateTime};
use serde::Deserialize;
use std::{env, net::IpAddr};

use crate::{
    errors::ApiError,
    models::{AbsensiPublic, AbsensiRequest, AbsensiRow, AppState},
};

fn get_client_ip(req: &HttpRequest, trust_xff: bool) -> Option<IpAddr> {
    if trust_xff {
        if let Some(h) = req.headers().get("x-forwarded-for") {
            if let Ok(s) = h.to_str() {
                if let Some(first) = s.split(',').map(|p| p.trim()).next() {
                    if let Ok(ip) = first.parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
            }
        }
    }
    req.peer_addr().map(|s| s.ip())
}

fn is_ip_allowed(ip: IpAddr, state: &AppState, dev_allow_loopback: bool) -> bool {
    if state.allowed_public_ips.iter().any(|x| *x == ip) {
        return true;
    }
    if state.allowed_subnets.iter().any(|net| net.contains(&ip)) {
        return true;
    }
    if dev_allow_loopback && ip.is_loopback() {
        return true;
    }
    false
}

#[derive(Deserialize)]
pub struct TodayQuery {
    pub email: String,
    pub tanggal: Option<String>,
}

pub async fn check_today_absen(
    state: web::Data<AppState>,
    q: web::Query<TodayQuery>,
) -> Result<HttpResponse, ApiError> {
    let email = q.email.trim();
    if email.is_empty() {
        return Err(ApiError::BadRequest("email wajib diisi".into()));
    }

    if let Some(tgls) = &q.tanggal {
        let tgl = NaiveDate::parse_from_str(tgls, "%Y-%m-%d")
            .map_err(|_| ApiError::BadRequest("tanggal harus format YYYY-MM-DD".into()))?;

        let exist: Option<(i64,)> = sqlx::query_as::<_, (i64,)>(
            "SELECT 1 FROM absensi WHERE email = ? AND tanggal_absensi = ? LIMIT 1",
        )
        .bind(email)
        .bind(tgl)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| ApiError::Internal(format!("DB check error: {e}")))?;

        return Ok(HttpResponse::Ok().json(serde_json::json!({ "exists": exist.is_some() })));
    }

    let exist: Option<(i64,)> = sqlx::query_as::<_, (i64,)>(
        "SELECT 1 FROM absensi WHERE email = ? AND tanggal_absensi = CURDATE() LIMIT 1",
    )
    .bind(email)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(format!("DB check error: {e}")))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "exists": exist.is_some() })))
}

fn parse_waktu_absensi(s: &str) -> Result<NaiveDateTime, ApiError> {
    const FMT: [&str; 6] = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d %H:%M",
    ];
    for f in FMT {
        if let Ok(dt) = NaiveDateTime::parse_from_str(s, f) {
            return Ok(dt);
        }
    }
    Err(ApiError::BadRequest(
        "waktu_absensi harus format: YYYY-MM-DD HH:MM[:SS]".into(),
    ))
}

pub async fn create_absensi(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<AbsensiRequest>,
) -> Result<HttpResponse, ApiError> {
    let mut input = body.into_inner();

    let ip = get_client_ip(&req, state.trust_x_forwarded_for)
        .unwrap_or_else(|| "127.0.0.1".parse().unwrap());
    let ip_str = ip.to_string();

    let dev_allow_loopback =
        env::var("DEV_ALLOW_LOOPBACK").unwrap_or_else(|_| "0".to_string()) == "1";

    if !is_ip_allowed(ip, &state, dev_allow_loopback) {
        return Err(ApiError::Forbidden(format!(
            "IP {} tidak diizinkan. Solusi: gunakan Wi-Fi kantor / jaringan yang diizinkan.",
            ip_str
        )));
    }
    input.ip_device = Some(ip_str);

    let tgl = NaiveDate::parse_from_str(&input.tanggal_absensi, "%Y-%m-%d")
        .map_err(|_| ApiError::BadRequest("tanggal_absensi harus format YYYY-MM-DD".into()))?;

    let wkt = parse_waktu_absensi(&input.waktu_absensi)?;

    let exists: Option<(i64,)> = sqlx::query_as::<_, (i64,)>(
        r#"SELECT 1 FROM absensi WHERE email = ? AND tanggal_absensi = ? LIMIT 1"#,
    )
    .bind(&input.email)
    .bind(tgl)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(format!("DB check error: {e}")))?;

    if exists.is_some() {
        return Err(ApiError::Conflict("Anda sudah absen pada hari ini.".into()));
    }

    let result = sqlx::query(
        r#"
        INSERT INTO absensi
        (tanggal_absensi, nama_lengkap, email, waktu_absensi, ipverified, ip_device,
         location_device_lat, location_device_lng, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(tgl)
    .bind(&input.nama_lengkap)
    .bind(&input.email)
    .bind(wkt)
    .bind(true)
    .bind(&input.ip_device)
    .bind(input.location_device_lat)
    .bind(input.location_device_lng)
    .bind(&input.status)
    .execute(&state.pool)
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(db_err) = &e {
            if db_err.code().as_deref() == Some("23000") {
                return ApiError::Conflict("Anda sudah absen pada hari ini.".into());
            }
        }
        ApiError::Internal(format!("DB insert error: {e}"))
    })?;

    let id = result.last_insert_id();

    let row: AbsensiRow = sqlx::query_as::<_, AbsensiRow>(
        r#"
        SELECT
            id,
            tanggal_absensi,
            nama_lengkap,
            email,
            waktu_absensi,
            ipverified,
            ip_device,
            location_device_lat,
            location_device_lng,
            status,
            CAST(created_at AS DATETIME) AS created_at
        FROM absensi WHERE id = ? LIMIT 1
        "#,
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(format!("DB select error: {e}")))?;

    let out = AbsensiPublic {
        id: row.id,
        tanggal_absensi: row.tanggal_absensi.format("%Y-%m-%d").to_string(),
        nama_lengkap: row.nama_lengkap,
        email: row.email,
        waktu_absensi: row.waktu_absensi.format("%Y-%m-%d %H:%M:%S").to_string(),
        ipverified: row.ipverified,
        ip_device: row.ip_device,
        location_device_lat: row.location_device_lat,
        location_device_lng: row.location_device_lng,
        status: row.status,
        created_at: row.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
    };

    Ok(HttpResponse::Created().json(out))
}
