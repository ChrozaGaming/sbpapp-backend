use actix_web::{web, HttpRequest, HttpResponse};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::{
    errors::ApiError,
    models::{
        AppState, CheckEmailQuery, LicenseGenerateRequest, LicenseKeyPublic, LicenseVerifyRequest,
        LoginRequest, RegisterRequest, SetPasswordRequest, TokenResponse, User, UserPublic,
    },
    security::{hash_password, verify_password},
};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: u64,
    email: String,
    exp: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    lk: Option<String>,
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

pub async fn register(
    state: web::Data<AppState>,
    body: web::Json<RegisterRequest>,
) -> Result<HttpResponse, ApiError> {
    let RegisterRequest { name, email, password } = body.into_inner();
    if name.trim().is_empty() || email.trim().is_empty() || password.len() < 6 {
        return Err(ApiError::BadRequest(
            "Nama, email wajib diisi; password min 6 karakter".into(),
        ));
    }

    let exists: Option<(u64,)> = sqlx::query_as("SELECT id FROM users WHERE email = ? LIMIT 1")
        .bind(&email)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| ApiError::Internal(format!("DB error: {e}")))?;
    if exists.is_some() {
        return Err(ApiError::Conflict("Email sudah terdaftar".into()));
    }

    let hashed = hash_password(&password).map_err(|e| ApiError::Internal(format!("Hash error: {e}")))?;
    let result = sqlx::query(r#"INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)"#)
        .bind(&name)
        .bind(&email)
        .bind(&hashed)
        .execute(&state.pool)
        .await
        .map_err(|e| ApiError::Internal(format!("DB insert error: {e}")))?;

    let user_id = result.last_insert_id();
    let user_public = UserPublic { id: user_id, name, email };
    Ok(HttpResponse::Created().json(user_public))
}

pub async fn check_email(
    state: web::Data<AppState>,
    q: web::Query<CheckEmailQuery>,
) -> Result<HttpResponse, ApiError> {
    let email = q.email.trim();
    if email.is_empty() {
        return Err(ApiError::BadRequest("email wajib diisi".into()));
    }
    let exists: Option<(u64,)> = sqlx::query_as("SELECT id FROM users WHERE email = ? LIMIT 1")
        .bind(email)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| ApiError::Internal(format!("DB error: {e}")))?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "exists": exists.is_some() })))
}

pub async fn login(
    state: web::Data<AppState>,
    body: web::Json<LoginRequest>,
) -> Result<HttpResponse, ApiError> {
    let LoginRequest { email, password } = body.into_inner();

    let user: Option<User> = sqlx::query_as::<_, User>(
        r#"
        SELECT id, name, email, password_hash, CAST(created_at AS DATETIME) AS created_at
        FROM users
        WHERE email = ? LIMIT 1
        "#,
    )
    .bind(&email)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(format!("DB error: {e}")))?;

    let user = match user {
        Some(u) => u,
        None => return Err(ApiError::Unauthorized("Email tidak ditemukan".into())),
    };

    if password.trim().is_empty() {
        if user.password_hash.trim().is_empty() {
            return Ok(HttpResponse::Accepted().json(serde_json::json!({
                "license_required": true,
                "email": user.email
            })));
        } else {
            return Err(ApiError::BadRequest("Password wajib diisi".into()));
        }
    }

    let ok = verify_password(&password, &user.password_hash)
        .map_err(|e| ApiError::Internal(format!("Verify error: {e}")))?;
    if !ok {
        return Err(ApiError::Unauthorized("Password salah".into()));
    }

    let exp = (chrono::Utc::now() + chrono::Duration::hours(12)).timestamp() as usize;
    let claims = Claims { sub: user.id, email: user.email.clone(), exp, lk: None };
    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(state.jwt_secret.as_bytes()))
        .map_err(|e| ApiError::Internal(format!("JWT error: {e}")))?;

    let public = UserPublic::from(user);
    Ok(HttpResponse::Ok().json(TokenResponse { token, user: public }))
}

pub async fn license_generate(
    state: web::Data<AppState>,
    body: web::Json<LicenseGenerateRequest>,
) -> Result<HttpResponse, ApiError> {
    let email = body.email.trim();
    if email.is_empty() {
        return Err(ApiError::BadRequest("email wajib diisi".into()));
    }

    let exists: Option<(u64,)> = sqlx::query_as("SELECT id FROM users WHERE email = ? LIMIT 1")
        .bind(email)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| ApiError::Internal(format!("DB error: {e}")))?;
    if exists.is_none() {
        return Err(ApiError::NotFound("User tidak ditemukan".into()));
    }

    let mut buf = [0u8; 16];
    OsRng.fill_bytes(&mut buf);
    let key_code = to_hex(&buf);

    sqlx::query(
        r#"
        INSERT INTO license_keys (key_code, user_email, used)
        VALUES (?, ?, 0)
        "#,
    )
    .bind(&key_code)
    .bind(email)
    .execute(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(format!("DB insert error: {e}")))?;

    let out = LicenseKeyPublic {
        key_code,
        email: email.to_string(),
        used: false,
        created_at: chrono::Utc::now().naive_utc().format("%Y-%m-%d %H:%M:%S").to_string(),
    };
    Ok(HttpResponse::Created().json(out))
}

pub async fn license_verify(
    state: web::Data<AppState>,
    body: web::Json<LicenseVerifyRequest>,
) -> Result<HttpResponse, ApiError> {
    let email = body.email.trim();
    let key = body.key.trim();

    if email.is_empty() || key.is_empty() {
        return Err(ApiError::BadRequest("email dan key wajib diisi".into()));
    }

    let user: Option<User> = sqlx::query_as::<_, User>(
        r#"
        SELECT id, name, email, password_hash, CAST(created_at AS DATETIME) AS created_at
        FROM users
        WHERE email = ? LIMIT 1
        "#,
    )
    .bind(email)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(format!("DB error: {e}")))?;
    let user = match user {
        Some(u) => u,
        None => return Err(ApiError::NotFound("User tidak ditemukan".into())),
    };

    let row: Option<(u64, bool, String, Option<chrono::NaiveDateTime>)> = sqlx::query_as(
        r#"SELECT id, used, user_email, used_at FROM license_keys WHERE key_code = ? LIMIT 1"#,
    )
    .bind(key)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(format!("DB error: {e}")))?;

    let Some((_key_id, used, key_email, _used_at)) = row else {
        return Err(ApiError::Unauthorized("License key tidak valid".into()));
    };
    if used {
        return Err(ApiError::Unauthorized("License key sudah digunakan".into()));
    }
    if key_email != email {
        return Err(ApiError::Unauthorized("License key tidak cocok dengan email".into()));
    }

    let exp = (chrono::Utc::now() + chrono::Duration::minutes(30)).timestamp() as usize;
    let claims = Claims {
        sub: user.id,
        email: user.email.clone(),
        exp,
        lk: Some(key.to_string()),
    };
    let token = jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )
    .map_err(|e| ApiError::Internal(format!("JWT error: {e}")))?;

    Ok(HttpResponse::Ok().json(TokenResponse { token, user: UserPublic::from(user) }))
}

pub async fn set_password(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<SetPasswordRequest>,
) -> Result<HttpResponse, ApiError> {
    let Some(authz) = req.headers().get("authorization") else {
        return Err(ApiError::Unauthorized("Missing Authorization header".into()));
    };
    let authz = authz.to_str().unwrap_or_default();
    if !authz.to_lowercase().starts_with("bearer ") {
        return Err(ApiError::Unauthorized("Invalid Authorization scheme".into()));
    }
    let token = authz[7..].trim();

    let decoding = jsonwebtoken::DecodingKey::from_secret(state.jwt_secret.as_bytes());
    let validation = jsonwebtoken::Validation::default();
    let data = jsonwebtoken::decode::<Claims>(token, &decoding, &validation)
        .map_err(|_| ApiError::Unauthorized("Invalid token".into()))?;

    let Some(key_code) = data.claims.lk.clone() else {
        return Err(ApiError::Unauthorized("License session diperlukan".into()));
    };

    let pwd = body.password.trim();
    if pwd.len() < 6 {
        return Err(ApiError::BadRequest("Password minimal 6 karakter".into()));
    }

    let user_id = data.claims.sub;

    let user_row: Option<(String, String)> = sqlx::query_as(
        r#"SELECT email, password_hash FROM users WHERE id = ? LIMIT 1"#,
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(format!("DB select error: {e}")))?;
    let (email, current_hash) = match user_row {
        Some(v) => v,
        None => return Err(ApiError::NotFound("User tidak ditemukan".into())),
    };
    if !current_hash.trim().is_empty() {
        return Err(ApiError::BadRequest("Password sudah diatur.".into()));
    }

    let hashed = hash_password(pwd).map_err(|e| ApiError::Internal(format!("Hash error: {e}")))?;

    let mut tx = state.pool.begin().await.map_err(|e| ApiError::Internal(format!("DB begin error: {e}")))?;

    let upd1 = sqlx::query(r#"UPDATE users SET password_hash = ? WHERE id = ?"#)
        .bind(&hashed)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::Internal(format!("DB update user error: {e}")))?;
    if upd1.rows_affected() != 1 {
        return Err(ApiError::Internal("Update password gagal".into()));
    }

    let upd2 = sqlx::query(
        r#"UPDATE license_keys SET used = 1, used_at = NOW()
           WHERE key_code = ? AND user_email = ? AND used = 0"#,
    )
    .bind(&key_code)
    .bind(&email)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::Internal(format!("DB update license error: {e}")))?;
    if upd2.rows_affected() != 1 {
        return Err(ApiError::BadRequest("License key tidak valid atau sudah digunakan".into()));
    }

    tx.commit().await.map_err(|e| ApiError::Internal(format!("DB commit error: {e}")))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "ok": true })))
}

pub async fn me(state: web::Data<AppState>, req: HttpRequest) -> Result<HttpResponse, ApiError> {
    let Some(authz) = req.headers().get("authorization") else {
        return Err(ApiError::Unauthorized("Missing Authorization header".into()));
    };
    let authz = authz.to_str().unwrap_or_default();
    if !authz.to_lowercase().starts_with("bearer ") {
        return Err(ApiError::Unauthorized("Invalid Authorization scheme".into()));
    }
    let token = authz[7..].trim();

    let decoding = jsonwebtoken::DecodingKey::from_secret(state.jwt_secret.as_bytes());
    let validation = jsonwebtoken::Validation::default();
    let data = jsonwebtoken::decode::<Claims>(token, &decoding, &validation)
        .map_err(|_| ApiError::Unauthorized("Invalid token".into()))?;

    let user: Option<User> = sqlx::query_as::<_, User>(
        r#"
        SELECT id, name, email, password_hash, CAST(created_at AS DATETIME) AS created_at
        FROM users
        WHERE id = ? LIMIT 1
        "#,
    )
    .bind(data.claims.sub)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(format!("DB error: {e}")))?;

    match user {
        Some(u) => Ok(HttpResponse::Ok().json(UserPublic::from(u))),
        None => Err(ApiError::NotFound("User not found".into())),
    }
}
