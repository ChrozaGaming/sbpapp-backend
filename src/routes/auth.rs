use actix_web::{web, HttpRequest, HttpResponse};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use crate::{
    errors::ApiError,
    models::{AppState, LoginRequest, RegisterRequest, TokenResponse, User, UserPublic},
    security::{hash_password, verify_password},
};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: u64,
    email: String,
    exp: usize,
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

    let hashed = hash_password(&password)
        .map_err(|e| ApiError::Internal(format!("Hash error: {e}")))?;

    let result = sqlx::query(
        r#"INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)"#,
    )
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

pub async fn login(
    state: web::Data<AppState>,
    body: web::Json<LoginRequest>,
) -> Result<HttpResponse, ApiError> {
    let LoginRequest { email, password } = body.into_inner();

    // ⬇️ CAST created_at → DATETIME agar cocok dgn NaiveDateTime
    let user: Option<User> = sqlx::query_as::<_, User>(
        r#"
        SELECT
            id, name, email, password_hash,
            CAST(created_at AS DATETIME) AS created_at
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

    let ok = verify_password(&password, &user.password_hash)
        .map_err(|e| ApiError::Internal(format!("Verify error: {e}")))?;
    if !ok {
        return Err(ApiError::Unauthorized("Password salah".into()));
    }

    let exp = (chrono::Utc::now() + chrono::Duration::hours(12)).timestamp() as usize;
    let claims = Claims { sub: user.id, email: user.email.clone(), exp };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )
    .map_err(|e| ApiError::Internal(format!("JWT error: {e}")))?;

    let public = UserPublic::from(user);
    Ok(HttpResponse::Ok().json(TokenResponse { token, user: public }))
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
        SELECT
            id, name, email, password_hash,
            CAST(created_at AS DATETIME) AS created_at
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
