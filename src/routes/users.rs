use actix_web::{web, HttpResponse};
use regex::Regex;
use rand::{rngs::OsRng, RngCore};

use crate::{
    errors::ApiError,
    models::{AppState, CreateUserRequest, OfficeUserPublic, OfficeUserRow},
};

fn validate_email(s: &str) -> bool {
    let re = Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").expect("email regex");
    re.is_match(s)
}

fn normalize_role(s: &str) -> Option<&'static str> {
    match s.trim().to_lowercase().as_str() {
        "superadmin" => Some("superadmin"),
        "pegawaikantor" => Some("pegawaikantor"),
        "pegawaigudang" => Some("pegawaigudang"),
        _ => None,
    }
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

pub async fn create_user(
    state: web::Data<AppState>,
    body: web::Json<CreateUserRequest>,
) -> Result<HttpResponse, ApiError> {
    let name = body.name.trim();
    let email = body.email.trim();
    let role = normalize_role(&body.roles).ok_or_else(|| ApiError::BadRequest("roles invalid".into()))?;

    if name.is_empty() {
        return Err(ApiError::BadRequest("name wajib diisi".into()));
    }
    if email.is_empty() || !validate_email(email) {
        return Err(ApiError::BadRequest("email tidak valid".into()));
    }

    let mut tx = state.pool.begin().await.map_err(|e| ApiError::Internal(format!("DB begin error: {e}")))?;

    let empty_hash = "";

    let result = sqlx::query(
        r#"
        INSERT INTO users (name, email, password_hash, roles)
        VALUES (?, ?, ?, ?)
        "#,
    )
    .bind(name)
    .bind(email)
    .bind(empty_hash)
    .bind(role)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(db_err) = &e {
            if db_err.code().as_deref() == Some("23000") {
                return ApiError::Conflict("email sudah terdaftar".into());
            }
        }
        ApiError::Internal(format!("DB insert error: {e}"))
    })?;

    let id = result.last_insert_id();

    let mut buf = [0u8; 16];
    OsRng.fill_bytes(&mut buf);
    let license_key = to_hex(&buf);

    sqlx::query(
        r#"
        INSERT INTO license_keys (key_code, user_email, used)
        VALUES (?, ?, 0)
        "#,
    )
    .bind(&license_key)
    .bind(email)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::Internal(format!("DB license insert error: {e}")))?;

    let row: OfficeUserRow = sqlx::query_as::<_, OfficeUserRow>(
        r#"
        SELECT
            id,
            email,
            name,
            roles,
            CAST(created_at AS DATETIME) AS created_at
        FROM users
        WHERE id = ? LIMIT 1
        "#,
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| ApiError::Internal(format!("DB select error: {e}")))?;

    tx.commit().await.map_err(|e| ApiError::Internal(format!("DB commit error: {e}")))?;

    let out = OfficeUserPublic {
        id: row.id,
        email: row.email,
        name: row.name,
        roles: row.roles,
        created_at: row.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
        license_key: Some(license_key),
    };

    Ok(HttpResponse::Created().json(out))
}
