use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use serde::Serialize;
use std::fmt::{self, Display};

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    Conflict(String),
    Internal(String),
}

impl Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::BadRequest(s) => write!(f, "Bad request: {}", s),
            ApiError::Unauthorized(s) => write!(f, "Unauthorized: {}", s),
            ApiError::Forbidden(s) => write!(f, "Forbidden: {}", s),
            ApiError::NotFound(s) => write!(f, "Not found: {}", s),
            ApiError::Conflict(s) => write!(f, "Conflict: {}", s),
            ApiError::Internal(s) => write!(f, "Internal server error: {}", s),
        }
    }
}

#[derive(Serialize)]
struct ErrorBody {
    message: String,
}

impl ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let body = ErrorBody {
            message: self.to_string(),
        };
        HttpResponse::build(self.status_code()).json(body)
    }
}
