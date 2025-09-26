use actix_web::{web, HttpResponse, Responder};

pub mod auth;
pub mod absensi;
pub mod users;

pub fn config_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("")
            .route("/health", web::get().to(health))
            .service(
                web::scope("/api")
                    .route("/register", web::post().to(auth::register))
                    .route("/login", web::post().to(auth::login))
                    .route("/me", web::get().to(auth::me))
                    .route("/auth/check-email", web::get().to(auth::check_email))
                    .route("/auth/set-password", web::post().to(auth::set_password))
                    .route("/license/generate", web::post().to(auth::license_generate))
                    .route("/license/verify", web::post().to(auth::license_verify))
                    .route("/absensi/today", web::get().to(absensi::check_today_absen))
                    .route("/absensi", web::post().to(absensi::create_absensi))
                    .route("/users", web::post().to(users::create_user)),
            ),
    );
}

async fn health() -> impl Responder {
    HttpResponse::Ok().body("ok")
}
