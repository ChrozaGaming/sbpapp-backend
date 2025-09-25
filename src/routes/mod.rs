use actix_web::{web, HttpResponse, Responder};

pub mod auth;
pub mod absensi;

pub fn config_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("")
            .route("/health", web::get().to(health))
            .service(
                web::scope("/api")
                    .route("/register", web::post().to(auth::register))
                    .route("/login", web::post().to(auth::login))
                    .route("/me", web::get().to(auth::me))
                    .route("/absensi", web::post().to(absensi::create_absensi)),
            ),
    );
}

async fn health() -> impl Responder {
    HttpResponse::Ok().body("ok")
}
