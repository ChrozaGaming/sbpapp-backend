use actix_web::web;

pub mod auth;
pub mod absensi;

pub fn config_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("")
            .route("/health", web::get().to(health))
            .service(
                web::scope("/api")
                    .service(web::resource("/register").route(web::post().to(auth::register)))
                    .service(web::resource("/login").route(web::post().to(auth::login)))
                    .service(web::resource("/me").route(web::get().to(auth::me)))
                    .service(web::resource("/absensi").route(web::post().to(absensi::create_absensi))),
            ),
    );
}

async fn health() -> &'static str { "ok" }
