use actix_web::{HttpRequest, HttpResponse};
use serde::Serialize;

#[derive(Serialize)]
struct DebugIp {
    peer_addr: Option<String>,
    x_forwarded_for: Option<String>,
    real_ip: Option<String>,
}

pub async fn show_ip(req: HttpRequest) -> HttpResponse {
    let peer = req.peer_addr().map(|a| a.to_string());
    let xff = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let real_ip = req
        .headers()
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    HttpResponse::Ok().json(DebugIp {
        peer_addr: peer,
        x_forwarded_for: xff,
        real_ip,
    })
}
