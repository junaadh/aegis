use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue};
use time::Duration;

pub fn set_session_cookie(headers: &mut HeaderMap, token: &str, max_age: Duration) {
    let age_secs = max_age.whole_seconds().max(0);
    let value = format!(
        "aegis_session={token}; HttpOnly; Secure; SameSite=Strict; Path=/v1; Max-Age={age_secs}"
    );
    if let Ok(hv) = HeaderValue::from_str(&value) {
        headers.append(SET_COOKIE, hv);
    }
}

pub fn clear_session_cookie(headers: &mut HeaderMap) {
    let value = "aegis_session=; HttpOnly; Secure; SameSite=Strict; Path=/v1; Max-Age=0";
    if let Ok(hv) = HeaderValue::from_str(value) {
        headers.append(SET_COOKIE, hv);
    }
}
