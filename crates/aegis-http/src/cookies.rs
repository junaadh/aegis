use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue};
use aegis_config::{CookieConfig, SameSite};
use time::Duration;

pub fn set_session_cookie(
    headers: &mut HeaderMap,
    cookie: &CookieConfig,
    token: &str,
    max_age: Duration,
) {
    let age_secs = max_age.whole_seconds().max(0);
    let mut parts = vec![
        format!("{}={token}", cookie.name),
        format!("Path={}", cookie.path),
        format!("Max-Age={age_secs}"),
        format!(
            "SameSite={}",
            match cookie.same_site {
                SameSite::Strict => "Strict",
                SameSite::Lax => "Lax",
                SameSite::None => "None",
            }
        ),
    ];

    if cookie.http_only {
        parts.push("HttpOnly".to_owned());
    }
    if cookie.secure {
        parts.push("Secure".to_owned());
    }
    if let Some(domain) = &cookie.domain {
        parts.push(format!("Domain={domain}"));
    }

    let value = parts.join("; ");
    if let Ok(hv) = HeaderValue::from_str(&value) {
        headers.append(SET_COOKIE, hv);
    }
}

pub fn clear_session_cookie(headers: &mut HeaderMap, cookie: &CookieConfig) {
    let mut parts = vec![
        format!("{}=", cookie.name),
        format!("Path={}", cookie.path),
        "Max-Age=0".to_owned(),
        format!(
            "SameSite={}",
            match cookie.same_site {
                SameSite::Strict => "Strict",
                SameSite::Lax => "Lax",
                SameSite::None => "None",
            }
        ),
    ];

    if cookie.http_only {
        parts.push("HttpOnly".to_owned());
    }
    if cookie.secure {
        parts.push("Secure".to_owned());
    }
    if let Some(domain) = &cookie.domain {
        parts.push(format!("Domain={domain}"));
    }

    let value = parts.join("; ");
    if let Ok(hv) = HeaderValue::from_str(&value) {
        headers.append(SET_COOKIE, hv);
    }
}
