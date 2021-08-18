use sqlx::PgPool;

use crate::{crypto, models, se, utils, CONFIG, LOG};

#[derive(serde::Deserialize, Debug)]
pub struct SpotifyAccess {
    pub access_token: String,
    pub token_type: String,
    pub scope: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
}

#[derive(serde::Serialize)]
struct SpotifyAccessParams {
    grant_type: String,
    code: String,
    redirect_uri: String,
}

impl SpotifyAccessParams {
    fn from_code(code: &str) -> Self {
        SpotifyAccessParams {
            grant_type: "authorization_code".to_string(),
            code: code.to_string(),
            redirect_uri: CONFIG.spotify_redirect_url(),
        }
    }
}

pub async fn new_spotify_access_token(code: &str) -> crate::Result<SpotifyAccess> {
    let auth = base64::encode(
        format!("{}:{}", CONFIG.spotify_client_id, CONFIG.spotify_secret_id).as_bytes(),
    );
    let mut resp = surf::post("https://accounts.spotify.com/api/token")
        .body(
            surf::Body::from_form(&SpotifyAccessParams::from_code(code))
                .map_err(|e| se!("form error {}", e))?,
        )
        .header("authorization", format!("Basic {}", auth))
        .send()
        .await
        .map_err(|e| format!("account request error {:?}", e))?;
    let access: SpotifyAccess = resp
        .body_json()
        .await
        .map_err(|e| se!("json parse error {}", e))?;
    Ok(access)
}

#[derive(serde::Serialize)]
struct RefreshParams {
    grant_type: String,
    refresh_token: String,
}

impl RefreshParams {
    fn from_token(token: &str) -> Self {
        RefreshParams {
            grant_type: "refresh_token".to_string(),
            refresh_token: token.to_string(),
        }
    }
}

pub async fn refresh_access_token(refresh_token: &str) -> crate::Result<SpotifyAccess> {
    let auth = base64::encode(
        format!("{}:{}", CONFIG.spotify_client_id, CONFIG.spotify_secret_id).as_bytes(),
    );
    let body = surf::Body::from_form(&RefreshParams::from_token(refresh_token))
        .map_err(|_| "error generating form data from refresh params")?;
    let mut resp = surf::post("https://accounts.spotify.com/api/token")
        .body(body)
        .header("authorization", format!("Basic {}", auth))
        .send()
        .await
        .map_err(|e| format!("account refresh request error {:?}", e))?;
    let access: serde_json::Value = resp
        .body_json()
        .await
        .map_err(|e| format!("account refresh json parse to value error {:?}", e))?;
    slog::info!(LOG, "refresh data: {:?}", access);
    let access: SpotifyAccess = serde_json::from_value(access)
        .map_err(|e| format!("account refresh json parse error {:?}", e))?;
    Ok(access)
}

#[derive(serde::Deserialize)]
pub struct SpotifyNameEmail {
    pub display_name: String,
    pub email: String,
}

pub async fn get_new_user_name_email(access: &SpotifyAccess) -> crate::Result<SpotifyNameEmail> {
    let mut resp = surf::get("https://api.spotify.com/v1/me")
        .header("authorization", format!("Bearer {}", access.access_token))
        .send()
        .await
        .map_err(|e| se!("get user error {}", e))?;
    Ok(resp
        .body_json()
        .await
        .map_err(|e| se!("json error {}", e))?)
}

pub fn spotify_expiry_seconds_to_epoch_expiration(expires_in: u64) -> crate::Result<i64> {
    let now = std::time::SystemTime::now();
    Ok(now
        .checked_add(std::time::Duration::from_secs(expires_in - 60))
        .ok_or_else(|| format!("can't add {:?} to time {:?}", expires_in - 60, now))?
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("invalid duration {:?}", e))?
        .as_secs() as i64)
}

pub async fn get_currently_playing(
    pool: &PgPool,
    user: &models::User,
) -> crate::Result<Option<serde_json::Value>> {
    let access_token = get_user_access_token(pool, user).await?;
    let mut resp = surf::get("https://api.spotify.com/v1/me/player/currently-playing")
        .header("authorization", format!("Bearer {}", access_token))
        .send()
        .await
        .map_err(|e| format!("get currently playing error {:?}", e))?;
    if resp.status() == tide::StatusCode::NoContent {
        return Ok(None);
    }
    let resp: serde_json::Value = resp
        .body_json()
        .await
        .map_err(|e| format!("get currently playing json error {:?}", e))?;
    Ok(Some(resp))
}

pub async fn get_user_access_token(pool: &PgPool, user: &models::User) -> crate::Result<String> {
    if user.access_expires > utils::now_seconds()? {
        return crypto::decrypt(&crypto::Enc {
            value: user.access_token.clone(),
            nonce: user.access_nonce.clone(),
        });
    }

    slog::info!(LOG, "refreshing access token for user {}", &user.id);
    let refresh_token = crypto::decrypt(&crypto::Enc {
        value: user.refresh_token.clone(),
        nonce: user.refresh_nonce.clone(),
    })?;

    let access = refresh_access_token(&refresh_token).await?;
    let enc_access = crypto::encrypt(&access.access_token)?;
    let access_expires = spotify_expiry_seconds_to_epoch_expiration(access.expires_in - 60)?;
    sqlx::query_as!(
        models::User,
        "
        update spot.users set access_token = $1, access_nonce = $2, access_expires = $3, modified = now() where id = $4 returning *
        ",
        &enc_access.value,
        &enc_access.nonce,
        &access_expires,
        &user.id,
    )
        .fetch_one(pool)
        .await
        .map_err(|e| se!("db error {}", e))?;

    Ok(access.access_token)
}

pub async fn get_history(pool: &PgPool, user: &models::User) -> crate::Result<serde_json::Value> {
    let access_token = get_user_access_token(pool, user).await?;
    let mut resp = surf::get("https://api.spotify.com/v1/me/player/recently-played?limit=50")
        .header("authorization", format!("Bearer {}", access_token))
        .send()
        .await
        .map_err(|e| format!("get history error {:?}", e))?;
    let resp: serde_json::Value = resp
        .body_json()
        .await
        .map_err(|e| format!("get history json error {:?}", e))?;
    Ok(resp)
}
