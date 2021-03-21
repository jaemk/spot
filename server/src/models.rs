#[derive(sqlx::FromRow, Debug, serde::Serialize)]
pub struct Track {
    pub id: i64,
    pub spotify_id: String,
    pub name: String,
    pub artist_names: Vec<String>,
    pub created: chrono::DateTime<chrono::Utc>,
    pub modified: chrono::DateTime<chrono::Utc>,
    // exists, but we don't really need it for anything right now
    // raw: serde_json::Value,
}

#[derive(sqlx::FromRow, Debug, serde::Serialize)]
pub struct Play {
    pub id: i64,
    pub user_id: i64,
    pub spotify_id: String,
    pub played_at: chrono::DateTime<chrono::Utc>,
    pub played_at_minute: chrono::DateTime<chrono::Utc>,
    pub name: String,
    pub artist_names: Vec<String>,
    pub created: chrono::DateTime<chrono::Utc>,
    pub modified: chrono::DateTime<chrono::Utc>,
}

#[derive(sqlx::FromRow, Debug, serde::Serialize)]
pub struct NewPlay {
    pub id: i64,
    pub created: chrono::DateTime<chrono::Utc>,
    pub modified: chrono::DateTime<chrono::Utc>,
}

#[derive(sqlx::FromRow, Debug, serde::Serialize)]
pub struct PlaySummary {
    pub date: Option<chrono::NaiveDate>,
    pub count: Option<i64>,
}

#[derive(sqlx::FromRow, Debug, serde::Serialize)]
pub struct User {
    pub id: i64,
    // email reported by spotify, we're assuming this is unique
    // since it's the account email of the spotify account.
    pub email: String,
    // name reported by spotify
    pub name: String,
    // the spotify scopes available to the access_token
    pub scopes: Vec<String>,
    // a spotify access token that can be used to access
    // the spotify user's info. This value is AWS_256_GCM
    // encrypted using the application secret set in the
    // current environment and the `access_nonce` generated
    // when the value was originally encrypted.
    pub access_token: String,
    pub access_nonce: String,
    // a spotify token that can be used to refresh the spotify
    // user's access_token. This is encrypted and stored the
    // same way as the actual access_token.
    pub refresh_token: String,
    pub refresh_nonce: String,
    // timestamp in seconds from epoch when the current
    // spotify access_token expires
    pub access_expires: i64,
    pub created: chrono::DateTime<chrono::Utc>,
    pub modified: chrono::DateTime<chrono::Utc>,

    // This has been deprecated in favor of multiple tokens
    // saved in the auth_tokens table.
    pub auth_token: String,
}

#[derive(sqlx::FromRow, Debug, serde::Serialize)]
pub struct AuthToken {
    pub id: i64,
    // a user's (of this application) authentication token
    // that is set as cookie on a user's session. This value
    // stored is the hmac (and hex encoded) string of the
    // actual token returned to the user.
    pub hash: String,
    pub user_id: i64,
    pub expires: chrono::DateTime<chrono::Utc>,
    pub created: chrono::DateTime<chrono::Utc>,
    pub modified: chrono::DateTime<chrono::Utc>,
}
