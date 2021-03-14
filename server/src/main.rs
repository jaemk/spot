use async_mutex::Mutex;
use cached::stores::TimedCache;
use cached::Cached;
use chrono::{TimeZone, Timelike};
use slog::o;
use slog::Drain;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::io::Read;
use std::sync::Arc;
use std::{env, fs};
use surf::StatusCode;

mod crypto;

pub type Error = Box<dyn std::error::Error>;
pub type Result<T> = std::result::Result<T, Error>;

fn env_or(k: &str, default: &str) -> String {
    env::var(k).unwrap_or_else(|_| default.to_string())
}

lazy_static::lazy_static! {
    pub static ref CONFIG: Config = Config::load();

    // The "base" logger that all crates should branch off of
    pub static ref BASE_LOG: slog::Logger = {
        let level: slog::Level = CONFIG.log_level
                .parse()
                .expect("invalid log_level");
        if CONFIG.log_format == "pretty" {
            let decorator = slog_term::TermDecorator::new().build();
            let drain = slog_term::CompactFormat::new(decorator).build().fuse();
            let drain = slog_async::Async::new(drain).build().fuse();
            let drain = slog::LevelFilter::new(drain, level).fuse();
            slog::Logger::root(drain, o!())
        } else {
            let drain = slog_json::Json::default(std::io::stderr()).fuse();
            let drain = slog_async::Async::new(drain).build().fuse();
            let drain = slog::LevelFilter::new(drain, level).fuse();
            slog::Logger::root(drain, o!())
        }
    };

    // Base logger
    pub static ref LOG: slog::Logger = BASE_LOG.new(slog::o!("app" => "spistorfy"));

    // state cache
    pub static ref STATE_KEYS: Arc<Mutex<TimedCache<String, ()>>> = Arc::new(Mutex::new(TimedCache::with_lifespan(30)));
}

#[derive(serde::Deserialize)]
pub struct Config {
    pub version: String,
    pub ssl: bool,
    pub host: String,
    pub real_hostname: Option<String>,
    pub port: u16,
    pub log_format: String,
    pub log_level: String,
    pub spotify_client_id: String,
    pub spotify_secret_id: String,
    pub db_url: String,
    pub enc_key: String,
    pub poll_interval_seconds: u64,
}
impl Config {
    pub fn load() -> Self {
        let version = fs::File::open("commit_hash.txt")
            .map(|mut f| {
                let mut s = String::new();
                f.read_to_string(&mut s).expect("Error reading commit_hasg");
                s
            })
            .unwrap_or_else(|_| "unknown".to_string());
        Self {
            version,
            ssl: env_or("SSL", "false") == "true",
            host: env_or("HOST", "localhost"),
            real_hostname: env::var("REAL_HOSTNAME").ok(),
            port: env_or("PORT", "3030").parse().expect("invalid port"),
            log_format: env_or("LOG_FORMAT", "json")
                .to_lowercase()
                .trim()
                .to_string(),
            log_level: env_or("LOG_LEVEL", "INFO"),
            spotify_client_id: env_or("SPOTIFY_CLIENT_ID", "fake"),
            spotify_secret_id: env_or("SPOTIFY_SECRET_ID", "fake"),
            db_url: env_or("DATABASE_URL", "error"),
            enc_key: env_or("ENC_KEY", "01234567890123456789012345678901"),
            poll_interval_seconds: env_or("POLL_INTERVAL_SECONDS", "10")
                .parse()
                .expect("invalid poll_interval_seconds"),
        }
    }
    pub fn initialize(&self) -> anyhow::Result<()> {
        slog::info!(
            LOG, "initialized config";
            "version" => &CONFIG.version,
            "ssl" => &CONFIG.ssl,
            "host" => &CONFIG.host,
            "port" => &CONFIG.port,
            "log_format" => &CONFIG.log_format,
            "log_level" => &CONFIG.log_level,
        );
        Ok(())
    }
    pub fn host(&self) -> String {
        let p = if self.ssl { "https" } else { "http" };
        format!("{}://{}:{}", p, self.host, self.port)
    }
    pub fn spotify_redirect_url(&self) -> String {
        let host = self.real_hostname.unwrap_or_else(|| self.host());
        format!("{}/auth", host)
    }
    pub fn domain(&self) -> String {
        self.host.clone()
    }
}

#[derive(Debug, serde::Deserialize)]
struct Auth {
    code: String,
    state: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Token {
    token: String,
    redirect: Option<String>,
}

async fn new_state_token(redirect: Option<String>) -> String {
    let s = uuid::Uuid::new_v4()
        .to_simple()
        .encode_lower(&mut uuid::Uuid::encode_buffer())
        .to_string();
    let s = serde_json::to_string(&Token { token: s, redirect }).expect("token json error");
    let s = base64::encode(&s);
    let mut lock = STATE_KEYS.lock().await;
    lock.cache_set(s.clone(), ());
    s
}

async fn is_valid_state(s: String) -> bool {
    let mut lock = STATE_KEYS.lock().await;
    lock.cache_remove(&s).is_some()
}

#[derive(serde::Deserialize)]
struct MaybeRedirect {
    redirect: Option<String>,
}

async fn login(req: tide::Request<Context>) -> tide::Result {
    let maybe_redirect: MaybeRedirect = req.query().expect("query parse error");
    let token = new_state_token(maybe_redirect.redirect.clone()).await;
    slog::info!(
        LOG,
        "redirecting to spotify auth with token {}, post-redirect-redirect {:?}",
        token,
        maybe_redirect.redirect,
    );
    Ok(tide::Redirect::new(
        format!("https://accounts.spotify.com/authorize?client_id={id}&response_type=code&redirect_uri={redirect}&scope={scope}&state={state}",
                 id = CONFIG.spotify_client_id,
                 redirect = CONFIG.spotify_redirect_url(),
                 scope = "user-read-private user-read-email user-read-recently-played user-read-currently-playing",
                 state = token)
    ).into())
}

#[derive(serde::Deserialize, Debug)]
struct Access {
    access_token: String,
    token_type: String,
    scope: String,
    expires_in: u64,
    refresh_token: Option<String>,
}

#[derive(serde::Serialize)]
struct AccessParams {
    grant_type: String,
    code: String,
    redirect_uri: String,
}
impl AccessParams {
    fn from_code(code: &str) -> Self {
        AccessParams {
            grant_type: "authorization_code".to_string(),
            code: code.to_string(),
            redirect_uri: CONFIG.spotify_redirect_url(),
        }
    }
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

async fn new_access_token(code: &str) -> anyhow::Result<Access> {
    let auth = base64::encode(
        format!("{}:{}", CONFIG.spotify_client_id, CONFIG.spotify_secret_id).as_bytes(),
    );
    let mut resp = surf::post("https://accounts.spotify.com/api/token")
        .body(surf::Body::from_form(&AccessParams::from_code(code)).expect("form error"))
        .header("authorization", format!("Basic {}", auth))
        .send()
        .await
        .expect("account request error");
    let access: Access = resp.body_json().await.expect("json parse error");
    Ok(access)
}

async fn refresh_access_token(refresh_token: &str) -> anyhow::Result<Access> {
    let auth = base64::encode(
        format!("{}:{}", CONFIG.spotify_client_id, CONFIG.spotify_secret_id).as_bytes(),
    );
    let mut resp = surf::post("https://accounts.spotify.com/api/token")
        .body(surf::Body::from_form(&RefreshParams::from_token(refresh_token)).expect("form error"))
        .header("authorization", format!("Basic {}", auth))
        .send()
        .await
        .expect("account refresh request error");
    let access: Access = resp.body_json().await.expect("json parse error");
    Ok(access)
}

struct Enc {
    value: String,
    nonce: String,
}

fn encrypt(s: &str) -> Enc {
    let nonce = crypto::new_nonce().expect("error generating nonce");
    let b =
        crypto::encrypt(s.as_bytes(), &nonce, CONFIG.enc_key.as_bytes()).expect("encryption error");
    let value = hex::encode(&b);
    let nonce = hex::encode(&nonce);
    Enc { value, nonce }
}

fn decrypt(enc: &Enc) -> String {
    let nonce = hex::decode(&enc.nonce).expect("nonce hex decode error");
    let mut value = hex::decode(&enc.value).expect("value hex decode error");
    let bytes = crypto::decrypt(value.as_mut_slice(), &nonce, CONFIG.enc_key.as_bytes())
        .expect("encryption error");
    String::from_utf8(bytes.to_owned()).unwrap()
}

#[derive(sqlx::FromRow, Debug, serde::Serialize)]
struct User {
    id: i64,
    // email reported by spotify, we're assuming this is unique
    // since it's the account email of the spotify account.
    email: String,
    // name reported by spotify
    name: String,
    // the spotify scopes available to the access_token
    scopes: Vec<String>,
    // a spotify access token that can be used to access
    // the spotify user's info. This value is AWS_256_GCM
    // encrypted using the application secret set in the
    // current environment and the `access_nonce` generated
    // when the value was originally encrypted.
    access_token: String,
    access_nonce: String,
    // a spotify token that can be used to refresh the spotify
    // user's access_token. This is encrypted and stored the
    // same way as the actual access_token.
    refresh_token: String,
    refresh_nonce: String,
    // timestamp in seconds from epoch when the current
    // spotify access_token expires
    access_expires: i64,
    // a user's (of this application) authentication token
    // that is set as cookie on a user's session. This value
    // stored is the hmac (and hex encoded) string of the
    // actual token returned to the user.
    auth_token: String,
    created: chrono::DateTime<chrono::Utc>,
    modified: chrono::DateTime<chrono::Utc>,
}

#[derive(serde::Deserialize)]
struct NameEmail {
    display_name: String,
    email: String,
}

async fn get_new_user_name_email(access: &Access) -> anyhow::Result<NameEmail> {
    let mut resp = surf::get("https://api.spotify.com/v1/me")
        .header("authorization", format!("Bearer {}", access.access_token))
        .send()
        .await
        .expect("get user error");
    Ok(resp.body_json().await.expect("json error"))
}

fn get_new_auth_token(email: &str) -> String {
    let s = uuid::Uuid::new_v4()
        .to_simple()
        .encode_lower(&mut uuid::Uuid::encode_buffer())
        .to_string();
    let s = format!("{}:{}", email, s);
    let b = crypto::hash(s.as_bytes());
    hex::encode(&b)
}

async fn upsert_user(
    pool: &PgPool,
    access: &Access,
    name_email: &NameEmail,
    new_auth_token: &str,
) -> anyhow::Result<User> {
    let scopes = access
        .scope
        .split_whitespace()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    let access_expires = spotify_expiry_seconds_to_epoch_expiration(access.expires_in - 60);

    let access_token = encrypt(&access.access_token);
    let refresh_token = encrypt(
        &access
            .refresh_token
            .as_ref()
            .expect("missing refresh token"),
    );
    let auth_token = crypto::hmac_sign(new_auth_token);
    let user = sqlx::query_as!(
        User,
        "
        insert into 
        spot.users (
            email, name, scopes,
            access_token, access_nonce,
            refresh_token, refresh_nonce,
            access_expires,
            auth_token
        ) 
        values ($1, $2, $3, $4, $5, $6, $7, $8, $9) 
        on conflict (email) do update set name = excluded.name, scopes = excluded.scopes, 
        access_token = excluded.access_token, access_nonce = excluded.access_nonce, 
        refresh_token = excluded.refresh_token, refresh_nonce = excluded.refresh_nonce, 
        access_expires = excluded.access_expires, auth_token = excluded.auth_token, 
        modified = now()
        returning *
        ",
        &name_email.email,
        &name_email.display_name,
        scopes.as_slice(),
        &access_token.value,
        &access_token.nonce,
        &refresh_token.value,
        &refresh_token.nonce,
        &access_expires,
        &auth_token,
    )
    .fetch_one(pool)
    .await
    .expect("db error");
    Ok(user)
}

async fn auth(req: tide::Request<Context>) -> tide::Result {
    slog::info!(LOG, "got login redirect");
    let ctx = req.state();
    let auth: Auth = req.query().expect("query parse error");
    if !is_valid_state(auth.state.clone()).await {
        return Ok(tide::Response::builder(400)
            .body(serde_json::json!({
                "error": format!("invalid login token {}", auth.state)
            }))
            .build());
    }
    let token_bytes = base64::decode(&auth.state).expect("decode error");
    let token_str = String::from_utf8(token_bytes).expect("token utf8 error");
    let token: Token = serde_json::from_str(&token_str).expect("deserialize token error");

    let access = new_access_token(&auth.code).await.expect("access error");
    let name_email = get_new_user_name_email(&access)
        .await
        .expect("error getting name error");
    let new_auth_token = get_new_auth_token(&name_email.email);

    let user = upsert_user(&ctx.pool, &access, &name_email, &new_auth_token)
        .await
        .expect("user upsert error");
    slog::info!(LOG, "completing user login: {}", user.id);

    let cookie_str = format!(
        "auth_token={token}; Domain={domain}; HttpOnly; Max-Age={max_age}",
        token = &new_auth_token,
        domain = &CONFIG.domain(),
        max_age = 60 * 24 * 30,
    );

    if let Some(redirect) = token.redirect {
        if !redirect.contains("login") {
            slog::info!(LOG, "found login redirect {:?}", redirect);
            let mut resp: tide::Response =
                tide::Redirect::new(format!("{}{}", CONFIG.host(), redirect)).into();
            resp.insert_header("set-cookie", cookie_str);
            return Ok(resp);
        }
    }
    Ok(tide::Response::builder(200)
        .header("set-cookie", cookie_str)
        .body(serde_json::json!({
        "ok": "ok",
        "user.id": user.id,
        "user.display_name": &user.name,
        "user.email": &user.email,
        "auth_token": &new_auth_token,
        }))
        .build())
}

fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("invalid duration")
        .as_secs() as i64
}

fn spotify_expiry_seconds_to_epoch_expiration(expires_in: u64) -> i64 {
    std::time::SystemTime::now()
        .checked_add(std::time::Duration::from_secs(expires_in - 60))
        .expect("invalid time")
        .duration_since(std::time::UNIX_EPOCH)
        .expect("invalid duration")
        .as_secs() as i64
}

async fn get_user_access_token(pool: &PgPool, user: &User) -> String {
    if user.access_expires > now_seconds() {
        return decrypt(&Enc {
            value: user.access_token.clone(),
            nonce: user.access_nonce.clone(),
        });
    }

    slog::info!(LOG, "refreshing access token for user {}", &user.id);
    let refresh_token = decrypt(&Enc {
        value: user.refresh_token.clone(),
        nonce: user.refresh_nonce.clone(),
    });

    let access = refresh_access_token(&refresh_token)
        .await
        .expect("refresh token failure");
    let enc_access = encrypt(&access.access_token);
    let access_expires = spotify_expiry_seconds_to_epoch_expiration(access.expires_in - 60);
    sqlx::query_as!(
        User,
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
    .expect("db error");

    access.access_token
}

#[derive(sqlx::FromRow, Debug, serde::Serialize)]
struct Play {
    id: i64,
    user_id: i64,
    spotify_id: String,
    played_at: chrono::DateTime<chrono::Utc>,
    played_at_minute: chrono::DateTime<chrono::Utc>,
    name: String,
    created: chrono::DateTime<chrono::Utc>,
    modified: chrono::DateTime<chrono::Utc>,
    raw: serde_json::Value,
}

#[derive(sqlx::FromRow, Debug, serde::Serialize)]
struct NewPlay {
    id: i64,
    created: chrono::DateTime<chrono::Utc>,
    modified: chrono::DateTime<chrono::Utc>,
}

async fn get_history(pool: &PgPool, user: &User) -> serde_json::Value {
    let access_token = get_user_access_token(pool, user).await;
    let mut resp = surf::get(format!(
        "https://api.spotify.com/v1/me/player/recently-played?limit=50",
    ))
    .header("authorization", format!("Bearer {}", access_token))
    .send()
    .await
    .expect("get history error");
    let resp: serde_json::Value = resp.body_json().await.expect("json error");
    resp
}

async fn get_currently_playing(pool: &PgPool, user: &User) -> Option<serde_json::Value> {
    let access_token = get_user_access_token(pool, user).await;
    let mut resp = surf::get(format!(
        "https://api.spotify.com/v1/me/player/currently-playing",
    ))
    .header("authorization", format!("Bearer {}", access_token))
    .send()
    .await
    .expect("get currently playing error");
    if resp.status() == StatusCode::NoContent {
        return None;
    }
    let resp: serde_json::Value = resp.body_json().await.expect("json error");
    Some(resp)
}

async fn recent(req: tide::Request<Context>) -> tide::Result {
    let user = get_auth_user(&req).await;
    if user.is_none() {
        let path = req.url().path();
        return Ok(
            tide::Redirect::new(format!("{}/login?redirect={}", CONFIG.host(), path)).into(),
        );
    }
    let user = user.unwrap();
    let ctx = req.state();
    let history = sqlx::query_as!(
        Play,
        "select * from spot.plays where user_id = $1 order by played_at desc",
        &user.id
    )
    .fetch_all(&ctx.pool)
    .await
    .expect("error getting plays for user");

    Ok(serde_json::json!({
        "ok": "ok",
        "recent": history,
    })
    .into())
}

async fn get_auth_user(req: &tide::Request<Context>) -> Option<User> {
    let ctx = req.state();
    match req.cookie("auth_token") {
        None => {
            slog::info!(LOG, "no auth token cookie found");
            None
        }
        Some(cookie) => {
            let token = cookie.value();
            let hash = crypto::hmac_sign(token);
            let u = sqlx::query_as!(
                User,
                "select * from spot.users where auth_token = $1",
                &hash
            )
            .fetch_one(&ctx.pool)
            .await
            .ok();
            slog::debug!(LOG, "current user {:?}", u);
            u
        }
    }
}

async fn background_recently_played_poll(pool: PgPool) {
    async_std::task::sleep(std::time::Duration::from_secs(
        CONFIG.poll_interval_seconds * 2,
    ))
    .await;
    loop {
        let users = sqlx::query_as!(User, "select * from spot.users")
            .fetch_all(&pool)
            .await
            .expect("error getting users");
        slog::info!(
            LOG,
            "recently played poll users {:?}",
            users
                .iter()
                .map(|u| u.email.as_str())
                .collect::<Vec<&str>>()
        );
        for user in &users {
            let mut new_plays = vec![];
            let recent = get_history(&pool, user).await;
            for item in recent["items"].as_array().unwrap() {
                // played_at is the "play end" time so we have to subtract the
                // track duration to get the probable "start time"
                let played_at = item["played_at"]
                    .as_str()
                    .unwrap()
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .unwrap();
                let duration_ms =
                    chrono::Duration::milliseconds(item["track"]["duration_ms"].as_i64().unwrap());
                let played_at = played_at - duration_ms;
                let played_at_minute = played_at
                    .with_nanosecond(0)
                    .unwrap()
                    .with_second(0)
                    .unwrap();
                let spotify_id = item["track"]["id"].as_str().unwrap();
                let name = item["track"]["name"].as_str().unwrap();
                let probably_exists = sqlx::query_scalar!(
                    "
                    select count(*) from spot.plays
                    where user_id = $1 and spotify_id = $2 and
                          tstzrange(
                             spot.plays.played_at_minute - interval '1 min',
                             spot.plays.played_at_minute + interval '1 min',
                             '[]'
                          ) &&
                          tstzrange(
                             $3::timestamptz - interval '1 min',
                             $3::timestamptz + interval '1 min',
                             '[]'
                          )
                    ",
                    &user.id,
                    spotify_id,
                    played_at_minute,
                )
                .fetch_one(&pool)
                .await
                .expect("failed to count plays in time range")
                .unwrap();
                if probably_exists == 0 {
                    let new_play = sqlx::query_as!(
                        NewPlay,
                        "
                        insert into spot.plays
                        (user_id, spotify_id, played_at, played_at_minute, name, raw)
                        values
                        ($1, $2, $3, $4, $5, $6)
                        on conflict (user_id, spotify_id, played_at_minute) do update set modified = now()
                        returning id, created, modified
                        ",
                        &user.id,
                        spotify_id,
                        played_at,
                        played_at_minute,
                        name,
                        item,
                    )
                        .fetch_one(&pool)
                        .await
                        .expect("failed to insert play");
                    if new_play.created == new_play.modified {
                        new_plays.push(new_play.id);
                    }
                }
            }
            if !new_plays.is_empty() {
                slog::info!(LOG, "inserted new plays {:?}", new_plays);
            }
        }
        async_std::task::sleep(std::time::Duration::from_secs(
            CONFIG.poll_interval_seconds * 10,
        ))
        .await;
    }
}

async fn background_currently_playing_poll(pool: PgPool) {
    loop {
        async_std::task::sleep(std::time::Duration::from_secs(CONFIG.poll_interval_seconds)).await;
        let users = sqlx::query_as!(User, "select * from spot.users")
            .fetch_all(&pool)
            .await
            .expect("error getting users");
        slog::info!(
            LOG,
            "currently playing poll users {:?}",
            users
                .iter()
                .map(|u| u.email.as_str())
                .collect::<Vec<&str>>()
        );
        for user in &users {
            if let Some(current) = get_currently_playing(&pool, user).await {
                // timestamp is that "play start" time. this value seems like
                // it gets updated whenever you pause or unpause the current track.
                let start_millis = current["timestamp"].as_i64().unwrap();
                let played_at = chrono::Utc.timestamp_millis(start_millis);
                let played_at_minute = played_at
                    .with_nanosecond(0)
                    .unwrap()
                    .with_second(0)
                    .unwrap();
                let spotify_id = current["item"]["id"].as_str().unwrap();
                let name = current["item"]["name"].as_str().unwrap();
                let latest = sqlx::query_as!(
                    Play,
                    "
                    select * from spot.plays where user_id = $1
                    order by played_at desc
                    limit 1
                    ",
                    &user.id,
                )
                .fetch_optional(&pool)
                .await
                .expect("failed fetching optional latest play");
                if latest.is_some() && latest.unwrap().spotify_id == spotify_id {
                    slog::debug!(
                        LOG,
                        "{} currently listening to {} (no change)",
                        &user.email,
                        name
                    );
                } else {
                    let new_play = sqlx::query_as!(
                        NewPlay,
                        "
                        insert into spot.plays
                        (user_id, spotify_id, played_at, played_at_minute, name, raw)
                        values
                        ($1, $2, $3, $4, $5, $6)
                        on conflict (user_id, spotify_id, played_at_minute) do update set modified = now()
                        returning id, created, modified
                        ",
                        &user.id,
                        spotify_id,
                        played_at,
                        played_at_minute,
                        name,
                        current,
                    )
                    .fetch_one(&pool)
                    .await
                    .expect("failed to insert play");
                    if new_play.created == new_play.modified {
                        slog::info!(LOG, "{} new current song {}", &user.email, name);
                    } else {
                        slog::info!(LOG, "{} currently listening to {}", &user.email, name);
                    }
                }
            };
        }
    }
}

async fn index(_req: tide::Request<Context>) -> tide::Result {
    slog::info!(LOG, "index redirecting to /recent");
    let resp: tide::Response = tide::Redirect::new(format!("{}/recent", CONFIG.host())).into();
    return Ok(resp);
}

#[derive(Clone)]
struct Context {
    pool: sqlx::PgPool,
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    // try sourcing a .env and server/.env if either exist
    dotenv::dotenv().ok();
    dotenv::from_path(
        std::env::current_dir()
            .map(|p| p.join("server/.env"))
            .unwrap(),
    )
    .ok();
    CONFIG.initialize()?;

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&CONFIG.db_url)
        .await?;
    async_std::task::spawn(background_currently_playing_poll(pool.clone()));
    async_std::task::spawn(background_recently_played_poll(pool.clone()));
    let ctx = Context { pool };
    let mut app = tide::with_state(ctx);
    app.at("/").get(index);
    app.at("/login").get(login);
    app.at("/auth").get(auth);
    app.at("/recent").get(recent);
    app.with(tide::log::LogMiddleware::new());

    slog::info!(LOG, "running at {}", CONFIG.host());
    app.listen(CONFIG.host()).await?;
    Ok(())
}
