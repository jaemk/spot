use async_mutex::Mutex;
use cached::stores::TimedCache;
use cached::Cached;
use slog::o;
use slog::Drain;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::io::Read;
use std::sync::Arc;
use std::{env, fs};

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
    pub static ref LOG: slog::Logger = BASE_LOG.new(slog::o!("app" => "dev"));

    // state cache
    pub static ref STATE_KEYS: Arc<Mutex<TimedCache<String, ()>>> = Arc::new(Mutex::new(TimedCache::with_lifespan(30)));
}

#[derive(serde::Deserialize)]
pub struct Config {
    pub version: String,
    pub ssl: bool,
    pub host: String,
    pub port: u16,
    pub log_format: String,
    pub log_level: String,
    pub spotify_client_id: String,
    pub spotify_secret_id: String,
    pub db_url: String,
    pub enc_key: String,
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
        format!("{}/auth", self.host())
    }
}

#[derive(Debug, serde::Deserialize)]
struct Auth {
    code: String,
    state: String,
}

async fn new_state_token() -> String {
    let s = uuid::Uuid::new_v4()
        .to_simple()
        .encode_lower(&mut uuid::Uuid::encode_buffer())
        .to_string();
    let mut lock = STATE_KEYS.lock().await;
    lock.cache_set(s.clone(), ());
    s
}

async fn is_valid_state(s: String) -> bool {
    let mut lock = STATE_KEYS.lock().await;
    lock.cache_remove(&s).is_some()
}

async fn login(_req: tide::Request<Context>) -> tide::Result {
    let token = new_state_token().await;
    slog::info!(
        LOG,
        "redirecting to spotify with token {}, url {}",
        token,
        CONFIG.spotify_redirect_url()
    );
    Ok(tide::Redirect::new(
        format!("https://accounts.spotify.com/authorize?client_id={id}&response_type=code&redirect_uri={redirect}&scope={scope}&state={state}",
                 id = CONFIG.spotify_client_id,
                 redirect = CONFIG.spotify_redirect_url(),
                 scope = "user-read-private user-read-email user-read-recently-played",
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
    hex::encode(bytes)
}

#[derive(sqlx::FromRow, Debug)]
struct User {
    id: i64,
    email: String,
    name: String,
    scopes: Vec<String>,
    access_token: String,
    access_nonce: String,
    refresh_token: String,
    refresh_nonce: String,
    access_expires: i64,
    auth_token: String,
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
    let access_expires = std::time::SystemTime::now()
        .checked_add(std::time::Duration::from_secs(access.expires_in - 60))
        .expect("invalid time")
        .duration_since(std::time::UNIX_EPOCH)
        .expect("invalid duration")
        .as_secs() as i64;

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
        users (
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
        access_expires = excluded.access_expires, auth_token = excluded.auth_token 
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
    let ctx = req.state();
    let auth: Auth = req.query().expect("query parse error");
    if !is_valid_state(auth.state.clone()).await {
        return Ok(tide::Response::builder(400)
            .body(serde_json::json!({
                "error": format!("invalid login token {}", auth.state)
            }))
            .build());
    }
    slog::info!(LOG, "new auth"; "token" => &auth.state);
    let access = new_access_token(&auth.code).await.expect("access error");

    slog::info!(LOG, "new access {:?}", access);
    let name_email = get_new_user_name_email(&access)
        .await
        .expect("error getting name error");
    let new_auth_token = get_new_auth_token(&name_email.email);

    let user = upsert_user(&ctx.pool, &access, &name_email, &new_auth_token)
        .await
        .expect("user upsert error");
    slog::info!(LOG, "user: {:?}", user);
    Ok(serde_json::json!({
        "ok": "ok",
        "user.id": user.id,
        "user.display_name": &user.name,
        "user.email": &user.email,
        "auth_token": &new_auth_token,
    })
    .into())
}

fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("invalid duration")
        .as_secs() as i64
}

async fn get_user_access_token(pool: &PgPool, user: &User) -> String {
    if user.access_expires <= now_seconds() {
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
    let user = sqlx::query_as!(
        User,
        "
        update users set access_token = $1, access_nonce = $2 where id = $3 returning *
        ",
        &enc_access.value,
        &enc_access.nonce,
        &user.id,
    )
    .fetch_one(pool)
    .await
    .expect("db error");
    access.access_token
}

struct Track;

async fn get_history(user: &User) -> Vec<Track> {
    vec![]
}

async fn recent(req: tide::Request<Context>) -> tide::Result {
    // let ctx = req.state();
    Ok(serde_json::json!({
        "ok": "ok",
        "recent": "",
    })
    .into())
}

#[derive(Clone)]
struct Context {
    pool: sqlx::PgPool,
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    CONFIG.initialize()?;
    // tide::log::start();
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&CONFIG.db_url)
        .await?;
    let ctx = Context { pool };
    let mut app = tide::with_state(ctx);
    app.at("/login").get(login);
    app.at("/auth").get(auth);
    app.at("/recent").get(recent);
    app.with(tide::log::LogMiddleware::new());
    app.listen(CONFIG.host()).await?;
    Ok(())
}
