use std::io::Read;
use std::sync::Arc;
use std::{env, fs};

use async_mutex::Mutex;
use cached::stores::TimedCache;
use slog::o;
use slog::Drain;
use sqlx::postgres::PgPoolOptions;

mod crypto;
mod logging;
mod models;
mod service;
mod spotify;
mod utils;

pub type Error = Box<dyn std::error::Error>;

#[derive(Debug)]
struct StringError(String);
impl std::fmt::Display for StringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "error: {}", self.0)
    }
}
impl std::error::Error for StringError {}

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
    pub static ref LOG: slog::Logger = BASE_LOG.new(slog::o!("app" => "soundlog"));

    // state cache
    pub static ref ONE_TIME_TOKENS: Arc<Mutex<TimedCache<String, ()>>> = Arc::new(Mutex::new(TimedCache::with_lifespan(30)));
}

// build a string error
#[macro_export]
macro_rules! se {
    ($($arg:tt)*) => {{ crate::StringError(format!($($arg)*))}};
}

#[macro_export]
macro_rules! json_resp {
    ($obj:expr) => {{
        tide::Response::builder(200)
            .content_type("application/json")
            .body(serde_json::to_string(&$obj)?)
            .build()
    }};
}

#[derive(serde::Deserialize)]
pub struct Config {
    pub version: String,
    pub ssl: bool,
    pub host: String,
    pub real_hostname: Option<String>,
    pub real_domain: Option<String>,
    pub port: u16,
    pub log_format: String,
    pub log_level: String,
    pub spotify_client_id: String,
    pub spotify_secret_id: String,
    pub db_url: String,
    pub enc_key: String,
    pub auth_expiration_seconds: u32,
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
            real_domain: env::var("REAL_DOMAIN").ok(),
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
            // 60 * 24 * 30
            auth_expiration_seconds: env_or("AUTH_EXPIRATION_SECONDS", "43200")
                .parse()
                .expect("invalid auth_expiration_seconds"),
            poll_interval_seconds: env_or("POLL_INTERVAL_SECONDS", "10")
                .parse()
                .expect("invalid poll_interval_seconds"),
        }
    }
    pub fn initialize(&self) {
        slog::info!(
            LOG, "initialized config";
            "version" => &CONFIG.version,
            "ssl" => &CONFIG.ssl,
            "host" => &CONFIG.host,
            "real_hostname" => &CONFIG.real_hostname,
            "real_domain" => &CONFIG.real_domain,
            "port" => &CONFIG.port,
            "log_format" => &CONFIG.log_format,
            "log_level" => &CONFIG.log_level,
            "auth_expiration_seconds" => &CONFIG.auth_expiration_seconds,
            "poll_interval_seconds" => &CONFIG.poll_interval_seconds,
        );
    }
    pub fn host(&self) -> String {
        let p = if self.ssl { "https" } else { "http" };
        format!("{}://{}:{}", p, self.host, self.port)
    }
    pub fn redirect_host(&self) -> String {
        self.real_hostname.clone().unwrap_or_else(|| self.host())
    }
    pub fn spotify_redirect_url(&self) -> String {
        format!("{}/auth", self.redirect_host())
    }
    pub fn domain(&self) -> String {
        self.real_domain
            .clone()
            .unwrap_or_else(|| self.host.clone())
    }
}

#[async_std::main]
async fn main() -> Result<()> {
    // try sourcing a .env and server/.env if either exist
    dotenv::dotenv().ok();
    dotenv::from_path(
        std::env::current_dir()
            .map(|p| p.join("server/.env"))
            .unwrap(),
    )
    .ok();
    CONFIG.initialize();

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&CONFIG.db_url)
        .await?;
    async_std::task::spawn(service::background_currently_playing_poll(pool.clone()));
    service::start(pool.clone()).await?;
    Ok(())
}
