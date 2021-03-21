use cached::Cached;
use chrono::{Duration, TimeZone, Utc};
use sqlx::PgPool;

use crate::{crypto, json_resp, models, se, spotify, utils, Result, CONFIG, LOG};

#[derive(Clone)]
struct Context {
    pool: sqlx::PgPool,
}

pub async fn start(pool: sqlx::PgPool) -> crate::Result<()> {
    let ctx = Context { pool };
    let mut app = tide::with_state(ctx);
    app.at("/").get(index);
    app.at("/status").get(status);
    app.at("/login").get(login);
    app.at("/auth").get(auth_callback);
    app.at("/recent").get(recent);
    app.at("/summary").get(summary);
    app.with(crate::logging::LogMiddleware::new());

    slog::info!(LOG, "running at {}", crate::CONFIG.host());
    app.listen(crate::CONFIG.host()).await?;
    Ok(())
}

async fn index(_req: tide::Request<Context>) -> tide::Result {
    slog::info!(LOG, "index redirecting to /recent");
    let resp: tide::Response =
        tide::Redirect::new(format!("{}/recent", CONFIG.redirect_host())).into();
    return Ok(resp);
}

#[derive(serde::Serialize)]
struct Status<'a> {
    ok: &'a str,
    version: &'a str,
}

async fn status(_req: tide::Request<Context>) -> tide::Result {
    Ok(json_resp!(Status {
        ok: "ok",
        version: &CONFIG.version
    }))
}

/// The login process uses spotify to authenticate the current user
/// which then redirects back to our callback url with a code we
/// can use to generate reusable access and refresh API tokens.
async fn login(req: tide::Request<Context>) -> tide::Result {
    let maybe_redirect: MaybeRedirect = req.query().map_err(|e| se!("query parse error {}", e))?;
    let token = new_one_time_login_token(maybe_redirect.redirect.clone())
        .await
        .map_err(|e| se!("error generating new one time login token {}", e))?;
    slog::info!(
        LOG,
        "redirecting to spotify-auth with state token {}, post-redirect-redirect {:?}",
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

/// after we redirect users to spotify to login, spotify will send
/// them back to this endpoint. The request will have special
/// query parameters `code` and `state`. `code` is a single-use
/// token that can be used to retrieve a new pair of spotify API access
/// and refresh tokens. `state` is an arbitrary string that we sent
/// when sending the user to spotify - this is treated as a one-time-token
/// that we use to assert that this login attempt only happens once.
async fn auth_callback(req: tide::Request<Context>) -> tide::Result {
    slog::info!(LOG, "got login redirect");
    let ctx = req.state();
    let spotify_auth: SpotifyAuthCallback =
        req.query().map_err(|e| se!("query parse error: {:?}", e))?;
    if !is_valid_one_time_login_token(&spotify_auth).await {
        return Ok(tide::Response::builder(400)
            .body(serde_json::json!({
                "error": format!("invalid one-time login token {}", spotify_auth.state)
            }))
            .build());
    }
    let token_bytes = base64::decode(&spotify_auth.state).map_err(|e| se!("decode error {}", e))?;
    let token_str = String::from_utf8(token_bytes).map_err(|e| se!("token utf8 error {}", e))?;
    let login_token: OneTimeLoginToken =
        serde_json::from_str(&token_str).map_err(|e| se!("deserialize token error {}", e))?;

    let spotify_access = spotify::new_spotify_access_token(&spotify_auth.code)
        .await
        .map_err(|e| se!("spotify access error {}", e))?;
    let name_email = spotify::get_new_user_name_email(&spotify_access)
        .await
        .map_err(|e| se!("error getting name {}", e))?;
    let new_auth_token = get_new_auth_token(&name_email.email);

    let user = upsert_user(&ctx.pool, &spotify_access, &name_email, &new_auth_token)
        .await
        .map_err(|e| se!("user upsert error {}", e))?;
    let is_new = user.created == user.modified;
    slog::info!(LOG, "completing user login: {}", user.email; "user_id" => user.id, "is_new" => is_new);
    if is_new {
        slog::info!(LOG, "inserting recently played for new user {}", user.email);
        if let Err(e) = _recently_played_user(&ctx.pool, &user).await {
            slog::error!(
                LOG,
                "error loading recently played for new user {} {}",
                user.email,
                e
            )
        }
    }

    let cookie_str = format!(
        "auth_token={token}; Domain={domain}; Secure; HttpOnly; Max-Age={max_age}; SameSite=Lax",
        token = &new_auth_token,
        domain = &CONFIG.domain(),
        max_age = 60 * 24 * 30,
    );

    if let Some(redirect) = login_token.redirect {
        // the one time login token that we sent to spotify when
        // redirecting the user to spotify's auth might have had
        // a redirect url that we sent which was the url that the
        // user was originally trying to go to when we noticed
        // that they weren't logged in. If the url they were
        // trying to go to wasn't the login url, then redirect
        // them to it, otherwise just return the user info.
        if !redirect.contains("login") {
            slog::info!(LOG, "found login redirect {:?}", redirect);
            let mut resp: tide::Response =
                tide::Redirect::new(format!("{}{}", CONFIG.redirect_host(), redirect)).into();
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
        }))
        .build())
}

macro_rules! user_or_redirect {
    ($req:expr) => {{
        let user = get_auth_user(&$req).await;
        if user.is_none() {
            let path = $req.url().path();
            return Ok(tide::Redirect::new(format!(
                "{}/login?redirect={}",
                CONFIG.redirect_host(),
                path
            ))
            .into());
        }
        user.unwrap()
    }};
}

#[derive(serde::Serialize)]
struct RecentResponse {
    count: usize,
    recent: Vec<models::Play>,
}

async fn recent(req: tide::Request<Context>) -> tide::Result {
    let user = user_or_redirect!(req);
    let ctx = req.state();
    let recent = sqlx::query_as!(
        models::Play,
        "select * from spot.plays where user_id = $1 order by played_at desc",
        &user.id
    )
    .fetch_all(&ctx.pool)
    .await
    .map_err(|e| se!("error getting plays for user {} {}", user.id, e))?;

    Ok(json_resp!(RecentResponse {
        count: recent.len(),
        recent,
    }))
}

#[derive(serde::Serialize)]
struct SummaryResponse {
    summary: Vec<models::PlaySummary>,
}

async fn summary(req: tide::Request<Context>) -> tide::Result {
    let user = user_or_redirect!(req);
    let ctx = req.state();
    let summary = sqlx::query_as!(
        models::PlaySummary,
        "
        select played_at::date as date, count(*)
        from spot.plays
        where user_id = $1
        group by played_at::date
        order by played_at::date desc
        ",
        &user.id
    )
    .fetch_all(&ctx.pool)
    .await
    .map_err(|e| se!("error getting play summary for user {} {}", user.id, e))?;

    Ok(json_resp!(SummaryResponse { summary }))
}

#[derive(Debug, serde::Deserialize)]
struct SpotifyAuthCallback {
    code: String,
    state: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct OneTimeLoginToken {
    token: String,
    redirect: Option<String>,
}

async fn new_one_time_login_token(redirect: Option<String>) -> Result<String> {
    let s = uuid::Uuid::new_v4()
        .to_simple()
        .encode_lower(&mut uuid::Uuid::encode_buffer())
        .to_string();
    let s = serde_json::to_string(&OneTimeLoginToken { token: s, redirect })
        .map_err(|e| se!("token json error {}", e))?;
    let s = base64::encode_config(&s, base64::URL_SAFE);
    let mut lock = crate::ONE_TIME_TOKENS.lock().await;
    lock.cache_set(s.clone(), ());
    Ok(s)
}

async fn is_valid_one_time_login_token(auth: &SpotifyAuthCallback) -> bool {
    let mut lock = crate::ONE_TIME_TOKENS.lock().await;
    lock.cache_remove(&auth.state).is_some()
}

#[derive(serde::Deserialize)]
struct MaybeRedirect {
    redirect: Option<String>,
}

fn get_new_auth_token(email: &str) -> String {
    let s = uuid::Uuid::new_v4()
        .to_simple()
        .encode_lower(&mut uuid::Uuid::encode_buffer())
        .to_string();
    let s = format!("{}:{}", email, s);
    let b = crate::crypto::hash(s.as_bytes());
    hex::encode(&b)
}

async fn upsert_user(
    pool: &PgPool,
    access: &spotify::SpotifyAccess,
    name_email: &spotify::SpotifyNameEmail,
    new_auth_token: &str,
) -> Result<models::User> {
    let scopes = access
        .scope
        .split_whitespace()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    let access_expires =
        spotify::spotify_expiry_seconds_to_epoch_expiration(access.expires_in - 60)?;

    let access_token = crypto::encrypt(&access.access_token)?;
    let refresh_token = crypto::encrypt(
        &access
            .refresh_token
            .as_ref()
            .ok_or_else(|| se!("missing refresh token"))?,
    )?;
    let auth_token = crypto::hmac_sign(new_auth_token);
    let mut tr = pool
        .begin()
        .await
        .map_err(|e| format!("error starting user transaction {:?}", e))?;
    let user = sqlx::query_as!(
        models::User,
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
    .fetch_one(&mut tr)
    .await
    .map_err(|e| format!("error upserting user {:?}", e))?;
    let expires = Utc::now()
        .checked_add_signed(Duration::seconds(CONFIG.auth_expiration_seconds as i64))
        .ok_or("error creating expiration timestamp")?;
    sqlx::query!(
        "
        insert into
        spot.auth_tokens (
            hash, user_id, expires
        )
        values ($1, $2, $3)
        ",
        &auth_token,
        &user.id,
        &expires,
    )
    .execute(&mut tr)
    .await
    .map_err(|e| format!("failed to insert user auth token {:?}", e))?;
    tr.commit()
        .await
        .map_err(|e| format!("error committing user insert {:?}", e))?;

    Ok(user)
}

async fn get_auth_user(req: &tide::Request<Context>) -> Option<models::User> {
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
                models::User,
                "
                select u.*
                from spot.users u
                    inner join spot.auth_tokens at
                    on u.id = at.user_id
                where hash = $1 and expires > now()
                ",
                &hash,
            )
            .fetch_one(&ctx.pool)
            .await
            .ok();
            slog::debug!(LOG, "current user {:?}", u);
            if let Some(ref u) = u {
                sqlx::query!(
                    "delete from spot.auth_tokens where user_id = $1 and expires <= now()",
                    &u.id
                )
                .execute(&ctx.pool)
                .await
                .map_err(|e| {
                    format!(
                        "error deleting expired auth tokens for user {}, continuing: {:?}",
                        u.id, e
                    )
                })
                .ok();
            }
            u
        }
    }
}

async fn _recently_played_user(pool: &PgPool, user: &models::User) -> Result<()> {
    let mut new_plays = vec![];
    let recent = spotify::get_history(pool, user).await?;
    for item in recent["items"]
        .as_array()
        .ok_or_else(|| format!("items: unexpected shape {:?}", recent))?
    {
        // played_at is the "play end" time so we have to subtract the
        // track duration to get the probable "start time"
        let played_at = item["played_at"]
            .as_str()
            .ok_or_else(|| format!("played_at: unexpected shape {:?}", item))?
            .parse::<chrono::DateTime<chrono::Utc>>()
            .map_err(|e| format!("invalid datetime {:?}", e))?;
        let duration_ms = chrono::Duration::milliseconds(
            item["track"]["duration_ms"]
                .as_i64()
                .ok_or_else(|| format!("duration: unexpected shape {:?}", item))?,
        );
        let played_at = played_at - duration_ms;
        let played_at_minute = utils::truncate_to_minute(played_at)?;
        let spotify_id = item["track"]["id"]
            .as_str()
            .ok_or_else(|| format!("spotify_id: unexpected shape {:?}", item))?;
        let name = item["track"]["name"]
            .as_str()
            .ok_or_else(|| format!("track name: unexpected shape {:?}", item))?;
        let album_name = item["track"]["album"]["name"]
            .as_str()
            .ok_or_else(|| format!("currently playing album name: unexpected shape {:?}", item))?;
        let album_id = item["track"]["album"]["id"]
            .as_str()
            .ok_or_else(|| format!("currently playing album name: unexpected shape {:?}", item))?;
        let album_images = &item["track"]["album"]["images"];
        if album_images.is_null() {
            return Err(se!(
                "currently playing album images: unexpected shape {:?}",
                item
            )
            .into());
        }
        let mut artist_names = vec![];
        let mut artist_ids = vec![];
        for artist in item["track"]["artists"]
            .as_array()
            .ok_or_else(|| format!("track artists: unexpected shape {:?}", item))?
        {
            artist_names.push(
                artist["name"]
                    .as_str()
                    .ok_or_else(|| format!("artist name: unexpected shape {:?}", artist))?
                    .to_string(),
            );
            artist_ids.push(
                artist["id"]
                    .as_str()
                    .ok_or_else(|| format!("artist id: unexpected shape {:?}", artist))?
                    .to_string(),
            );
        }

        // Since we're inserting a chunk of 50 recent tracks, there's the
        // possibility that what we're trying to insert was already captured
        // by the "currently playing" poll.
        // Based on our estimated start-time, check if there's an existing play
        // immediately before or after our estimated time. If there is, then
        // we've already captured this playback, otherwise we should do an insert.
        // Note, that our estimated start-time can be quite off from the actual
        // start time due to pause/unpause or skipping around in the playback.
        // This only protects against having two duplicate plays adjacent in time,
        // but does not protect against you immediately skimming to the end of a 10m
        // song, causing us to think the play-start-time was 10m ago and inserting
        // a "play" that may not really make sense.
        struct Around {
            before: Option<String>,
            after: Option<String>,
        }
        let around_time = sqlx::query_as!(
            Around,
            "
            select
                (select spotify_id from spot.plays
                    where user_id = $1 and played_at <= $2
                    order by played_at desc limit 1) as before,
                (select spotify_id from spot.plays
                    where user_id = $1 and played_at >= $2
                    order by played_at asc limit 1) as after;
            ",
            &user.id,
            played_at_minute,
        )
        .fetch_one(pool)
        .await
        .map_err(|e| format!("failed to query before and after plays {:?}", e))?;
        let some_spotify_id = Some(spotify_id.to_string());
        let probably_exists =
            around_time.before == some_spotify_id || around_time.after == some_spotify_id;
        if !probably_exists {
            sqlx::query!(
                "
                insert into spot.tracks
                (spotify_id, name, artist_names, artist_ids, album_name, album_id, album_images)
                values
                ($1, $2, $3, $4, $5, $6, $7)
                on conflict (spotify_id) do update set
                name = excluded.name, artist_names = excluded.artist_names,
                artist_ids = excluded.artist_ids,
                album_name = excluded.album_name, album_id = excluded.album_id,
                album_images = excluded.album_images,
                modified = now()
                ",
                spotify_id,
                name,
                artist_names.as_slice(),
                artist_ids.as_slice(),
                album_name,
                album_id,
                album_images,
            )
            .execute(pool)
            .await
            .map_err(|e| format!("failed to upsert track {:?}", e))?;
            let new_play = sqlx::query_as!(
                models::NewPlay,
                "
                insert into spot.plays
                (user_id, spotify_id, played_at, played_at_minute, name, artist_names)
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
                artist_names.as_slice(),
            )
            .fetch_one(pool)
            .await
            .map_err(|e| format!("failed to insert play {:?}", e))?;
            if new_play.created == new_play.modified {
                new_plays.push(new_play.id);
            }
        }
    }
    if !new_plays.is_empty() {
        slog::info!(LOG, "inserted new plays {:?}", new_plays);
    }
    Ok(())
}

async fn _currently_playing_user(pool: &PgPool, user: &models::User) -> Result<()> {
    let current = spotify::get_currently_playing(pool, user).await?;
    if let Some(current) = current {
        // Non "track" things like podcasts, return a null item (track)
        // ignore these for now. They also don't appear to come back at all
        // from the recently-played API, but it's not mentioned in their
        // documentation whether that's intentional or not.
        if current["item"].is_null() {
            slog::debug!(
                LOG,
                "currently playing for user {:?} is not a track",
                user.id
            );
            return Ok(());
        }

        // timestamp is the "play start" time. This value seems like
        // it gets updated whenever you pause or unpause the current track
        // which means we need to dedupe against the current latest in
        // our db so we don't keep inserting plays when you pause/unpause.
        let start_millis = current["timestamp"].as_i64().ok_or_else(|| {
            format!(
                "currently playing timestamp: unexpected shape {:?}",
                current
            )
        })?;
        let played_at = chrono::Utc.timestamp_millis(start_millis);
        let played_at_minute = utils::truncate_to_minute(played_at)?;
        let spotify_id = current["item"]["id"].as_str().ok_or_else(|| {
            format!(
                "currently playing spotify_id: unexpected shape {:?}",
                current
            )
        })?;
        let name = current["item"]["name"]
            .as_str()
            .ok_or_else(|| format!("currently playing name: unexpected shape {:?}", current))?;
        let album_name = current["item"]["album"]["name"].as_str().ok_or_else(|| {
            format!(
                "currently playing album name: unexpected shape {:?}",
                current
            )
        })?;
        let album_id = current["item"]["album"]["id"].as_str().ok_or_else(|| {
            format!(
                "currently playing album name: unexpected shape {:?}",
                current
            )
        })?;
        let album_images = &current["item"]["album"]["images"];
        if album_images.is_null() {
            return Err(se!(
                "currently playing album images: unexpected shape {:?}",
                current
            )
            .into());
        }
        let mut artist_names = vec![];
        let mut artist_ids = vec![];
        for artist in current["item"]["artists"]
            .as_array()
            .ok_or_else(|| format!("currently playing artists: unexpected shape {:?}", current))?
        {
            artist_names.push(
                artist["name"]
                    .as_str()
                    .ok_or_else(|| {
                        format!(
                            "currently playing artist name: unexpected shape {:?}",
                            artist
                        )
                    })?
                    .to_string(),
            );
            artist_ids.push(
                artist["id"]
                    .as_str()
                    .ok_or_else(|| {
                        format!("currently playing artist id: unexpected shape {:?}", artist)
                    })?
                    .to_string(),
            );
        }
        let latest = sqlx::query_as!(
            models::Play,
            "
            select * from spot.plays where user_id = $1
            order by played_at desc
            limit 1
            ",
            &user.id,
        )
        .fetch_optional(pool)
        .await
        .map_err(|e| format!("failed fetching optional latest play {:?}", e))?;
        if latest.is_some() && latest.unwrap().spotify_id == spotify_id {
            slog::debug!(
                LOG,
                "{} currently listening to {} (no change)",
                &user.email,
                name
            );
        } else {
            sqlx::query!(
                "
                insert into spot.tracks
                (spotify_id, name, artist_names, artist_ids, album_name, album_id, album_images)
                values
                ($1, $2, $3, $4, $5, $6, $7)
                on conflict (spotify_id) do update set
                name = excluded.name, artist_names = excluded.artist_names,
                artist_ids = excluded.artist_ids,
                album_name = excluded.album_name, album_id = excluded.album_id,
                album_images = excluded.album_images,
                modified = now()
                ",
                spotify_id,
                name,
                artist_names.as_slice(),
                artist_ids.as_slice(),
                album_name,
                album_id,
                album_images
            )
            .execute(pool)
            .await
            .map_err(|e| format!("failed to upsert track {:?}", e))?;
            let new_play = sqlx::query_as!(
                models::NewPlay,
                "
                insert into spot.plays
                (user_id, spotify_id, played_at, played_at_minute, name, artist_names)
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
                artist_names.as_slice(),
            )
            .fetch_one(pool)
            .await
            .map_err(|e| format!("failed to insert play for user {:?} {:?}", user.id, e))?;
            if new_play.created == new_play.modified {
                slog::info!(LOG, "{} new current song {}", &user.email, name);
            }
        }
    };
    Ok(())
}

async fn _background_currently_playing_poll_inner(pool: &PgPool) -> Result<()> {
    let users = sqlx::query_as!(models::User, "select * from spot.users")
        .fetch_all(pool)
        .await
        .map_err(|e| format!("error getting users for poll {:?}", e))?;
    slog::info!(
        LOG,
        "currently playing poll users {:?}",
        users
            .iter()
            .map(|u| u.email.as_str())
            .collect::<Vec<&str>>()
    );
    for user in &users {
        if let Err(e) = _currently_playing_user(pool, user).await {
            slog::error!(
                LOG,
                "error polling currently playing for user {:?} {:?}",
                user,
                e
            );
        }
    }
    Ok(())
}

pub async fn background_currently_playing_poll(pool: PgPool) {
    loop {
        async_std::task::sleep(std::time::Duration::from_secs(CONFIG.poll_interval_seconds)).await;
        if let Err(e) = _background_currently_playing_poll_inner(&pool).await {
            slog::error!(
                LOG,
                "error while running background currently playing poll {:?}",
                e
            );
        }
    }
}
