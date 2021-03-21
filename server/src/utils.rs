use crate::Result;
use chrono::offset::Utc;
use chrono::{DateTime, Timelike};

pub fn truncate_to_minute(dt: DateTime<Utc>) -> Result<DateTime<Utc>> {
    Ok(dt
        .with_nanosecond(0)
        .ok_or_else(|| format!("error setting nanoseconds to zero: {:?}", dt))?
        .with_second(0)
        .ok_or_else(|| format!("error setting seconds to zero: {:?}", dt))?)
}

pub fn now_seconds() -> Result<i64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("invalid duration {:?}", e))?
        .as_secs() as i64)
}
