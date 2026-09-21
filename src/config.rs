//! /etc/vantage.toml — optional. Without it, probe cannot tell the zone edge
//! from any other drop, and says so.

use serde::Deserialize;

pub const PATH: &str = "/etc/vantage.toml";

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Log prefix of the host's forward-drop rule, without the trailing ": ".
    pub drop_log_prefix: Option<String>,
}

pub fn parse(s: &str) -> Result<Config, String> {
    toml::from_str(s).map_err(|e| format!("{PATH}: {e}"))
}

pub fn load() -> Result<Config, String> {
    match std::fs::read_to_string(PATH) {
        Ok(s) => parse(&s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(format!("{PATH}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_and_refuses_unknown_keys() {
        assert_eq!(
            parse("drop_log_prefix = \"x\"\n")
                .unwrap()
                .drop_log_prefix
                .as_deref(),
            Some("x")
        );
        assert!(parse("").unwrap().drop_log_prefix.is_none());
        assert!(parse("drop_prefix = \"x\"\n").is_err());
    }
}
