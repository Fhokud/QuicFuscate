//! Canonical environment variable utilities.
//! Single source of truth for all env flag/parse operations across the codebase.

/// Parse an env var as a boolean flag.
/// Returns `true` for "1", "true", "yes", "on" (case-insensitive).
/// Returns `default` if the variable is unset.
/// Returns `false` for all other values.
#[inline]
pub fn env_flag(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(raw) => matches!(raw.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => default,
    }
}

/// Parse an env var into any `FromStr` type. Returns `None` if unset or unparseable.
#[inline]
pub fn env_parse<T: std::str::FromStr>(name: &str) -> Option<T> {
    std::env::var(name).ok().and_then(|v| v.trim().parse::<T>().ok())
}

/// Try multiple env var names in order, return the first that is set.
#[inline]
pub fn env_first<const N: usize>(names: [&str; N]) -> Option<String> {
    names.into_iter().find_map(|name| std::env::var(name).ok())
}

/// Parse a boolean from a string value.
/// Returns `Some(true)` for "1"/"true"/"yes"/"on", `Some(false)` for "0"/"false"/"no"/"off", `None` otherwise.
#[inline]
pub fn parse_bool(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_flag_truthy_values() {
        for val in ["1", "true", "TRUE", "True", "yes", "YES", "on", "ON"] {
            std::env::set_var("TEST_ENV_FLAG_TRUE", val);
            assert!(env_flag("TEST_ENV_FLAG_TRUE", false), "expected true for {val}");
            std::env::remove_var("TEST_ENV_FLAG_TRUE");
        }
    }

    #[test]
    fn env_flag_falsy_values() {
        for val in ["0", "false", "FALSE", "no", "off", "random", ""] {
            std::env::set_var("TEST_ENV_FLAG_FALSE", val);
            assert!(!env_flag("TEST_ENV_FLAG_FALSE", true), "expected false for {val}");
            std::env::remove_var("TEST_ENV_FLAG_FALSE");
        }
    }

    #[test]
    fn env_flag_unset_returns_default() {
        std::env::remove_var("TEST_ENV_FLAG_UNSET");
        assert!(env_flag("TEST_ENV_FLAG_UNSET", true));
        assert!(!env_flag("TEST_ENV_FLAG_UNSET", false));
    }

    #[test]
    fn env_flag_trims_whitespace() {
        std::env::set_var("TEST_ENV_FLAG_WS", "  true  ");
        assert!(env_flag("TEST_ENV_FLAG_WS", false));
        std::env::remove_var("TEST_ENV_FLAG_WS");
    }

    #[test]
    fn env_parse_numeric() {
        std::env::set_var("TEST_ENV_PARSE_NUM", "42");
        assert_eq!(env_parse::<u32>("TEST_ENV_PARSE_NUM"), Some(42));
        std::env::remove_var("TEST_ENV_PARSE_NUM");
    }

    #[test]
    fn env_parse_unset() {
        std::env::remove_var("TEST_ENV_PARSE_UNSET");
        assert_eq!(env_parse::<u32>("TEST_ENV_PARSE_UNSET"), None);
    }

    #[test]
    fn env_parse_invalid() {
        std::env::set_var("TEST_ENV_PARSE_BAD", "not_a_number");
        assert_eq!(env_parse::<u32>("TEST_ENV_PARSE_BAD"), None);
        std::env::remove_var("TEST_ENV_PARSE_BAD");
    }

    #[test]
    fn env_first_finds_first_set() {
        std::env::remove_var("TEST_EF_A");
        std::env::set_var("TEST_EF_B", "found");
        assert_eq!(env_first(["TEST_EF_A", "TEST_EF_B"]), Some("found".to_string()));
        std::env::remove_var("TEST_EF_B");
    }

    #[test]
    fn env_first_none_if_all_unset() {
        std::env::remove_var("TEST_EF_X");
        std::env::remove_var("TEST_EF_Y");
        assert_eq!(env_first(["TEST_EF_X", "TEST_EF_Y"]), None);
    }

    #[test]
    fn parse_bool_values() {
        assert_eq!(parse_bool("1"), Some(true));
        assert_eq!(parse_bool("true"), Some(true));
        assert_eq!(parse_bool("yes"), Some(true));
        assert_eq!(parse_bool("on"), Some(true));
        assert_eq!(parse_bool("0"), Some(false));
        assert_eq!(parse_bool("false"), Some(false));
        assert_eq!(parse_bool("no"), Some(false));
        assert_eq!(parse_bool("off"), Some(false));
        assert_eq!(parse_bool("maybe"), None);
        assert_eq!(parse_bool(""), None);
    }
}
