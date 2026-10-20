//! The panel's requests, one JSON object per line on stdin. Strict: unknown
//! fields, types and versions are refused.

use serde::Deserialize;
use std::collections::BTreeMap;

/// 2 added `secrets` and `heldSecrets` to `exec`: a value that must not sit
/// in any child's environment.
pub const PROTOCOL: u8 = 2;
/// A save carries the item in `env`, and the list read's filter is the
/// longest script; 4 MiB is far past both.
pub const MAX_LINE: usize = 4 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum Request {
    Hello {
        v: u8,
    },
    /// Run `argv` as the panel would, with `BW_SESSION` or a held secret
    /// added to its environment by name (`inject`), and deal with its stdout
    /// as `capture` says.
    ///
    /// `secrets` and `heldSecrets` are values the run needs but which must
    /// not be in its environment, where every process of the same user can
    /// read them for the life of the run and of every child that inherits
    /// them: the master password, a PIN, a FIDO2 hmac-secret. They are
    /// written to the run's stdin ahead of `stdin`, as `NAME=value` records
    /// ended by NUL and closed by an empty record (`secret_block()`), for the
    /// shell to read into unexported variables. `secrets` are given values,
    /// `heldSecrets` name held ones as `inject` does. The block is written
    /// whenever `secrets` is present, even empty, so a script that reads one
    /// never waits on a stdin nobody writes.
    Exec {
        v: u8,
        id: u64,
        argv: Vec<String>,
        #[serde(default)]
        env: BTreeMap<String, Option<String>>,
        #[serde(default)]
        inject: BTreeMap<String, String>,
        #[serde(default)]
        secrets: Option<BTreeMap<String, String>>,
        #[serde(default, rename = "heldSecrets")]
        held_secrets: BTreeMap<String, String>,
        #[serde(default)]
        capture: Option<String>,
        #[serde(default)]
        stdin: Option<String>,
        /// Not tracked and not killed: outlives this helper (an unload's
        /// `bw lock`).
        #[serde(default)]
        detach: bool,
    },
    Kill {
        v: u8,
        id: u64,
    },
    /// Drop the session key, every item, and every held secret except those
    /// named in `keep` (a lock still running with its own copy of the key).
    Forget {
        v: u8,
        #[serde(default)]
        keep: Vec<String>,
    },
    /// Copy the session key into a named secret, so a run queued now (a
    /// lock) uses this key even after `forget` or a newer unlock.
    HoldSession {
        v: u8,
        name: String,
    },
    ForgetSecret {
        v: u8,
        name: String,
    },
    /// Drop one item, once the vault no longer has it (deleted or trashed):
    /// nothing else would, until the next full list.
    ForgetItem {
        v: u8,
        id: String,
    },
    /// One item in full, for the edit view.
    Item {
        v: u8,
        q: u64,
        id: String,
    },
    /// Put a login's password on the clipboard without it reaching the panel.
    CopyPassword {
        v: u8,
        q: u64,
        id: String,
        #[serde(rename = "clearSec")]
        clear_sec: u32,
    },
    /// One secret value of an item, for display while the user has it
    /// revealed. `field` names it (`store::SecretField`); anything not on
    /// that list is answered with a failure.
    Field {
        v: u8,
        q: u64,
        id: String,
        field: String,
    },
    /// As `copyPassword`, for any value `field` can name.
    CopyField {
        v: u8,
        q: u64,
        id: String,
        field: String,
        #[serde(rename = "clearSec")]
        clear_sec: u32,
    },
    Totp {
        v: u8,
        q: u64,
        id: String,
    },
    Search {
        v: u8,
        q: u64,
        query: String,
    },
    Shutdown {
        v: u8,
    },
}

impl Request {
    pub fn version(&self) -> u8 {
        match self {
            Self::Hello { v }
            | Self::Exec { v, .. }
            | Self::Kill { v, .. }
            | Self::Forget { v, .. }
            | Self::HoldSession { v, .. }
            | Self::ForgetSecret { v, .. }
            | Self::ForgetItem { v, .. }
            | Self::Item { v, .. }
            | Self::CopyPassword { v, .. }
            | Self::Field { v, .. }
            | Self::CopyField { v, .. }
            | Self::Totp { v, .. }
            | Self::Search { v, .. }
            | Self::Shutdown { v } => *v,
        }
    }
}

/// What to do with a run's stdout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Capture {
    /// Hand it to the panel.
    Plain,
    /// A session key (`bw unlock`, `bw login`, a remembered session): keep
    /// it; the panel learns only that there is one.
    Session,
    /// A vault read: keep the items, hand over the rest. Replaces the store.
    Vault,
    /// A saved item: as `Vault`, but updates only the items it names.
    VaultMerge,
    /// Keep stdout as a named secret.
    Secret(String),
    /// Stdout is the `D` data of a `pinentry` answer (the panel's pinentry
    /// script prints it still encoded): decode it and keep it as a named
    /// secret, only when the run exited 0. The panel is told nothing of it.
    Pinentry(String),
}

impl Capture {
    pub fn parse(value: Option<&str>) -> Option<Self> {
        match value.unwrap_or("plain") {
            "plain" => Some(Self::Plain),
            "session" => Some(Self::Session),
            "vault" => Some(Self::Vault),
            "vaultMerge" => Some(Self::VaultMerge),
            other => other
                .strip_prefix("secret:")
                .filter(|name| valid_name(name))
                .map(|name| Self::Secret(name.to_owned()))
                .or_else(|| {
                    other
                        .strip_prefix("pinentry:")
                        .filter(|name| valid_name(name))
                        .map(|name| Self::Pinentry(name.to_owned()))
                }),
        }
    }
}

/// A held value an `inject` entry names: `session` or `secret:<name>`.
pub enum Source<'a> {
    Session,
    Secret(&'a str),
}

pub fn parse_source(value: &str) -> Option<Source<'_>> {
    if value == "session" {
        return Some(Source::Session);
    }
    value
        .strip_prefix("secret:")
        .filter(|name| valid_name(name))
        .map(Source::Secret)
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

pub fn valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.as_bytes()[0].is_ascii_digit()
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// The stdin block carrying `records` to a run: `NAME=value` ended by NUL
/// each, then an empty record. A value never holds NUL (it came from JSON
/// text or a `bw` answer, both of which the helper reads as strings without
/// one), so the shell's `read -r -d ''` sees each record whole, newlines
/// and all.
pub fn secret_block<'a>(records: impl IntoIterator<Item = (&'a str, &'a str)>) -> Vec<u8> {
    let mut block = Vec::new();
    for (name, value) in records {
        block.extend_from_slice(name.as_bytes());
        block.push(b'=');
        block.extend_from_slice(value.as_bytes());
        block.push(0);
    }
    block.push(0);
    block
}

pub fn parse(line: &str) -> Result<Request, &'static str> {
    if line.len() > MAX_LINE {
        return Err("line too long");
    }
    let request: Request = serde_json::from_str(line).map_err(|_| "malformed request")?;
    if request.version() != PROTOCOL {
        return Err("wrong protocol version");
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_strict() {
        assert!(matches!(
            parse(r#"{"type":"hello","v":2}"#),
            Ok(Request::Hello { .. })
        ));
        assert!(parse(r#"{"type":"hello","v":1}"#).is_err());
        assert!(parse(r#"{"type":"hello","v":2,"extra":true}"#).is_err());
        assert!(parse(r#"{"type":"unknown","v":2}"#).is_err());
        assert!(matches!(
            parse(r#"{"type":"forgetItem","v":2,"id":"a"}"#),
            Ok(Request::ForgetItem { .. })
        ));
        assert!(parse(r#"{"type":"forgetItem","v":2,"id":"a","extra":1}"#).is_err());
        assert!(parse(r#"{"type":"forgetItem","v":1,"id":"a"}"#).is_err());
        let exec = parse(
            r#"{"type":"exec","v":2,"id":3,"argv":["bw","status"],"inject":{"BW_SESSION":"session"},"env":{"A":"b","C":null}}"#,
        );
        assert!(matches!(exec, Ok(Request::Exec { id: 3, .. })));
    }

    #[test]
    fn secrets_ride_beside_the_environment() {
        // Absent: no block. Present and empty: a block of just the end record.
        let bare = parse(r#"{"type":"exec","v":2,"id":1,"argv":["bash"]}"#);
        assert!(matches!(
            bare,
            Ok(Request::Exec { secrets: None, ref held_secrets, .. }) if held_secrets.is_empty()
        ));
        let with = parse(
            r#"{"type":"exec","v":2,"id":1,"argv":["bash"],"secrets":{"QSBW_SECRET":"pw"},"heldSecrets":{"QSBW_PIN":"secret:pw3"}}"#,
        );
        match with {
            Ok(Request::Exec {
                secrets: Some(secrets),
                held_secrets,
                ..
            }) => {
                assert_eq!(secrets.get("QSBW_SECRET").map(String::as_str), Some("pw"));
                assert_eq!(
                    held_secrets.get("QSBW_PIN").map(String::as_str),
                    Some("secret:pw3")
                );
            }
            other => panic!("{other:?}"),
        }
        // The old protocol number is refused: its helper would have put these
        // values in the environment.
        assert!(parse(r#"{"type":"exec","v":1,"id":1,"argv":["bash"]}"#).is_err());
    }

    #[test]
    fn the_block_is_nul_ended_records_closed_by_an_empty_one() {
        assert_eq!(secret_block([]), b"\0");
        assert_eq!(
            secret_block([("A", "x=y\n"), ("B_2", "")]),
            b"A=x=y\n\0B_2=\0\0"
        );
    }

    #[test]
    fn field_requests_are_strict() {
        let field = parse(r#"{"type":"field","v":2,"q":4,"id":"a","field":"notes"}"#);
        assert!(matches!(&field, Ok(Request::Field { q: 4, field, .. }) if field == "notes"));
        assert!(parse(r#"{"type":"field","v":2,"q":4,"id":"a"}"#).is_err());
        assert!(parse(r#"{"type":"field","v":2,"q":4,"id":"a","field":"notes","x":1}"#).is_err());
        assert!(parse(r#"{"type":"field","v":1,"q":4,"id":"a","field":"notes"}"#).is_err());
        let copy =
            parse(r#"{"type":"copyField","v":2,"q":5,"id":"a","field":"cardCode","clearSec":30}"#);
        assert!(matches!(
            copy,
            Ok(Request::CopyField {
                q: 5,
                clear_sec: 30,
                ..
            })
        ));
        // A copy names its clear time, and it is not negative.
        assert!(parse(r#"{"type":"copyField","v":2,"q":5,"id":"a","field":"cardCode"}"#).is_err());
        assert!(parse(
            r#"{"type":"copyField","v":2,"q":5,"id":"a","field":"cardCode","clearSec":-1}"#
        )
        .is_err());
        assert!(parse(
            r#"{"type":"copyField","v":3,"q":5,"id":"a","field":"cardCode","clearSec":30}"#
        )
        .is_err());
    }

    #[test]
    fn captures_and_sources() {
        assert_eq!(Capture::parse(None), Some(Capture::Plain));
        assert_eq!(
            Capture::parse(Some("secret:master")),
            Some(Capture::Secret("master".into()))
        );
        assert_eq!(Capture::parse(Some("secret:")), None);
        assert_eq!(Capture::parse(Some("secret:a b")), None);
        assert_eq!(Capture::parse(Some("other")), None);
        assert_eq!(
            Capture::parse(Some("pinentry:pw3")),
            Some(Capture::Pinentry("pw3".into()))
        );
        assert_eq!(Capture::parse(Some("pinentry:")), None);
        assert_eq!(Capture::parse(Some("pinentry:a b")), None);
        assert!(matches!(parse_source("session"), Some(Source::Session)));
        assert!(matches!(
            parse_source("secret:pw"),
            Some(Source::Secret("pw"))
        ));
        assert!(parse_source("pw").is_none());
        assert!(valid_env_name("BW_SESSION") && !valid_env_name("1A") && !valid_env_name("A=B"));
    }
}
