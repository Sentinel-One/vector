use std::{
    collections::{HashMap, HashSet},
    io::Read,
    sync::LazyLock,
};

use futures::TryFutureExt;
use indexmap::IndexMap;
use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
use toml::value::Table;
use vector_lib::config::ComponentKey;

use crate::{
    config::{
        loading::{deserialize_table, prepare_input, process::Process, ComponentHint, Loader},
        SecretBackend,
    },
    secrets::SecretBackends,
    signal,
};

// The following regex aims to extract a pair of strings, the first being the secret backend name
// and the second being the secret key. Here are some matching & non-matching examples:
// - "SECRET[backend.secret_name]" will match and capture "backend" and "secret_name"
// - "SECRET[backend.secret.name]" will match and capture "backend" and "secret.name"
// - "SECRET[backend..secret.name]" will match and capture "backend" and ".secret.name"
// - "SECRET[secret_name]" will not match
// - "SECRET[.secret.name]" will not match
pub static COLLECTOR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"SECRET\[([[:word:]]+)\.([[:word:].]+)\]").unwrap());

/// Helper type for specifically deserializing secrets backends.
#[derive(Debug, Default, Deserialize, Serialize)]
pub(crate) struct SecretBackendOuter {
    #[serde(default)]
    pub(crate) secret: IndexMap<ComponentKey, SecretBackends>,
}

/// Loader for secrets backends.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct SecretBackendLoader {
    backends: IndexMap<ComponentKey, SecretBackends>,
    pub(crate) secret_keys: HashMap<String, HashSet<String>>,
}

impl SecretBackendLoader {
    pub(crate) fn new() -> Self {
        Self {
            backends: IndexMap::new(),
            secret_keys: HashMap::new(),
        }
    }

    pub(crate) async fn retrieve(
        &mut self,
        signal_rx: &mut signal::SignalRx,
    ) -> Result<HashMap<String, String>, String> {
        let mut secrets: HashMap<String, String> = HashMap::new();

        for (backend_name, keys) in &self.secret_keys {
            let backend = self.backends
                .get_mut(&ComponentKey::from(backend_name.clone()))
                .ok_or_else(|| {
                    format!("Backend \"{backend_name}\" is required for secret retrieval but was not found in config.")
                })?;

            debug!(message = "Retrieving secrets from a backend.", backend = ?backend_name, keys = ?keys);
            let backend_secrets = backend
                .retrieve(keys.clone(), signal_rx)
                .map_err(|e| {
                    format!("Error while retrieving secret from backend \"{backend_name}\": {e}.",)
                })
                .await?;

            for (k, v) in backend_secrets {
                trace!(message = "Successfully retrieved a secret.", backend = ?backend_name, key = ?k);
                secrets.insert(format!("{backend_name}.{k}"), v);
            }
        }

        Ok(secrets)
    }

    pub(crate) fn has_secrets_to_retrieve(&self) -> bool {
        !self.secret_keys.is_empty()
    }
}

impl Process for SecretBackendLoader {
    fn prepare<R: Read>(&mut self, input: R) -> Result<String, Vec<String>> {
        let config_string = prepare_input(input)?;
        // Collect secret placeholders just after env var processing
        collect_secret_keys(&config_string, &mut self.secret_keys);
        Ok(config_string)
    }

    fn merge(&mut self, table: Table, _: Option<ComponentHint>) -> Result<(), Vec<String>> {
        if table.contains_key("secret") {
            let additional = deserialize_table::<SecretBackendOuter>(table)?;
            self.backends.extend(additional.secret);
        }
        Ok(())
    }
}

impl Loader<SecretBackendLoader> for SecretBackendLoader {
    fn take(self) -> SecretBackendLoader {
        self
    }
}

fn collect_secret_keys(input: &str, keys: &mut HashMap<String, HashSet<String>>) {
    COLLECTOR.captures_iter(input).for_each(|cap| {
        if let (Some(backend), Some(key)) = (cap.get(1), cap.get(2)) {
            if let Some(keys) = keys.get_mut(backend.as_str()) {
                keys.insert(key.as_str().to_string());
            } else {
                keys.insert(
                    backend.as_str().to_string(),
                    HashSet::from_iter(std::iter::once(key.as_str().to_string())),
                );
            }
        }
    });
}

/// Cheap pre-filter: the overwhelming majority of configs contain no placeholder at all, and
/// this lets them skip the regex scan entirely.
const SECRET_MARKER: &str = "SECRET[";

/// The lexical context a placeholder sits in, as far as a line-local scan can establish.
///
/// Substitution happens on the raw config text *before* it is parsed, which is what preserves
/// the current behaviour that an unquoted placeholder yields a typed scalar (`port: SECRET[..]`
/// with a value of `8000` deserializes as an integer). The cost of that is a secret value can
/// otherwise terminate its enclosing scalar and become configuration structure, so each
/// substitution has to be treated according to where it lands.
#[derive(Debug, PartialEq, Eq)]
enum Context {
    /// Inside a double-quoted scalar opened on this line. Escaping is portable here: TOML basic
    /// strings, YAML double-quoted scalars and JSON strings share `\\`, `\"`, `\n`, `\r`, `\t`
    /// and `\uXXXX`.
    DoubleQuoted,
    /// Everything else, and deliberately the default whenever the scan cannot positively
    /// establish `DoubleQuoted`.
    ///
    /// This includes single-quoted scalars, because there is no portable escape: a TOML literal
    /// string admits no escape sequence at all, so a `'` simply cannot be represented inside
    /// one. It also covers comments, multi-line strings and YAML block scalars, whose state a
    /// line-local scan cannot know.
    Unknown,
}

/// The text between the start of the placeholder's line and the placeholder itself.
fn line_prefix(input: &str, at: usize) -> &str {
    let line_start = input[..at].rfind('\n').map_or(0, |i| i + 1);
    &input[line_start..at]
}

/// Establish the context of a placeholder from the text preceding it on its own line.
///
/// Biased to return [`Context::Unknown`] whenever the answer is not certain. The two possible
/// misreadings are not symmetric, and this is what makes the bias the safe one:
///
/// - Guessing `Unknown` when actually double-quoted means the value is required to be inert
///   instead of escaped. An inert value is equally harmless inside a string literal, so the
///   result is at worst a rejected secret with an actionable error.
/// - Guessing `DoubleQuoted` when actually unquoted would emit `\"`-style escapes into a bare
///   position and break config loading outright.
fn scan_context(prefix: &str) -> Context {
    let bytes = prefix.as_bytes();
    let mut in_double = false;
    let mut in_single = false;
    let mut i = 0;

    while i < bytes.len() {
        // A multi-line delimiter means state may have been carried in from an earlier line, so
        // line-local reasoning no longer holds.
        if bytes[i..].starts_with(br#"""""#) || bytes[i..].starts_with(b"'''") {
            return Context::Unknown;
        }

        match bytes[i] {
            // Inside a double-quoted scalar a backslash escapes the next byte, so it cannot
            // close the string.
            b'\\' if in_double => {
                i += 2;
                continue;
            }
            b'"' if !in_single => in_double = !in_double,
            b'\'' if !in_double => in_single = !in_single,
            // A comment: the placeholder is not in a value position at all, but a newline in
            // the value would still escape the comment and become structure.
            b'#' if !in_double && !in_single => return Context::Unknown,
            _ => {}
        }
        i += 1;
    }

    if in_double {
        Context::DoubleQuoted
    } else {
        Context::Unknown
    }
}

/// Escape a value so it cannot terminate the double-quoted scalar it is being spliced into.
fn escape_double_quoted(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => escaped.push_str(r"\\"),
            '"' => escaped.push_str(r#"\""#),
            '\n' => escaped.push_str(r"\n"),
            '\r' => escaped.push_str(r"\r"),
            '\t' => escaped.push_str(r"\t"),
            c if c.is_control() => escaped.push_str(&format!("\\u{:04x}", c as u32)),
            c => escaped.push(c),
        }
    }
    escaped
}

/// Whether a value can be spliced into an unquoted position without being able to become
/// anything other than a single scalar, in any supported format.
///
/// An allowlist rather than a denylist, because the set of characters that are structurally
/// significant somewhere across TOML, YAML and JSON is large and easy to under-enumerate - a
/// bare `,` is enough to add an element in a YAML flow sequence, with no quote or newline
/// involved. The permitted set still covers what actually appears unquoted in practice: ports
/// and other numbers, versions, hostnames, paths, and base64 (hence `+`, `/` and `=`).
fn is_inert(value: &str) -> bool {
    let mut chars = value.chars();
    // A leading `-`, `?`, `&`, `*`, `!` or similar is a YAML indicator, so require the first
    // character to be unambiguous.
    match chars.next() {
        None => true,
        Some(first) if first.is_ascii_alphanumeric() || first == '_' => value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '/' | '=')),
        Some(_) => false,
    }
}

pub fn interpolate(input: &str, secrets: &HashMap<String, String>) -> Result<String, Vec<String>> {
    if !input.contains(SECRET_MARKER) {
        return Ok(input.to_owned());
    }

    let mut errors = Vec::<String>::new();
    let output = COLLECTOR
        .replace_all(input, |caps: &Captures<'_>| {
            let matched = caps.get(0).expect("capture group 0 always matches");
            let Some(value) = caps
                .get(1)
                .and_then(|b| caps.get(2).map(|k| (b, k)))
                .and_then(|(b, k)| secrets.get(&format!("{}.{}", b.as_str(), k.as_str())))
            else {
                errors.push(format!(
                    "Unable to find secret replacement for {}.",
                    matched.as_str()
                ));
                return String::new();
            };

            // The value is substituted into text that has not been parsed yet, so it must not be
            // able to close its scalar and introduce configuration of its own.
            match scan_context(line_prefix(input, matched.start())) {
                Context::DoubleQuoted => escape_double_quoted(value),
                Context::Unknown if is_inert(value) => value.clone(),
                Context::Unknown => {
                    // Deliberately does not include the value.
                    errors.push(format!(
                        "Secret {} resolves to a value containing characters that could alter the \
                         configuration structure when substituted outside a double-quoted string. \
                         Enclose the placeholder in double quotes, for example \"{}\".",
                        matched.as_str(),
                        matched.as_str()
                    ));
                    String::new()
                }
            }
        })
        .into_owned();
    if errors.is_empty() {
        Ok(output)
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use indoc::indoc;

    use super::{collect_secret_keys, interpolate};

    /// OBE-11560: a retrieved secret is spliced into the raw config *text* before it is parsed, so
    /// a value carrying a quote and a newline can terminate its scalar and become configuration -
    /// demonstrated end to end with a working `exec` source.
    ///
    /// Substitution has to stay pre-parse to preserve typing (an unquoted placeholder yields a
    /// typed scalar, which is the only form that works for a numeric field), so instead each
    /// substitution is treated according to the context it lands in: escaped inside a
    /// double-quoted scalar, required to be inert anywhere else.
    mod structural_injection {
        use super::*;

        /// A value that escapes its string and adds a source, in TOML.
        const TOML_BREAKOUT: &str =
            "x\"\n[sources.injected]\ntype = \"exec\"\ncommand = [\"id\"]\ny = \"";
        /// The YAML equivalent; note the shape differs from the TOML one.
        const YAML_BREAKOUT: &str = "x\"\ninjected:\n  type: exec\n";

        fn secrets(value: &str) -> HashMap<String, String> {
            vec![("b.k".to_string(), value.to_string())]
                .into_iter()
                .collect()
        }

        // --- the injection is closed ------------------------------------------------------

        #[test]
        fn toml_breakout_inside_quotes_is_escaped_not_structural() {
            let config = interpolate(r#"password = "SECRET[b.k]""#, &secrets(TOML_BREAKOUT))
                .expect("a quoted placeholder should substitute");

            let parsed: toml::Table = toml::from_str(&config).expect("must still be valid TOML");

            assert_eq!(
                parsed.keys().collect::<Vec<_>>(),
                vec!["password"],
                "the secret must not have introduced a table"
            );
            assert_eq!(
                parsed["password"].as_str(),
                Some(TOML_BREAKOUT),
                "the value must round-trip verbatim"
            );
        }

        #[test]
        fn yaml_breakout_inside_quotes_is_escaped_not_structural() {
            let config = interpolate(r#"password: "SECRET[b.k]""#, &secrets(YAML_BREAKOUT))
                .expect("a quoted placeholder should substitute");

            let parsed: serde_yaml::Value =
                serde_yaml::from_str(&config).expect("must still be valid YAML");
            let map = parsed.as_mapping().expect("a mapping");

            assert_eq!(map.len(), 1, "the secret must not have introduced a key");
            assert_eq!(map["password"].as_str(), Some(YAML_BREAKOUT));
        }

        #[test]
        fn breakout_outside_quotes_is_rejected() {
            let error = interpolate("password: SECRET[b.k]", &secrets(YAML_BREAKOUT))
                .expect_err("an unquoted placeholder must not accept a structural value");

            assert_eq!(error.len(), 1);
            assert!(error[0].contains("could alter the configuration structure"));
            assert!(
                !error[0].contains("injected"),
                "the error must not leak the secret value"
            );
        }

        #[test]
        fn yaml_flow_sequence_comma_injection_is_rejected() {
            // A comma alone adds an element in a flow sequence - no quote, no newline. This is the
            // case a `\r\n\"` denylist misses, which is why unquoted values use an allowlist.
            let error = interpolate("hosts: [SECRET[b.k]]", &secrets("a, b"))
                .expect_err("a comma must not be accepted in an unquoted position");

            assert!(error[0].contains("could alter the configuration structure"));
        }

        #[test]
        fn newline_in_a_comment_cannot_escape_into_structure() {
            // The placeholder is not in a value position, but a newline would end the comment.
            let error = interpolate("# see SECRET[b.k]", &secrets("x\ninjected: true"))
                .expect_err("a comment must not accept a value containing a newline");

            assert!(error[0].contains("could alter the configuration structure"));
        }

        // --- today's behaviour is preserved ----------------------------------------------

        #[test]
        fn unquoted_numeric_secret_still_parses_as_an_integer() {
            // The case that matters: this is the only form in which a numeric secret works, and it
            // works *because* substitution precedes parsing.
            let config = interpolate("port: SECRET[b.k]", &secrets("8000"))
                .expect("a numeric secret is inert and must be accepted");

            assert_eq!(config, "port: 8000");

            let parsed: serde_yaml::Value = serde_yaml::from_str(&config).unwrap();
            assert_eq!(
                parsed["port"].as_u64(),
                Some(8000),
                "an unquoted numeric secret must stay an integer"
            );
        }

        #[test]
        fn quoted_numeric_secret_still_parses_as_a_string() {
            let config = interpolate(r#"port: "SECRET[b.k]""#, &secrets("8000")).unwrap();

            let parsed: serde_yaml::Value = serde_yaml::from_str(&config).unwrap();
            assert_eq!(parsed["port"].as_str(), Some("8000"));
            assert!(
                parsed["port"].as_u64().is_none(),
                "quoting is what makes it a string, both before and after this change"
            );
        }

        #[test]
        fn rich_password_round_trips_inside_quotes() {
            // Realistic secrets contain characters that are structural somewhere; inside a
            // double-quoted scalar they are simply escaped rather than rejected.
            let password = r#"p@ss:w#rd,{}[]\|<>'"~$%^&*()"#;
            let config = interpolate(r#"password = "SECRET[b.k]""#, &secrets(password)).unwrap();

            let parsed: toml::Table = toml::from_str(&config).expect("must be valid TOML");
            assert_eq!(parsed["password"].as_str(), Some(password));
            assert_eq!(parsed.len(), 1);
        }

        #[test]
        fn base64_token_is_accepted_unquoted() {
            let token = "aGVsbG8rd29ybGQvPT0=";
            let config = interpolate("token: SECRET[b.k]", &secrets(token)).unwrap();

            assert_eq!(config, format!("token: {token}"));
        }

        #[test]
        fn input_without_a_placeholder_is_returned_unchanged() {
            let config = "sources:\n  in:\n    type: stdin\n";
            assert_eq!(Ok(config.to_string()), interpolate(config, &secrets("v")));
        }

        // --- context-scanning caveats, all of which must fail closed ---------------------

        #[test]
        fn single_quoted_context_requires_an_inert_value() {
            // A TOML literal string admits no escape sequence at all, so a `'` cannot be
            // represented inside one; there is no portable escaping and the value must be inert.
            let error = interpolate("password = 'SECRET[b.k]'", &secrets("has'quote"))
                .expect_err("a single-quoted context must not be escaped into");
            assert!(error[0].contains("could alter the configuration structure"));

            // An inert value is still fine there.
            assert_eq!(
                Ok("password = 'abc123'".to_string()),
                interpolate("password = 'SECRET[b.k]'", &secrets("abc123"))
            );
        }

        #[test]
        fn toml_multiline_string_on_the_same_line_requires_an_inert_value() {
            let error = interpolate(r#"x = """a SECRET[b.k]"#, &secrets("has\"quote"))
                .expect_err("a multi-line delimiter defeats line-local scanning");
            assert!(error[0].contains("could alter the configuration structure"));
        }

        #[test]
        fn toml_multiline_string_opened_on_an_earlier_line_requires_an_inert_value() {
            // The scan only sees the placeholder's own line, which has no quote on it at all, so
            // it must not conclude the value is safely quoted.
            let input = "x = \"\"\"\nsome text SECRET[b.k]\n\"\"\"\n";
            let error = interpolate(input, &secrets("has\"quote"))
                .expect_err("carried-in quote state must fail closed");
            assert!(error[0].contains("could alter the configuration structure"));
        }

        #[test]
        fn yaml_block_scalar_requires_an_inert_value() {
            let input = "script: |\n  echo SECRET[b.k]\n";
            let error = interpolate(input, &secrets("x\ninjected: true"))
                .expect_err("a block scalar must fail closed");
            assert!(error[0].contains("could alter the configuration structure"));

            // ...and an inert value is still substituted there.
            let ok = interpolate(input, &secrets("8000")).unwrap();
            assert_eq!(ok, "script: |\n  echo 8000\n");
        }

        #[test]
        fn an_escaped_quote_does_not_close_the_enclosing_string() {
            // `\"` must not be read as terminating the scalar, or the value would be treated as
            // unquoted and a legitimate rich secret would be rejected.
            let config = interpolate(r#"x = "a\" then SECRET[b.k]""#, &secrets("has\"quote"))
                .expect("still inside the string, so the value is escaped");

            let parsed: toml::Table = toml::from_str(&config).expect("must be valid TOML");
            assert_eq!(parsed["x"].as_str(), Some("a\" then has\"quote"));
        }

        #[test]
        fn a_closed_quote_before_the_placeholder_is_not_quoted_context() {
            // `"a"` opens and closes, so the placeholder that follows is unquoted.
            let error = interpolate(r#"x = "a" SECRET[b.k]"#, &secrets("has\"quote"))
                .expect_err("a balanced pair of quotes leaves the placeholder unquoted");
            assert!(error[0].contains("could alter the configuration structure"));
        }

        #[test]
        fn each_placeholder_is_judged_on_its_own_line() {
            let input = "a = \"SECRET[b.k]\"\nb = SECRET[b.k]\n";

            // The quoted one would be fine, the bare one is not, so the whole load fails.
            let error = interpolate(input, &secrets("has\"quote")).expect_err("bare use must fail");
            assert_eq!(
                error.len(),
                1,
                "only the bare placeholder should be faulted"
            );
        }

        // --- the TOML-bare caveat, recorded rather than assumed --------------------------

        #[test]
        fn toml_cannot_use_an_unquoted_placeholder_at_all() {
            // Backend discovery (`SecretBackendLoader::prepare`) returns the text *without*
            // substituting, and the loader then parses it. TOML has no unquoted string form, so a
            // bare placeholder fails that first parse - meaning the unquoted-numeric form works in
            // YAML only. Recorded here so the asymmetry is not rediscovered later.
            assert!(
                toml::from_str::<toml::Table>("port = SECRET[b.k]").is_err(),
                "a bare placeholder is not valid TOML"
            );
            assert!(
                serde_yaml::from_str::<serde_yaml::Value>("port: SECRET[b.k]").is_ok(),
                "but it is a valid YAML plain scalar"
            );
        }
    }

    #[test]
    fn replacement() {
        let secrets: HashMap<String, String> = vec![
            ("a.secret.key".into(), "value".into()),
            ("a...key".into(), "a...value".into()),
        ]
        .into_iter()
        .collect();

        assert_eq!(
            Ok("value".into()),
            interpolate("SECRET[a.secret.key]", &secrets)
        );
        assert_eq!(
            Ok("value value".into()),
            interpolate("SECRET[a.secret.key] SECRET[a.secret.key]", &secrets)
        );

        assert_eq!(
            Ok("xxxvalueyyy".into()),
            interpolate("xxxSECRET[a.secret.key]yyy", &secrets)
        );
        assert_eq!(
            Ok("a...value".into()),
            interpolate("SECRET[a...key]", &secrets)
        );
        assert_eq!(
            Ok("xxxSECRET[non_matching_syntax]yyy".into()),
            interpolate("xxxSECRET[non_matching_syntax]yyy", &secrets)
        );
        assert_eq!(
            Err(vec![
                "Unable to find secret replacement for SECRET[a.non.existing.key].".into()
            ]),
            interpolate("xxxSECRET[a.non.existing.key]yyy", &secrets)
        );
    }

    #[test]
    fn collection() {
        let mut keys = HashMap::new();
        collect_secret_keys(
            indoc! {r"
            SECRET[first_backend.secret_key]
            SECRET[first_backend.another_secret_key]
            SECRET[second_backend.secret_key]
            SECRET[second_backend.secret.key]
            SECRET[first_backend.a_third.secret_key]
            SECRET[first_backend...an_extra_secret_key]
            SECRET[non_matching_syntax]
            SECRET[.non.matching.syntax]
        "},
            &mut keys,
        );
        assert_eq!(keys.len(), 2);
        assert!(keys.contains_key("first_backend"));
        assert!(keys.contains_key("second_backend"));

        let first_backend_keys = keys.get("first_backend").unwrap();
        assert_eq!(first_backend_keys.len(), 4);
        assert!(first_backend_keys.contains("secret_key"));
        assert!(first_backend_keys.contains("another_secret_key"));
        assert!(first_backend_keys.contains("a_third.secret_key"));
        assert!(first_backend_keys.contains("..an_extra_secret_key"));

        let second_backend_keys = keys.get("second_backend").unwrap();
        assert_eq!(second_backend_keys.len(), 2);
        assert!(second_backend_keys.contains("secret_key"));
        assert!(second_backend_keys.contains("secret.key"));
    }

    #[test]
    fn collection_duplicates() {
        let mut keys = HashMap::new();
        collect_secret_keys(
            indoc! {r"
            SECRET[first_backend.secret_key]
            SECRET[first_backend.secret_key]
        "},
            &mut keys,
        );

        let first_backend_keys = keys.get("first_backend").unwrap();
        assert_eq!(first_backend_keys.len(), 1);
        assert!(first_backend_keys.contains("secret_key"));
    }
}
