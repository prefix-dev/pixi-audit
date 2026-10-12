use jiff::civil::date;
use toml_edit::DocumentMut;

use super::*;

fn apply(
    content: &str,
    list: IgnoreList,
    ids: &[&str],
    reason: Option<&str>,
    expired_at: Option<Date>,
) -> (String, Outcome) {
    apply_to_package(content, list, ids, None, reason, expired_at)
}

fn apply_to_package(
    content: &str,
    list: IgnoreList,
    ids: &[&str],
    package: Option<&str>,
    reason: Option<&str>,
    expired_at: Option<Date>,
) -> (String, Outcome) {
    let mut document = content.parse::<DocumentMut>().unwrap();
    let ids: Vec<String> = ids.iter().map(ToString::to_string).collect();
    let outcome = add_rules(
        &mut document,
        list,
        &ids,
        &IgnoreScope {
            package: package.map(str::to_string),
            ..IgnoreScope::default()
        },
        reason,
        expired_at,
    )
    .unwrap();
    (document.to_string(), outcome)
}

fn entries(text: &str, list: IgnoreList) -> Vec<IgnoreEntry> {
    let manifest: toml::Value = toml::from_str(text).unwrap();
    manifest["tool"]["pixi-audit"][list.key()]
        .clone()
        .try_into()
        .unwrap()
}

#[test]
fn package_rules_are_written_and_deduplicated_by_id_and_package() {
    // Whole package.
    let (text, outcome) = apply_to_package(
        "",
        IgnoreList::Permanent,
        &[],
        Some("vendored"),
        Some("never runs"),
        None,
    );
    assert!(outcome.existing.is_empty());
    assert_eq!(
        entries(&text, IgnoreList::Permanent),
        [IgnoreEntry::Rule(IgnoreTable {
            scope: IgnoreScope {
                package: Some("vendored".to_string()),
                ..IgnoreScope::default()
            },
            reason: Some("never runs".to_string()),
            ..IgnoreTable::default()
        })]
    );

    // One id in a package is distinct from the same id everywhere and from
    // the whole package, but equal to itself in any spelling.
    let (text, _) = apply_to_package(
        &text,
        IgnoreList::Permanent,
        &["CVE-1", "cve-1"],
        Some("Vendored"),
        None,
        None,
    );
    assert_eq!(
        entries(&text, IgnoreList::Permanent)[1],
        IgnoreEntry::Rule(IgnoreTable {
            id: Some("CVE-1".to_string()),
            scope: IgnoreScope {
                package: Some("Vendored".to_string()),
                ..IgnoreScope::default()
            },
            ..IgnoreTable::default()
        })
    );
    let (_, outcome) = apply(&text, IgnoreList::Permanent, &["CVE-1"], None, None);
    assert_eq!(outcome.added, ["CVE-1"]);
    let (_, outcome) = apply_to_package(
        &text,
        IgnoreList::Permanent,
        &[],
        Some("VENDORED"),
        None,
        None,
    );
    assert!(outcome.added.is_empty());
}

#[test]
fn creates_the_table_and_list_in_a_bare_manifest() {
    let (text, outcome) = apply(
        "[workspace]\nname = \"demo\"\n",
        IgnoreList::Permanent,
        &["CVE-1"],
        None,
        None,
    );
    assert_eq!(
        entries(&text, IgnoreList::Permanent),
        [IgnoreEntry::Id("CVE-1".to_string())]
    );
    assert_eq!(
        outcome,
        Outcome {
            added: vec!["CVE-1".to_string()],
            existing: vec![],
        }
    );
}

#[test]
fn appends_to_an_existing_list_and_keeps_comments() {
    let content =
        "[tool.pixi-audit]\n# reviewed 2026-01\nignore = [\"CVE-1\"] # keep\nfail-on = \"high\"\n";
    let (text, outcome) = apply(
        content,
        IgnoreList::Permanent,
        &["CVE-2", "cve-1"],
        None,
        None,
    );
    assert_eq!(
        text,
        "[tool.pixi-audit]\n# reviewed 2026-01\nignore = [\"CVE-1\", \"CVE-2\"] # keep\nfail-on = \"high\"\n"
    );
    assert_eq!(outcome.added, ["CVE-2"]);
    assert_eq!(outcome.existing, ["cve-1"]);
}

#[test]
fn expiry_and_reason_round_trip() {
    let (text, _) = apply(
        "",
        IgnoreList::UntilFixed,
        &["CVE-3"],
        Some("only in tests"),
        Some(date(2026, 12, 1)),
    );
    let entries = entries(&text, IgnoreList::UntilFixed);
    assert_eq!(
        entries,
        [IgnoreEntry::Rule(IgnoreTable {
            id: Some("CVE-3".to_string()),
            reason: Some("only in tests".to_string()),
            expired_at: Some(toml::Value::String("2026-12-01".to_string())),
            ..IgnoreTable::default()
        })]
    );
}

#[test]
fn duplicates_are_detected_in_table_entries_and_within_one_call() {
    let content = "[tool.pixi-audit]\nignore = [{ id = \"CVE-4\", reason = \"x\" }]\n";
    let (text, outcome) = apply(
        content,
        IgnoreList::Permanent,
        &["CVE-4", "CVE-5", "cve-5"],
        None,
        None,
    );
    assert_eq!(outcome.added, ["CVE-5"]);
    assert_eq!(outcome.existing, ["CVE-4", "cve-5"]);
    assert_eq!(text.matches("CVE-5").count(), 1, "{text}");
}

#[test]
fn version_scoped_rules_are_written_separately() {
    let mut document = "".parse::<DocumentMut>().unwrap();
    for version in ["1.13.1", "1.13.2"] {
        add_rules(
            &mut document,
            IgnoreList::Permanent,
            &["CVE-1".to_string()],
            &IgnoreScope {
                ecosystem: Some("conda-forge".to_string()),
                version: Some(version.to_string()),
                ..IgnoreScope::default()
            },
            None,
            None,
        )
        .unwrap();
    }
    let entries = entries(&document.to_string(), IgnoreList::Permanent);
    let rules: Vec<_> = entries
        .iter()
        .map(|entry| entry.resolved(false).unwrap())
        .collect();
    assert_eq!(
        rules
            .iter()
            .map(|rule| rule.scope().version.as_deref())
            .collect::<Vec<_>>(),
        [Some("1.13.1"), Some("1.13.2")]
    );
}

#[test]
fn scope_keys_ignore_identifier_case_but_preserve_version_strings() {
    let mut document = r#"[tool.pixi-audit]
ignore = [{ id = "CVE-1", package = "Requests", ecosystem = "PyPI", version = "1.0RC1", up-to-version = "2.0" }]
"#
    .parse::<DocumentMut>()
    .unwrap();
    let mut scope = IgnoreScope {
        package: Some("requests".to_string()),
        ecosystem: Some("pypi".to_string()),
        version: Some("1.0RC1".to_string()),
        up_to_version: Some("2.0".to_string()),
    };
    let ids = ["cve-1".to_string()];
    let original = document.to_string();
    let outcome = add_rules(
        &mut document,
        IgnoreList::Permanent,
        &ids,
        &scope,
        None,
        None,
    )
    .unwrap();
    assert!(outcome.added.is_empty());
    assert_eq!(document.to_string(), original);

    scope.version = Some("1.0rc1".to_string());
    let outcome = add_rules(
        &mut document,
        IgnoreList::Permanent,
        &ids,
        &scope,
        None,
        None,
    )
    .unwrap();
    assert_eq!(
        entries(&document.to_string(), IgnoreList::Permanent)[1]
            .resolved(false)
            .unwrap()
            .scope(),
        &scope
    );
    assert!(outcome.existing.is_empty());

    scope.up_to_version = Some("2.0.0".to_string());
    let outcome = add_rules(
        &mut document,
        IgnoreList::Permanent,
        &ids,
        &scope,
        None,
        None,
    )
    .unwrap();
    assert_eq!(
        entries(&document.to_string(), IgnoreList::Permanent)[2]
            .resolved(false)
            .unwrap()
            .scope(),
        &scope
    );
    assert!(outcome.existing.is_empty());
}

#[test]
fn malformed_entries_do_not_hide_a_valid_new_rule() {
    let content = r#"[tool.pixi-audit]
ignore = [42, { id = "CVE-1", package = 7 }, { id = "CVE-1", reason = false }]
"#;
    let (text, outcome) = apply(content, IgnoreList::Permanent, &["CVE-1"], None, None);
    assert!(outcome.existing.is_empty());
    let manifest: toml::Value = toml::from_str(&text).unwrap();
    let original: toml::Value = toml::from_str(content).unwrap();
    let array = manifest["tool"]["pixi-audit"]["ignore"].as_array().unwrap();
    assert_eq!(
        &array[..3],
        original["tool"]["pixi-audit"]["ignore"].as_array().unwrap()
    );
    assert_eq!(array[3], toml::Value::String("CVE-1".to_string()));
    assert!(
        manifest["tool"]["pixi-audit"]["ignore"]
            .clone()
            .try_into::<Vec<IgnoreEntry>>()
            .is_err()
    );
}

#[test]
fn a_list_that_is_not_an_array_is_an_error() {
    let mut document = "[tool.pixi-audit]\nignore = \"CVE-1\"\n"
        .parse::<DocumentMut>()
        .unwrap();
    assert!(
        add_rules(
            &mut document,
            IgnoreList::Permanent,
            &["CVE-2".to_string()],
            &IgnoreScope::default(),
            None,
            None
        )
        .is_err()
    );
}
