use jiff::civil::date;
use toml_edit::DocumentMut;

use super::*;

fn apply(
    content: &str,
    list: IgnoreList,
    ids: &[&str],
    reason: Option<&str>,
    until: Option<Date>,
) -> (String, Outcome) {
    apply_to_package(content, list, ids, None, reason, until)
}

fn apply_to_package(
    content: &str,
    list: IgnoreList,
    ids: &[&str],
    package: Option<&str>,
    reason: Option<&str>,
    until: Option<Date>,
) -> (String, Outcome) {
    let mut document = content.parse::<DocumentMut>().unwrap();
    let ids: Vec<String> = ids.iter().map(ToString::to_string).collect();
    let outcome = add_rules(&mut document, list, &ids, package, reason, until).unwrap();
    (document.to_string(), outcome)
}

#[test]
fn package_rules_are_written_and_deduplicated_by_id_and_package() {
    // Whole package.
    let (text, outcome) = apply_to_package(
        "",
        IgnoreList::Always,
        &[],
        Some("vendored"),
        Some("never runs"),
        None,
    );
    assert_eq!(
        text,
        "[tool.pixi-audit]\nignore = [{ package = \"vendored\", reason = \"never runs\" }]\n"
    );
    assert_eq!(outcome.added, ["package 'vendored'"]);

    // One id in a package is distinct from the same id everywhere and from
    // the whole package, but equal to itself in any spelling.
    let (text, outcome) = apply_to_package(
        &text,
        IgnoreList::Always,
        &["CVE-1", "cve-1"],
        Some("Vendored"),
        None,
        None,
    );
    assert_eq!(outcome.added, ["CVE-1 in package 'Vendored'"]);
    assert_eq!(outcome.existing, ["cve-1 in package 'Vendored'"]);
    assert!(
        text.contains("{ id = \"CVE-1\", package = \"Vendored\" }"),
        "{text}"
    );
    let (_, outcome) = apply(&text, IgnoreList::Always, &["CVE-1"], None, None);
    assert_eq!(outcome.added, ["CVE-1"]);
    let (_, outcome) =
        apply_to_package(&text, IgnoreList::Always, &[], Some("VENDORED"), None, None);
    assert_eq!(outcome.existing, ["package 'VENDORED'"]);
}

#[test]
fn creates_the_table_and_list_in_a_bare_manifest() {
    let (text, outcome) = apply(
        "[workspace]\nname = \"demo\"\n",
        IgnoreList::Always,
        &["CVE-1"],
        None,
        None,
    );
    assert_eq!(
        text,
        "[workspace]\nname = \"demo\"\n\n[tool.pixi-audit]\nignore = [\"CVE-1\"]\n"
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
        "[tool.pixi-audit]\n# reviewed 2026-01\nignore = [\"CVE-1\"] # keep\nseverity = \"high\"\n";
    let (text, outcome) = apply(content, IgnoreList::Always, &["CVE-2", "cve-1"], None, None);
    assert_eq!(
        text,
        "[tool.pixi-audit]\n# reviewed 2026-01\nignore = [\"CVE-1\", \"CVE-2\"] # keep\nseverity = \"high\"\n"
    );
    assert_eq!(outcome.added, ["CVE-2"]);
    assert_eq!(outcome.existing, ["cve-1"]);
}

#[test]
fn reason_and_until_become_an_inline_table() {
    let (text, _) = apply(
        "",
        IgnoreList::UntilFixed,
        &["CVE-3"],
        Some("only in tests"),
        Some(date(2026, 12, 1)),
    );
    assert_eq!(
        text,
        "[tool.pixi-audit]\nignore-until-fixed = [{ id = \"CVE-3\", reason = \"only in tests\", until = \"2026-12-01\" }]\n"
    );
}

#[test]
fn duplicates_are_detected_in_table_entries_and_within_one_call() {
    let content = "[tool.pixi-audit]\nignore = [{ id = \"CVE-4\", reason = \"x\" }]\n";
    let (text, outcome) = apply(
        content,
        IgnoreList::Always,
        &["CVE-4", "CVE-5", "cve-5"],
        None,
        None,
    );
    assert_eq!(outcome.added, ["CVE-5"]);
    assert_eq!(outcome.existing, ["CVE-4", "cve-5"]);
    assert_eq!(text.matches("CVE-5").count(), 1, "{text}");
}

#[test]
fn pyproject_uses_the_same_table() {
    let content = "[project]\nname = \"x\"\n\n[tool.pixi]\nchannels = [\"conda-forge\"]\n";
    let (text, _) = apply(content, IgnoreList::Always, &["CVE-6"], None, None);
    assert_eq!(
        text,
        "[project]\nname = \"x\"\n\n[tool.pixi]\nchannels = [\"conda-forge\"]\n\n[tool.pixi-audit]\nignore = [\"CVE-6\"]\n"
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
            IgnoreList::Always,
            &["CVE-2".to_string()],
            None,
            None,
            None
        )
        .is_err()
    );
}
