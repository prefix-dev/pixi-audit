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
    let mut document = content.parse::<DocumentMut>().unwrap();
    let ids: Vec<String> = ids.iter().map(ToString::to_string).collect();
    let outcome = add_rules(&mut document, list, &ids, reason, until).unwrap();
    (document.to_string(), outcome)
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
        "[tool.pixi-audit]\nignore-until-fixed = [{ id = \"CVE-3\", reason = \"only in tests\", until = 2026-12-01 }]\n"
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
            None
        )
        .is_err()
    );
}
