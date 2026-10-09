use super::*;

#[test]
fn ignore_rules_apply_through_their_last_day() {
    let rule = IgnoreRule::from_id("CVE-1".into(), true);
    for expired_at in [
        toml::Value::String("2026-09-02".to_string()),
        toml::Value::Datetime("2026-09-02".parse().unwrap()),
    ] {
        let entries = [IgnoreEntry::Rule(IgnoreTable {
            id: Some("CVE-1".to_string()),
            expired_at: Some(expired_at),
            ..IgnoreTable::default()
        })];
        let (active, expired) =
            effective_ignores(&entries, jiff::civil::date(2026, 9, 2), true).unwrap();
        assert_eq!(active, std::slice::from_ref(&rule));
        assert!(expired.is_empty());

        let (active, expired) =
            effective_ignores(&entries, jiff::civil::date(2026, 9, 3), true).unwrap();
        assert!(active.is_empty());
        assert_eq!(
            expired,
            [ExpiredIgnore {
                rule: rule.clone(),
                expired_at: jiff::civil::date(2026, 9, 2),
            }]
        );
    }
}

#[test]
fn complete_schema_round_trips_with_unknown_keys() {
    let text = r#"
ignore = ["CVE-1", { package = "requests", ecosystem = "PyPI", version = "1.0", up-to-version = "2.0", reason = "reviewed", expired-at = "2999-01-01" }]
ignore-until-fixed = [{ id = "CVE-2", package = "libfoo" }]
ignore-unfixed = true
fail-on = "high"
future-option = true
"#;
    let config: AuditConfig = toml::from_str(text).unwrap();
    assert!(config.ignore_unfixed);
    assert_eq!(config.fail_on.as_deref(), Some("high"));
    assert_eq!(config.unknown["future-option"], toml::Value::Boolean(true));
    let serialized = toml::to_string(&config).unwrap();
    let round_trip: AuditConfig = toml::from_str(&serialized).unwrap();
    assert_eq!(round_trip, config);
    let rules: Vec<_> = config
        .ignore_lists()
        .into_iter()
        .flat_map(|(list, entries)| {
            effective_ignores(entries, jiff::civil::date(2026, 9, 2), list.until_fixed())
                .unwrap()
                .0
        })
        .collect();
    assert_eq!(rules.len(), 3);
    assert_eq!(rules[1].scope().package.as_deref(), Some("requests"));
    assert_eq!(rules[1].scope().up_to_version.as_deref(), Some("2.0"));
}
