from privacyforge import AuditLog, Policy, TokenVault, protect, restore


def test_roundtrip_restores_original():
    vault = TokenVault()
    text = "Email rahul.sharma92@examplemail.com or call +91 98200 12345."
    result = protect(text, Policy(), vault=vault)
    assert "rahul.sharma92@examplemail.com" not in result.text
    assert "98200" not in result.text
    assert "⟦EMAIL_1⟧" in result.text
    assert restore(result.text, vault) == text


def test_same_value_reuses_token():
    vault = TokenVault()
    text = "a@b.com and again a@b.com"
    result = protect(text, Policy(), vault=vault)
    assert result.text.count("⟦EMAIL_1⟧") == 2
    assert len(vault) == 1


def test_audit_records_categories_not_values():
    audit = AuditLog()
    vault = TokenVault()
    secret = "rahul.sharma92@examplemail.com"
    protect(f"contact {secret}", Policy(), vault=vault, audit=audit)
    assert audit.summary() == {"EMAIL:redact": 1}
    for entry in audit.entries:
        assert secret not in str(entry)
