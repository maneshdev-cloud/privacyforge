import pytest

from privacyforge import PrivacyBlockError, Policy, TokenVault, protect


def test_block_policy_raises_without_leaking_value():
    policy = Policy(rules={"CARD": "block"})
    with pytest.raises(PrivacyBlockError) as excinfo:
        protect("pay 4111 1111 1111 1111", policy, vault=TokenVault())
    assert "CARD" in str(excinfo.value)
    assert "4111" not in str(excinfo.value)


def test_warn_policy_passes_value_through_with_warning():
    policy = Policy(rules={"EMAIL": "warn"})
    result = protect("mail a@b.com", policy, vault=TokenVault())
    assert "a@b.com" in result.text
    assert result.warnings == ["EMAIL"]


def test_allow_policy_passes_silently():
    policy = Policy(rules={"EMAIL": "allow"})
    result = protect("mail a@b.com", policy, vault=TokenVault())
    assert "a@b.com" in result.text
    assert result.warnings == []


def test_invalid_action_rejected():
    with pytest.raises(ValueError):
        Policy(rules={"EMAIL": "shred"})


def test_policy_from_dict():
    policy = Policy.from_dict({"rules": {"PAN": "block"}, "default_action": "warn"})
    assert policy.action_for("PAN") == "block"
    assert policy.action_for("EMAIL") == "warn"
