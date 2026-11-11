from privacyforge.detectors import detect, luhn_valid, verhoeff_valid


def categories(text):
    return [f.category for f in detect(text)]


def test_verhoeff_and_luhn_helpers():
    assert verhoeff_valid("234567890124")
    assert not verhoeff_valid("234567890125")
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")


def test_email_detected():
    findings = detect("reach me at rahul.sharma92@examplemail.com please")
    assert [f.category for f in findings] == ["EMAIL"]
    assert findings[0].value == "rahul.sharma92@examplemail.com"


def test_indian_phone_detected():
    assert "PHONE" in categories("call me on +91 98200 12345 today")
    assert "PHONE" in categories("my number is 9820012345")


def test_aadhaar_detected_and_checksum_enforced():
    assert "AADHAAR" in categories("Aadhaar: 2345 6789 0124")
    # Same shape, wrong Verhoeff check digit -> not flagged.
    assert "AADHAAR" not in categories("Aadhaar: 2345 6789 0125")


def test_pan_detected():
    findings = detect("PAN ABCPE1234F on file")
    assert [f.category for f in findings] == ["PAN"]


def test_card_detected_and_luhn_enforced():
    assert "CARD" in categories("pay with 4111 1111 1111 1111 now")
    assert "CARD" not in categories("pay with 4111 1111 1111 1112 now")


def test_api_key_formats_detected():
    assert "API_KEY" in categories("key = sk-proj-FAKE0123456789abcdefFAKE")
    assert "API_KEY" in categories("token: AKIAIOSFODNN7EXAMPLE")
    assert "API_KEY" in categories("api_key = abcdef1234567890XYZ")


def test_password_assignment_detected():
    findings = detect("the wifi password is monsoonTiger42 ok")
    pw = [f for f in findings if f.category == "PASSWORD"]
    assert pw and pw[0].value == "monsoonTiger42"


def test_high_entropy_secret_detected():
    token = "Xk9mQ2vLp8sR4nT6wYzA1bC3"
    assert "SECRET" in categories(f"session {token} end")


def test_clean_text_has_no_findings():
    assert detect("The quick brown fox jumps over the lazy dog.") == []


def test_findings_do_not_overlap():
    findings = detect("mail a@b.com or call +91 98200 12345")
    spans = sorted((f.start, f.end) for f in findings)
    for (_, end), (start, _) in zip(spans, spans[1:]):
        assert end <= start
