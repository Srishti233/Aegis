import pytest

from app.detectors.secrets import luhn_ok, redact, scan_secrets, shannon_entropy
from app.detectors.types import SecretFinding


def types(text):
    return [f.type for f in scan_secrets(text)]


@pytest.mark.parametrize("text,expected", [
    ("key sk-abcdefghijklmnopqrstuvwxyz1234", "OPENAI_KEY"),
    ("AKIAIOSFODNN7EXAMPLE", "AWS_KEY"),
    ("ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8", "GITHUB_TOKEN"),
    ("AIza" + "SyA-1234567890abcdefghijklmnopqrstu", "GOOGLE_KEY"),
    ("sk_live_" + "abcdefghijklmnop1234", "STRIPE_KEY"),
    ("xoxb-1234567890-abcdefghij", "SLACK_TOKEN"),
    ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123_-xyz", "JWT"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----", "PRIVATE_KEY"),
    ("mail bob.smith@example.com now", "EMAIL"),
    ("call +1 415 555 2671", "PHONE"),
    ("ssn 123-45-6789", "GOV_ID"),
    ("password = hunter2hunter2hunter2", "GENERIC_SECRET"),
])
def test_detects(text, expected):
    assert expected in types(text)


def test_luhn():
    assert luhn_ok("4111111111111111") and luhn_ok("5500005555555559")
    assert not luhn_ok("4111111111111112")


def test_credit_card_requires_luhn():
    assert types("card 4111 1111 1111 1111") == ["CREDIT_CARD"]
    assert "CREDIT_CARD" not in types("number 4111 1111 1111 1112")


@pytest.mark.parametrize("text", [
    "Order number 88213947 shipped", "Version 3.14.15926535", "IP 192.168.100.200", "Date 2024-01-15",
    "commit 9fceb02d0ae598e95dc970b74767f19372d61af7", "How do I sort a list in Python?",
])
def test_no_false_positives_on_numbers_and_hashes(text):
    assert types(text) == []


def test_redaction_uses_typed_placeholders_and_respects_actions():
    text = "mail a@b.com key AKIAIOSFODNN7EXAMPLE"
    found = [SecretFinding(f.type, f.start, f.end, "redact" if f.type == "AWS_KEY" else "flag") for f in scan_secrets(text)]
    out = redact(text, found)
    assert "[REDACTED_AWS_KEY]" in out and "a@b.com" in out
    assert redact(text, found, ("redact", "flag")) == "mail [REDACTED_EMAIL] key [REDACTED_AWS_KEY]"


def test_entropy():
    assert shannon_entropy("aaaa") == 0 and shannon_entropy("abcd") == 2.0 and shannon_entropy("") == 0
