import pyotp

from app import security


def test_password_roundtrip():
    h = security.hash_password("correct horse battery")
    assert security.verify_password("correct horse battery", h)
    assert not security.verify_password("wrong", h)
    assert not security.verify_password("anything", None)


def test_encrypt_roundtrip():
    assert security.decrypt(security.encrypt("geheim")) == "geheim"


def test_totp():
    secret = security.new_totp_secret()
    assert security.verify_totp(secret, pyotp.TOTP(secret).now())
    assert not security.verify_totp(secret, "000000") or pyotp.TOTP(secret).now() == "000000"
    assert security.totp_uri(secret, "admin").startswith("otpauth://totp/SophosStats:admin")
