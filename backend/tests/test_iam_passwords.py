import pytest

from app.iam.exceptions import InvalidPassword
from app.iam.passwords import PasswordService, validate_password


@pytest.fixture
def service():
    return PasswordService(memory_cost=1024, time_cost=1, parallelism=1)


def test_hash_uses_argon2id_and_verifies_password(service):
    encoded = service.hash_password("correct horse battery staple")
    assert encoded.startswith("$argon2id$")
    assert service.verify_password(encoded, "correct horse battery staple")
    assert not service.verify_password(encoded, "different long passphrase")


def test_hashes_use_independent_salts(service):
    first = service.hash_password("correct horse battery staple")
    second = service.hash_password("correct horse battery staple")
    assert first != second


@pytest.mark.parametrize("password", ["", "short", "12345678901234", None, 123])
def test_rejects_short_or_non_text_password(password):
    with pytest.raises(InvalidPassword):
        validate_password(password)


def test_accepts_long_passphrase_without_composition_rules():
    validate_password("correct horse battery staple")


def test_rejects_password_over_utf8_byte_limit():
    with pytest.raises(InvalidPassword, match="1024"):
        validate_password("é" * 513)


def test_does_not_trim_or_normalize_passwords(service):
    value = "  correct horse battery staple  "
    encoded = service.hash_password(value)
    assert service.verify_password(encoded, value)
    assert not service.verify_password(encoded, value.strip())


@pytest.mark.parametrize("encoded", ["", "not-a-hash", "$argon2id$broken", None])
def test_malformed_hashes_fail_closed(service, encoded):
    assert not service.verify_password(encoded, "correct horse battery staple")
    assert service.needs_rehash(encoded)


def test_rehash_only_occurs_after_successful_verification():
    old = PasswordService(memory_cost=1024, time_cost=1, parallelism=1)
    current = PasswordService(memory_cost=2048, time_cost=2, parallelism=1)
    old_hash = old.hash_password("correct horse battery staple")
    upgraded = current.rehash_if_needed(old_hash, "correct horse battery staple")
    assert upgraded is not None and upgraded != old_hash
    assert current.verify_password(upgraded, "correct horse battery staple")
    assert current.rehash_if_needed(old_hash, "wrong password") is None


def test_current_parameters_do_not_trigger_rehash(service):
    encoded = service.hash_password("correct horse battery staple")
    assert not service.needs_rehash(encoded)
    assert service.rehash_if_needed(encoded, "correct horse battery staple") is None


def test_rejects_nonpositive_argon2_parameters():
    with pytest.raises(ValueError, match="positive"):
        PasswordService(memory_cost=0)
