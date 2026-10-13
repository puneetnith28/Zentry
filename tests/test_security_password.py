from app.core.security import (
    get_password_hash,
    validate_password_complexity,
    verify_password,
)


def test_password_hashing_and_verification():
    password = "SuperSecretPassword123!"
    hashed = get_password_hash(password)

    # Hash should be non-empty and different from plain password
    assert hashed != password
    assert hashed.startswith("$2b$")

    # Distinct hashes for the same password due to random salt
    hashed2 = get_password_hash(password)
    assert hashed != hashed2

    # Verification
    assert verify_password(password, hashed) is True
    assert verify_password(password, hashed2) is True
    assert verify_password("WrongPassword123!", hashed) is False
    assert verify_password("", hashed) is False
    assert verify_password(password, "invalid_hash_string") is False


def test_password_complexity_validation():
    # Valid passwords
    assert validate_password_complexity("StrongPass123!") == (True, None)
    assert validate_password_complexity("Valid1@Password") == (True, None)

    # Too short (< 8 chars)
    valid, err = validate_password_complexity("Short1!")
    assert valid is False
    assert "at least 8 characters" in err

    # Missing uppercase
    valid, err = validate_password_complexity("alllowercase123!")
    assert valid is False
    assert "uppercase" in err

    # Missing lowercase
    valid, err = validate_password_complexity("ALLUPPERCASE123!")
    assert valid is False
    assert "lowercase" in err

    # Missing digit or special char
    valid, err = validate_password_complexity("NoDigitsOrSpecialLetters")
    assert valid is False
    assert "digit or special" in err
