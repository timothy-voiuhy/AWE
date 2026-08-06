import pytest
from pydantic import ValidationError

from awe_backend.config import Settings


def test_production_rejects_insecure_auth_configuration():
    with pytest.raises(ValidationError):
        Settings(environment="production")


def test_production_accepts_explicit_security_configuration():
    settings = Settings(
        environment="production",
        secret_key="x" * 32,
        admin_password_hash="configured-hash",
        secure_cookies=True,
    )
    assert settings.auth_enabled
