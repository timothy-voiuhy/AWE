import pytest
from pydantic import ValidationError

from awe_backend.schemas import TerminalConnectRequest
from awe_backend.terminal_profiles import TerminalProfileStore


def test_terminal_connection_accepts_private_key_without_password():
    request = TerminalConnectRequest(
        host="example.com",
        username="tester",
        password="",
        private_key="private-key-data",
    )

    assert request.password == ""


def test_terminal_connection_can_explicitly_trust_host_key():
    request = TerminalConnectRequest(
        host="example.com", username="tester", password="secret", trust_host_key=True
    )

    assert request.trust_host_key is True


def test_terminal_connection_requires_password_or_private_key():
    with pytest.raises(ValidationError, match="A password or private key is required"):
        TerminalConnectRequest(host="example.com", username="tester", password="")


def test_terminal_profile_can_be_updated(tmp_path):
    store = TerminalProfileStore(tmp_path)
    created = store.create("Production", "old.example.com", 22, "old-user")

    updated = store.update(created["id"], "Production SSH", "new.example.com", 2222, "new-user")

    assert updated == {
        "id": created["id"],
        "name": "Production SSH",
        "host": "new.example.com",
        "port": 2222,
        "username": "new-user",
    }
    assert store.update("missing", "Name", "host", 22, "user") is None
