from pathlib import Path

from awe_backend.schemas import VaultItemInput
from awe_backend.vault import VaultService


def test_vault_encrypts_and_manages_items(tmp_path: Path):
    service = VaultService("test-secret")
    payload = VaultItemInput(
        name="Production token",
        kind="token",
        value="highly-sensitive-value",
        notes="Used by the scanner",
    )

    created = service.create(tmp_path, payload)
    vault_file = tmp_path / ".awe-vault.enc"

    assert vault_file.exists()
    assert b"highly-sensitive-value" not in vault_file.read_bytes()
    assert vault_file.stat().st_mode & 0o777 == 0o600
    assert service.list(tmp_path) == [created]

    assert service.delete(tmp_path, created.id) is True
    assert service.list(tmp_path) == []
    assert service.delete(tmp_path, created.id) is False
