"""AI tool wrappers over JWT decode/attack helpers.

Reuses the pure (no network I/O) crypto helpers from gui.jwt_page instead of
re-implementing JWT parsing/forging — those never need permission since they only
transform a token string locally. run_jwt_tool_container mirrors JwtPage's own
`docker run ticarpi/jwt_tool` invocation.
"""
from __future__ import annotations

import json
import subprocess

from forgeai import ToolRegistry

from ai.context import AiToolContext
from gui.jwt_page import (
    _alg_none_attack,
    _blank_password_attack,
    _kid_attack,
    _null_sig_attack,
    _parse_jwt,
    _tamper_timestamps,
)

_ATTACKS = ("alg_none", "null_sig", "blank_password", "kid")


def _make_decode_jwt(ctx: AiToolContext):
    def decode_jwt(token: str) -> str:
        """Decode a JWT's header and payload (no signature verification).

        Args:
            token: The JWT string (header.payload.signature).
        """
        header, payload, sig_hex, _h_b64, _p_b64 = _parse_jwt(token)
        if header is None:
            return "Error: could not parse token — expected header.payload.signature"
        return json.dumps({"header": header, "payload": payload, "signature_hex": sig_hex})

    return decode_jwt


def _make_jwt_attack_preview(ctx: AiToolContext):
    def jwt_attack_preview(token: str, attack: str, secret: str = "", kid_value: str = "") -> str:
        """Craft a forged JWT locally for a known attack, without sending it anywhere.

        Args:
            token: The source JWT to base the attack on.
            attack: One of alg_none, null_sig, blank_password, kid.
            secret: HMAC secret to sign with (required for the kid attack).
            kid_value: Value to inject into the "kid" header claim (required for the kid attack).
        """
        if attack not in _ATTACKS:
            return f"Error: attack must be one of {_ATTACKS}"
        header, payload, _sig_hex, h_b64, p_b64 = _parse_jwt(token)
        if header is None:
            return "Error: could not parse token"

        if attack == "alg_none":
            return _alg_none_attack(h_b64, p_b64)
        if attack == "null_sig":
            return _null_sig_attack(h_b64, p_b64)
        if attack == "blank_password":
            return _blank_password_attack(h_b64, p_b64)
        # kid
        return _kid_attack(h_b64, p_b64, kid_value, secret.encode())

    return jwt_attack_preview


def _make_tamper_jwt_timestamps(ctx: AiToolContext):
    def tamper_jwt_timestamps(payload_json: str, preset: str) -> str:
        """Modify exp/nbf/iat claims in a JWT payload JSON string.

        Args:
            payload_json: The JWT payload as a JSON string.
            preset: One of +24h, +30d, +1yr, max, remove_exp, remove_nbf, now_iat.
        """
        return _tamper_timestamps(payload_json, preset)

    return tamper_jwt_timestamps


def _make_run_jwt_tool_container(ctx: AiToolContext):
    def run_jwt_tool_container(token: str, target_url: str = "", mode: str = "at") -> str:
        """Run `ticarpi/jwt_tool` in Docker against a token (algorithm confusion,
        signature attacks, timestamp tampering, etc.) and return its output.

        Args:
            token: The JWT to analyze/attack.
            target_url: Optional URL to replay the forged token against.
            mode: jwt_tool mode flag, e.g. "at" (all tests), "pb" (playbook), "rs" (RS/HS confusion).
        """
        args = ["docker", "run", "--rm", "ticarpi/jwt_tool", token]
        if target_url:
            args += ["-t", target_url, "-rh", f"Authorization: Bearer {token}", "-M", mode]
        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=120)
        except FileNotFoundError:
            return "Error: docker not found — is Docker installed and on PATH?"
        except subprocess.TimeoutExpired:
            return "Error: jwt_tool timed out after 120s"
        output = (result.stdout or "") + (result.stderr or "")
        return output[-8000:] if len(output) > 8000 else output

    return run_jwt_tool_container


def register_all(registry: ToolRegistry, ctx: AiToolContext) -> None:
    registry.register(_make_decode_jwt(ctx))
    registry.register(_make_jwt_attack_preview(ctx))
    registry.register(_make_tamper_jwt_timestamps(ctx))
    registry.register(_make_run_jwt_tool_container(ctx), requires_permission=True)
