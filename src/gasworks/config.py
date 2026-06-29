"""Endpoint + client configuration, with GASWORKS_* env overrides for dev/testing."""

import os
from dataclasses import dataclass

from . import __version__

DEFAULT_STS_BASE = "https://works.gascity.com"
DEFAULT_OIDC_ISSUER = "https://auth.gascity.com/realms/gascity"
DEFAULT_CLIENT_ID = "gasworks-cli"
# Fixed loopback port for the browser auth-code flow. It MUST match a redirect URI
# registered on the gasworks-cli realm client (Keycloak's `*` does not span the port,
# so an ephemeral port would not match). The device-code flow needs no redirect URI.
DEFAULT_LOOPBACK_PORT = 9822

USER_AGENT = f"gasworks-cli/{__version__}"


@dataclass(frozen=True)
class Config:
    sts_base: str
    oidc_issuer: str
    client_id: str
    loopback_port: int

    # --- STS (works.gascity.com) ---
    @property
    def login_url(self) -> str:
        return f"{self.sts_base}/sts/v0/login"

    @property
    def token_url(self) -> str:
        return f"{self.sts_base}/sts/v0/token"

    @property
    def context_url(self) -> str:
        return f"{self.sts_base}/sts/v0/context"

    # --- Keycloak (auth.gascity.com) ---
    @property
    def device_auth_url(self) -> str:
        return f"{self.oidc_issuer}/protocol/openid-connect/auth/device"

    @property
    def authorize_url(self) -> str:
        return f"{self.oidc_issuer}/protocol/openid-connect/auth"

    @property
    def oidc_token_url(self) -> str:
        return f"{self.oidc_issuer}/protocol/openid-connect/token"

    @property
    def revoke_url(self) -> str:
        return f"{self.oidc_issuer}/protocol/openid-connect/revoke"


def load() -> Config:
    """Build Config from defaults + GASWORKS_* env overrides."""
    return Config(
        sts_base=os.environ.get("GASWORKS_STS_URL", DEFAULT_STS_BASE).rstrip("/"),
        oidc_issuer=os.environ.get("GASWORKS_OIDC_ISSUER", DEFAULT_OIDC_ISSUER).rstrip("/"),
        client_id=os.environ.get("GASWORKS_CLIENT_ID", DEFAULT_CLIENT_ID),
        loopback_port=int(os.environ.get("GASWORKS_LOOPBACK_PORT", DEFAULT_LOOPBACK_PORT)),
    )
