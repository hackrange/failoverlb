"""
Settings for the manager.

Everything comes in through environment variables, which is what docker
compose is good at handing us.  Anything secret gets read once here and then
lives in memory, never written back out to disk in the clear.
"""

import base64
import ipaddress
import os
import secrets
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NFM_",
        case_sensitive=False,
        extra="ignore",
    )

    # ---- who this node is ---------------------------------------------------
    node_name: str = Field(default="nginx-node")
    node_address: str = Field(default="127.0.0.1")
    cluster_priority: int = Field(default=100, ge=1, le=255)

    # ---- listeners ----------------------------------------------------------
    gui_port: int = Field(default=7443, ge=1, le=65535)
    peer_port: int = Field(default=7444, ge=1, le=65535)
    bind_address: str = Field(default="0.0.0.0")

    # ---- where things live --------------------------------------------------
    data_dir: Path = Field(default=Path("/data"))
    agent_socket: Path = Field(default=Path("/run/nginxmgr/agent.sock"))

    # Read only mounts of the host, so the GUI can show what is really running.
    host_nginx_dir: Path = Field(default=Path("/host/etc/nginx"))
    host_letsencrypt_dir: Path = Field(default=Path("/host/etc/letsencrypt"))

    # ---- security -----------------------------------------------------------
    secret_key: str = Field(default="")
    admin_allowlist: str = Field(default="")
    session_timeout_minutes: int = Field(default=60, ge=5, le=1440)

    # How many bad passwords before we lock the account, and for how long.
    max_login_attempts: int = Field(default=5, ge=3, le=20)
    lockout_minutes: int = Field(default=15, ge=1, le=1440)

    # ---- OIDC ---------------------------------------------------------------
    oidc_enabled: bool = Field(default=False)
    oidc_discovery_url: str = Field(default="")
    oidc_client_id: str = Field(default="")
    oidc_client_secret: str = Field(default="")
    oidc_redirect_base: str = Field(default="")
    oidc_groups_claim: str = Field(default="groups")
    oidc_admin_group: str = Field(default="nginx-admins")
    oidc_operator_group: str = Field(default="nginx-operators")
    oidc_viewer_group: str = Field(default="nginx-viewers")

    # ---- certificates -------------------------------------------------------
    acme_email: str = Field(default="")
    acme_staging: bool = Field(default=False)

    # Start trying to renew this many days before the cert runs out.  Lets
    # Encrypt certs are good for 90 days and they tell you to renew at 30, so
    # this leaves a solid window to notice and fix a failure.
    acme_renew_days_before: int = Field(default=30, ge=1, le=89)

    # ---- how often background jobs run, in seconds --------------------------
    health_check_interval: int = Field(default=10, ge=2, le=300)
    heartbeat_interval: int = Field(default=5, ge=1, le=60)
    cert_check_interval: int = Field(default=3600, ge=60)
    drift_check_interval: int = Field(default=300, ge=30)

    # How long a node can go quiet before the rest call it dead.  Needs to be a
    # good bit bigger than heartbeat_interval or a slow network turns into a
    # failover nobody asked for.
    node_dead_after: int = Field(default=20, ge=5, le=300)

    # ---- day to day ---------------------------------------------------------
    log_level: str = Field(default="info")

    @field_validator("secret_key")
    @classmethod
    def _need_a_real_key(cls, v):
        """
        Refuse to run without a real secret key.

        Making one up at startup sounds friendly, but then every restart
        invalidates every session and rotates the key that encrypts stored
        secrets, which means those secrets can never be read again.  Better to
        stop now with a clear message.
        """
        if not v:
            return v
        if len(v) < 32:
            raise ValueError(
                "NFM_SECRET_KEY is too short.  Make one with: openssl rand -base64 48"
            )
        return v

    @property
    def db_path(self) -> Path:
        return self.data_dir / "fleet.db"

    @property
    def db_url(self) -> str:
        return f"sqlite:///{self.db_path}"

    @property
    def pki_dir(self) -> Path:
        """Cluster CA and this node's own key pair."""
        return self.data_dir / "pki"

    @property
    def admin_networks(self):
        """
        Turn the allow list string into networks we can actually test against.

        A bad entry is skipped instead of crashing the app.  Getting locked out
        of your own management GUI because of a typo in a CIDR is a worse
        outcome than one entry quietly not matching.
        """
        nets = []
        for raw in self.admin_allowlist.split(","):
            raw = raw.strip()
            if not raw:
                continue
            try:
                nets.append(ipaddress.ip_network(raw, strict=False))
            except ValueError:
                continue
        return nets

    @property
    def fernet_key(self) -> bytes:
        """
        Turn the secret key into a 32 byte key we can encrypt with.

        Hashing it means the operator can paste in whatever length string they
        like and we still end up with the right size.
        """
        import hashlib

        digest = hashlib.sha256(self.secret_key.encode()).digest()
        return base64.urlsafe_b64encode(digest)


@lru_cache
def get_settings() -> Settings:
    return Settings()


def generate_secret_key() -> str:
    """Used by install.sh through a tiny python one liner."""
    return base64.b64encode(secrets.token_bytes(48)).decode()


if __name__ == "__main__":
    print(generate_secret_key())
