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

    # ---- where this came from -----------------------------------------------
    # Only used to build the copy and paste command on the Cluster page when you
    # add a node.  Change these if you run your own fork or install somewhere
    # other than the default, so the command the GUI hands out actually works.
    repo_url: str = Field(default="https://git.hackrange.com/trice/nginx-gui-mgmt.git")
    install_dir: str = Field(default="/data/docker/nginx-gui-mgmt")

    # ---- listeners ----------------------------------------------------------
    gui_port: int = Field(default=7443, ge=1, le=65535)
    peer_port: int = Field(default=7444, ge=1, le=65535)
    bind_address: str = Field(default="0.0.0.0")

    # Serve the GUI under a path prefix instead of at the root.  Set this when
    # something in front proxies us at, say, /nginx-manager rather than on a
    # hostname of our own.  Leave it empty for the normal case.
    #
    # Every link, form action and cookie path is built from this, so setting it
    # is all you have to do.  Getting it wrong shows up immediately as a login
    # page with no stylesheet.
    root_path: str = Field(default="")

    # ---- where things live --------------------------------------------------
    data_dir: Path = Field(default=Path("/data"))
    agent_socket: Path = Field(default=Path("/run/nginxmgr/agent.sock"))

    # Read only mounts of the host, so the GUI can show what is really running.
    host_nginx_dir: Path = Field(default=Path("/host/etc/nginx"))
    host_letsencrypt_dir: Path = Field(default=Path("/host/etc/letsencrypt"))

    # ---- security -----------------------------------------------------------
    secret_key: str = Field(default="")
    admin_allowlist: str = Field(default="")

    # Addresses whose X-Forwarded-For we are willing to believe.
    #
    # Empty by default and that matters.  With nothing here we read the address
    # the connection actually came from and ignore the header completely, which
    # is the only safe answer when the GUI is reached directly: anybody can send
    # X-Forwarded-For, so believing it from a stranger lets them put a
    # management address in it and walk through the allow list.
    #
    # Put something here only when a proxy you control is genuinely in front of
    # the GUI.  Get it wrong in the other direction, by proxying without setting
    # this, and every visitor arrives looking like the proxy, which is usually
    # loopback, and the allow list passes the whole internet.
    trusted_proxies: str = Field(default="")
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
    # The default interval a new pool gets.  Each pool can override it, and the
    # checker honours whatever the pool asks for.
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
    def trusted_proxy_networks(self):
        """
        Which addresses are allowed to tell us who the client really is.

        A bad entry is skipped rather than crashing, same as the allow list, but
        the direction of the mistake is different and worse.  A typo here does
        not lock you out, it quietly stops us believing a proxy we meant to
        believe, and then everybody arrives looking like that proxy.  So the
        dashboard says out loud when this is set and when it is not.
        """
        nets = []
        for raw in self.trusted_proxies.split(","):
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
