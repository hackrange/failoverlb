"""
Settings for the manager.

Everything comes from environment variables (NFM_*), usually set by docker
compose.  Secrets are read once here and kept in memory, never written back
to disk in the clear.
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
    # Used only for the add-node command shown on the Cluster page.  Change
    # these if you run a fork or install elsewhere.  The repo is cloned
    # anonymously, so a wrong or private URL shows up as a GitHub login prompt
    # rather than a 404.
    repo_url: str = Field(default="https://github.com/hackrange/failoverlb.git")
    install_dir: str = Field(default="/data/docker/failoverlb")

    # ---- listeners ----------------------------------------------------------
    gui_port: int = Field(default=7443, ge=1, le=65535)
    peer_port: int = Field(default=7444, ge=1, le=65535)
    bind_address: str = Field(default="0.0.0.0")

    # Path prefix for the GUI, e.g. /nginx-manager when a proxy serves us under
    # a path.  Empty for the normal case.  All links, form actions and cookie
    # paths use it; a wrong value shows up as a login page with no stylesheet.
    root_path: str = Field(default="")

    # ---- where things live --------------------------------------------------
    data_dir: Path = Field(default=Path("/data"))
    agent_socket: Path = Field(default=Path("/run/nginxmgr/agent.sock"))

    # Read-only host mounts, so the GUI can show what is really running.
    host_nginx_dir: Path = Field(default=Path("/host/etc/nginx"))
    host_letsencrypt_dir: Path = Field(default=Path("/host/etc/letsencrypt"))

    # ---- security -----------------------------------------------------------
    secret_key: str = Field(default="")
    admin_allowlist: str = Field(default="")

    # Addresses whose X-Forwarded-For we believe.
    #
    # Empty by default: we use the real peer address and ignore the header,
    # since anyone can send X-Forwarded-For and spoof a management address past
    # the allow list.  Set it only when a proxy you control is in front.  The
    # opposite mistake (proxying without setting this) makes every visitor look
    # like the proxy, often loopback, and the allow list passes everyone.
    trusted_proxies: str = Field(default="")
    session_timeout_minutes: int = Field(default=60, ge=5, le=1440)

    # Failed passwords before the account locks, and for how long.
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

    # Days before expiry to start renewing.  Let's Encrypt certs last 90 days
    # and they recommend renewing at 30, which leaves time to fix a failure.
    acme_renew_days_before: int = Field(default=30, ge=1, le=89)

    # ---- how often background jobs run, in seconds --------------------------
    # Default for new pools; each pool can override it.
    health_check_interval: int = Field(default=10, ge=2, le=300)
    heartbeat_interval: int = Field(default=5, ge=1, le=60)
    cert_check_interval: int = Field(default=3600, ge=60)
    drift_check_interval: int = Field(default=300, ge=30)

    # Silence before peers declare a node dead.  Keep it well above
    # heartbeat_interval or a slow network causes a needless failover.
    node_dead_after: int = Field(default=20, ge=5, le=300)

    # ---- is our own frontend actually serving -------------------------------
    # A request through this node's own public listener, so the GSLB can tell
    # a wedged nginx from a running one.  See app/core/frontend_probe.py.
    frontend_probe_interval: int = Field(default=10, ge=2, le=300)

    # Empty means NFM_NODE_ADDRESS, the same address GSLB hands out, so the
    # probe tests what clients actually hit.  Override if nginx here does not
    # listen on that address.
    frontend_probe_host: str = Field(default="")
    frontend_probe_port: int = Field(default=443, ge=1, le=65535)

    # Sent as SNI and Host so the probe hits a real server block instead of
    # the default.  Empty still shows whether a worker is answering.
    frontend_probe_server_name: str = Field(default="")

    # Short on purpose: a wedged listener never answers, and a healthy local
    # one replies in milliseconds.
    frontend_probe_timeout: float = Field(default=5.0, ge=0.5, le=60.0)

    # Consecutive results needed to change the verdict.  Slower to mark down
    # than up: a false "down" pulls a working node out of DNS, a false "up"
    # costs one more interval.
    frontend_probe_fail_after: int = Field(default=3, ge=1, le=20)
    frontend_probe_pass_after: int = Field(default=2, ge=1, le=20)

    # Restart nginx when the probe says this node stopped serving.  Pulling
    # the node from DNS only routes around a wedge; this fixes it.  It must be
    # a restart: a reload keeps the same shared memory zones, including one
    # left locked by a dead worker.  Turn off to leave a wedged node alone
    # (and out of DNS) for someone to inspect.
    frontend_watchdog: bool = Field(default=True)

    # Wait between restarts, and a daily cap.  Restarting every cycle when it
    # doesn't help just drops connections; hitting the cap means a person is
    # needed.
    frontend_watchdog_cooldown: int = Field(default=600, ge=30, le=86400)
    frontend_watchdog_max_per_day: int = Field(default=4, ge=1, le=50)

    # ---- how hard a flapping backend may work nginx ------------------------
    # Each pool member state change rewrites the config and reloads nginx on
    # every node.  A flapping backend can turn that into an outage: on August
    # 24, 2026 four reloads in 102 seconds killed every worker.
    #
    # Batch changes for this long so several backends recovering together
    # cause one reload.
    health_reload_debounce: int = Field(default=5, ge=1, le=120)

    # Hard minimum between reloads.  Cheap, because upstreams carry max_fails
    # and fail_timeout, so nginx avoids a dead backend within seconds anyway.
    # The rewrite only makes that state visible and durable.
    health_reload_min_interval: int = Field(default=60, ge=5, le=3600)

    # Cap over a rolling hour.  Past it, changes are delayed (not dropped) and
    # the log says something is flapping and needs a person.
    health_reload_max_per_hour: int = Field(default=12, ge=1, le=600)

    # ---- day to day ---------------------------------------------------------
    log_level: str = Field(default="info")

    @field_validator("secret_key")
    @classmethod
    def _need_a_real_key(cls, v):
        """
        Refuse a short secret key.

        We never generate one at startup: every restart would kill all
        sessions and make stored encrypted secrets unreadable.
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
        Parse the allow list.  Bad entries are skipped rather than crashing,
        so a CIDR typo can't lock you out of the GUI.
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
        Parse trusted_proxies, skipping bad entries.  A typo here silently
        makes every client look like the proxy, which is why the dashboard
        shows whether this is set.
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
        Derive a 32 byte Fernet key from the secret key.  Hashing accepts
        any input length.
        """
        import hashlib

        digest = hashlib.sha256(self.secret_key.encode()).digest()
        return base64.urlsafe_b64encode(digest)


@lru_cache
def get_settings() -> Settings:
    return Settings()


def generate_secret_key() -> str:
    """Used by install.sh via a python one-liner."""
    return base64.b64encode(secrets.token_bytes(48)).decode()


if __name__ == "__main__":
    print(generate_secret_key())
