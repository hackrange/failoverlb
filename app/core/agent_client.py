"""
Talking to the host agent.

The container cannot touch the host on its own.  Everything that needs root
goes through the agent's unix socket, and the agent decides whether to do it.

Keep this file boring: send a verb, return the answer.  The decisions belong
on the agent side.
"""

import asyncio
import json
import logging
import socket
from pathlib import Path

from app.config import get_settings

log = logging.getLogger("nfm.agent")

# Largest reply we will read.  Configs and cert bundles are well under this;
# it stops a broken agent from exhausting our memory.
MAX_RESPONSE_BYTES = 32 * 1024 * 1024

DEFAULT_TIMEOUT = 90
LONG_TIMEOUT = 400        # certbot and nginx upgrades take a while


class AgentError(Exception):
    """The agent said no, or we could not reach it."""

    def __init__(self, message, code="error"):
        super().__init__(message)
        self.message = message
        self.code = code


class AgentUnavailable(AgentError):
    """
    Cannot reach the agent at all.

    Separate type because the pending change queue retries these later,
    whereas a refused request will not succeed on retry.
    """


class AgentClient:
    def __init__(self, socket_path: Path = None):
        self.socket_path = socket_path or get_settings().agent_socket

    # ---- the actual call ----------------------------------------------------

    async def call(self, verb: str, timeout: int = DEFAULT_TIMEOUT, **kwargs) -> dict:
        """
        Send one verb and wait for the answer.

        Opens a fresh connection each time.  Calls are infrequent, and a pooled
        connection going stale mid-apply is far worse than the setup cost.
        """
        if not Path(self.socket_path).exists():
            raise AgentUnavailable(
                f"no agent socket at {self.socket_path}.  Is nginx-mgr-agent running?",
                "no_socket",
            )

        payload = {"verb": verb, **kwargs}
        request = (json.dumps(payload) + "\n").encode()

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(str(self.socket_path)),
                timeout=10,
            )
        except (OSError, socket.error) as exc:
            raise AgentUnavailable(f"could not connect to the agent: {exc}", "connect_failed")
        except asyncio.TimeoutError:
            raise AgentUnavailable("timed out connecting to the agent", "connect_timeout")

        try:
            writer.write(request)
            await writer.drain()

            line = await asyncio.wait_for(
                reader.readline(),
                timeout=timeout,
            )
            if not line:
                raise AgentUnavailable("the agent closed the connection without answering", "no_reply")
            if len(line) > MAX_RESPONSE_BYTES:
                raise AgentError("the agent sent back more than we will read", "too_large")

        except asyncio.TimeoutError:
            raise AgentError(f"the agent did not answer {verb} within {timeout}s", "timeout")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        try:
            response = json.loads(line)
        except json.JSONDecodeError:
            raise AgentError("the agent sent back something that was not json", "bad_reply")

        if not response.get("ok"):
            raise AgentError(
                response.get("error", "the agent refused, with no reason given"),
                response.get("code", "error"),
            )

        return response.get("data", {})

    # ---- the verbs, wrapped so callers do not pass strings around -----------

    async def ping(self):
        return await self.call("ping", timeout=10)

    async def status(self):
        return await self.call("status", timeout=30)

    async def config_test(self):
        return await self.call("config_test", timeout=60)

    async def write_staging(self, files: dict):
        return await self.call("write_staging", files=files, timeout=60)

    async def test_staging(self):
        return await self.call("test_staging", timeout=60)

    async def apply(self, reload: bool = True, label: str = "apply"):
        return await self.call("apply", reload=reload, label=label, timeout=120)

    async def reload(self):
        return await self.call("reload", timeout=60)

    async def service(self, action: str):
        return await self.call("service", action=action, timeout=60)

    async def read_file(self, path: str):
        return await self.call("read_file", path=path, timeout=30)

    async def list_dir(self, path: str):
        return await self.call("list_dir", path=path, timeout=30)

    async def acme_token_write(self, token: str, value: str):
        return await self.call("acme_token_write", token=token, value=value, timeout=30)

    async def acme_token_delete(self, token: str):
        return await self.call("acme_token_delete", token=token, timeout=30)

    async def certbot(self, **kwargs):
        return await self.call("certbot", timeout=LONG_TIMEOUT, **kwargs)

    async def cert_list(self):
        return await self.call("cert_list", timeout=60)

    async def cert_export(self, name: str):
        return await self.call("cert_export", name=name, timeout=60)

    async def cert_import(self, name: str, bundle: dict):
        return await self.call("cert_import", name=name, bundle=bundle, timeout=60)

    async def cert_forget(self, name: str):
        return await self.call("cert_forget", name=name, timeout=30)

    async def list_backups(self):
        return await self.call("list_backups", timeout=30)

    async def rollback(self, name: str = None):
        return await self.call("rollback", name=name, timeout=120)

    async def nginx_metrics(self, port: int = 7081):
        return await self.call("nginx_metrics", port=port, timeout=20)

    async def public_ip(self):
        return await self.call("public_ip", timeout=45)

    async def local_addresses(self):
        return await self.call("local_addresses", timeout=20)

    async def write_hook_scripts(self, scripts: dict):
        return await self.call("write_hook_scripts", scripts=scripts, timeout=30)

    async def nginx_upgrade(self, **kwargs):
        # Building nginx from source is slow.
        return await self.call("nginx_upgrade", timeout=1800, **kwargs)

    async def nginx_upgrade_status(self):
        return await self.call("nginx_upgrade_status", timeout=20)

    async def is_available(self) -> bool:
        """Quick yes or no.  Used by the health page and the sync worker."""
        try:
            await self.ping()
            return True
        except AgentError:
            return False


# One shared client.  It holds no state, just the socket path.
_client = None


def get_agent() -> AgentClient:
    global _client
    if _client is None:
        _client = AgentClient()
    return _client
