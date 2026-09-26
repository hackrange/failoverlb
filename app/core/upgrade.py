"""
Upgrading nginx across the fleet, and adding or dropping modules.

Both are the same job: modules are compiled in, so adding one means
rebuilding nginx.

One node at a time.  A build takes ten to twenty minutes and ends with a
restart, so rolling through the fleet keeps it serving, and a bad build stops
the walk instead of breaking every node.

Per node: build, wait, check nginx is running, the config passes and the
version changed, re-read the module list, then move on.

A failure stops the walk with the remaining nodes untouched.  A partly
upgraded fleet is a normal working state; the manager only offers settings
the oldest node supports.
"""

import asyncio
import json
import logging
import time
from datetime import timedelta

from app.core.agent_client import AgentError, AgentUnavailable, get_agent
from app.core.cluster import ClusterError, NodeUnreachable, PeerClient, get_cluster
from app.db import session_scope
from app.models import Node, NodeState, Pool, utcnow

log = logging.getLogger("nfm.upgrade")


def wants_waf_module() -> bool:
    """
    Whether nginx should be built with the WAF module.

    Every rebuild must answer this, not just the one that enables the WAF.
    The installer builds from the list it is given, so a later version
    upgrade that omitted the WAF would drop it and break every site using it.
    Read fresh from one fleet-wide setting on each build.
    """
    from app.core import settings_store

    return bool(settings_store.get("waf_module"))

# Build timeout.  A full source build with OpenSSL and a dozen modules takes
# ten to twenty minutes, so this is generous.
BUILD_TIMEOUT = 45 * 60

# How often to ask a node how its build is going.
POLL_SECONDS = 15


class UpgradeError(Exception):
    pass


class UpgradeRunner:
    """
    Walks the fleet, one node at a time.

    Progress lives in memory for the GUI to poll.  Deliberately not
    persisted: a half-finished walk should not resume on its own after the
    manager restarts.
    """

    def __init__(self):
        self.state = {
            "running": False,
            "target": {},
            "nodes": {},
            "order": [],
            "current": None,
            "started": None,
            "finished": None,
            "stopped_because": None,
        }
        self._lock = asyncio.Lock()

    # ---- what a run would do, before doing it -------------------------------

    async def plan(self, nginx_version=None, openssl_version=None) -> dict:
        """
        Work out the order and whether it is safe to start.  Shown for review
        before a long fleet-wide rebuild begins.
        """
        with session_scope() as session:
            nodes = session.query(Node).all()
            pools = session.query(Pool).all()

            info = []
            for n in nodes:
                info.append({
                    "name": n.name,
                    "role": n.role.value,
                    "state": n.state.value,
                    "nginx_version": n.nginx_version,
                    "reachable": n.state == NodeState.ONLINE or n.is_self,
                    "nginx_active": n.nginx_active,
                })

            warnings = []
            blockers = []

            offline = [i["name"] for i in info if not i["reachable"]]
            if offline:
                blockers.append(
                    f"these nodes are not answering: {', '.join(offline)}.  "
                    f"Rebuilding while a node is down leaves the fleet on mixed "
                    f"versions with no way to finish the job."
                )

            not_running = [i["name"] for i in info if i["reachable"] and not i["nginx_active"]]
            if not_running:
                warnings.append(
                    f"nginx is not running on: {', '.join(not_running)}.  "
                    f"Fix that first, or you will not be able to tell whether the "
                    f"build broke anything."
                )

            if len(info) < 2:
                warnings.append(
                    "there is only one node, so it will be down for the few seconds "
                    "the service restarts at the end of the build.  With two or more "
                    "nodes the others keep serving throughout."
                )

            for p in pools:
                if p.members and p.healthy_count == 0:
                    warnings.append(
                        f"pool {p.name} already has no healthy backends.  Sort that "
                        f"out before adding a rebuild on top."
                    )

            # Standbys first, active last, so the node taking config changes
            # stays working and a bad early build can still be backed out.
            order = [i["name"] for i in info if i["role"] != "active" and i["reachable"]]
            order += [i["name"] for i in info if i["role"] == "active" and i["reachable"]]

        return {
            "order": order,
            "nodes": info,
            "warnings": warnings,
            "blockers": blockers,
            "can_start": not blockers,
            "target": {
                "nginx_version": nginx_version,
                "openssl_version": openssl_version,
            },
            "estimated_minutes": len(order) * 15,
        }

    # ---- the walk -----------------------------------------------------------

    async def start(self, nginx_version=None, openssl_version=None,
                    actor: str = "system", force: bool = False) -> dict:
        async with self._lock:
            if self.state["running"]:
                raise UpgradeError("an upgrade is already running")

            plan = await self.plan(nginx_version, openssl_version)
            if plan["blockers"] and not force:
                raise UpgradeError("; ".join(plan["blockers"]))
            if not plan["order"]:
                raise UpgradeError("there are no reachable nodes to upgrade")

            self.state = {
                "running": True,
                "target": plan["target"],
                "order": plan["order"],
                "nodes": {n: {"state": "waiting"} for n in plan["order"]},
                "current": None,
                "started": utcnow().isoformat(),
                "finished": None,
                "stopped_because": None,
                "actor": actor,
            }

        asyncio.create_task(self._walk())
        return dict(self.state)

    async def _walk(self):
        from app.core import audit

        try:
            for name in self.state["order"]:
                self.state["current"] = name
                self.state["nodes"][name] = {"state": "starting"}

                log.warning("rebuilding nginx on %s", name)
                audit.record("nginx.upgrade.start", user=self.state.get("actor"),
                             object_type="node", object_name=name,
                             changes=self.state["target"])

                ok, detail = await self._upgrade_one(name)

                self.state["nodes"][name] = {
                    "state": "done" if ok else "failed",
                    "detail": detail,
                }

                audit.record("nginx.upgrade.finish", user=self.state.get("actor"),
                             object_type="node", object_name=name,
                             result="success" if ok else "failed", detail=str(detail)[:2000])

                if not ok:
                    # Stop.  A partly upgraded fleet works; carrying on could
                    # break the rest the same way.
                    self.state["stopped_because"] = (
                        f"{name} did not come back cleanly, so the remaining nodes "
                        f"were left alone.  Sort {name} out and start again."
                    )
                    log.error("stopping the upgrade: %s failed", name)
                    for other in self.state["order"]:
                        if self.state["nodes"][other]["state"] == "waiting":
                            self.state["nodes"][other] = {"state": "skipped"}
                    break

        except Exception as exc:
            log.exception("the upgrade walk blew up")
            self.state["stopped_because"] = f"the upgrade stopped: {exc}"
        finally:
            self.state["running"] = False
            self.state["current"] = None
            self.state["finished"] = utcnow().isoformat()

    async def _upgrade_one(self, name: str):
        """Build on one node and wait for it.  Returns (ok, detail)."""
        settings_before = await self._node_version(name)

        try:
            await self._call(name, "nginx_upgrade", {
                "nginx_version": self.state["target"].get("nginx_version"),
                "openssl_version": self.state["target"].get("openssl_version"),
                "with_modsecurity": wants_waf_module(),
            })
        except (AgentError, NodeUnreachable, ClusterError) as exc:
            return False, f"could not start the build: {exc}"

        self.state["nodes"][name] = {"state": "building", "since": time.time()}

        deadline = time.time() + BUILD_TIMEOUT
        last_log = ""

        while time.time() < deadline:
            await asyncio.sleep(POLL_SECONDS)

            try:
                status = await self._call(name, "nginx_upgrade_status", {"lines": 12})
            except (AgentError, NodeUnreachable, ClusterError) as exc:
                # A node briefly goes quiet when the service restarts at the
                # end of the build.  Keep waiting.
                self.state["nodes"][name] = {
                    "state": "building",
                    "note": f"not answering just now: {exc}",
                }
                continue

            last_log = status.get("log_tail", "")
            self.state["nodes"][name] = {
                "state": "building",
                "log_tail": last_log[-1200:],
                "installed_version": status.get("installed_version"),
            }

            if status.get("state") == "finished":
                if not status.get("ok"):
                    return False, f"the build failed:\n{last_log[-1500:]}"
                break
        else:
            return False, f"the build did not finish within {BUILD_TIMEOUT // 60} minutes"

        # Built is not loaded: write (or remove) the load_module line.
        # Without it, enabling the WAF on one site renders
        # `modsecurity on;`, nginx rejects it as an unknown directive, and
        # since applies are all or nothing the whole fleet can't apply.
        #
        # The agent verb refuses if the .so is missing, tests nginx, and
        # rolls back on failure, so a node that can't load the module fails
        # here instead of at the next apply.
        wants = wants_waf_module()
        try:
            await self._call(name, "waf_module", {"enabled": wants})
        except (AgentError, NodeUnreachable, ClusterError) as exc:
            return False, (
                f"the build finished but the WAF module could not be "
                f"{'loaded' if wants else 'unloaded'}: {exc}")

        # Verify independently.
        return await self._verify(name, settings_before, last_log)

    async def _verify(self, name: str, version_before, build_log: str):
        """Check nginx is up, its config passes, and the version changed."""
        await asyncio.sleep(3)

        try:
            status = await self._call(name, "status", {})
        except (AgentError, NodeUnreachable, ClusterError) as exc:
            return False, f"the build finished but the node is not answering: {exc}"

        active = status.get("service_active")
        if active not in ("active", "no-systemd"):
            return False, f"the build finished but nginx is not running (service is {active})"

        try:
            test = await self._call(name, "config_test", {})
        except (AgentError, NodeUnreachable, ClusterError) as exc:
            return False, f"could not test the config afterwards: {exc}"

        if not test.get("ok"):
            return False, f"nginx will not load its config after the build:\n{test.get('output', '')}"

        # Record the new version and module list; the GUI keys off them.
        from app.core.capabilities import parse_build_info

        build_info = status.get("build_info", "")
        parsed = parse_build_info(build_info)
        version_after = parsed.get("nginx_version")

        with session_scope() as session:
            node = session.query(Node).filter(Node.name == name).first()
            if node:
                node.nginx_version = version_after
                node.nginx_build_info = build_info[:65536]
                node.nginx_active = True
                node.last_error = None
                session.commit()

        wanted = self.state["target"].get("nginx_version")
        if wanted and version_after != wanted:
            return False, (
                f"the build finished but nginx still reports {version_after}, "
                f"not {wanted}.  Check the build log."
            )

        return True, {
            "version_before": version_before,
            "version_after": version_after,
            "modules": len(parsed.get("modules", [])),
        }

    async def revert(self, name: str) -> dict:
        """Put the previous build back on one node."""
        try:
            result = await self._call(name, "nginx_revert", {})
        except (AgentError, NodeUnreachable, ClusterError) as exc:
            raise UpgradeError(f"could not revert {name}: {exc}")

        from app.core import audit

        audit.record("nginx.revert", object_type="node", object_name=name,
                     result="success" if result.get("ok") else "failed",
                     detail=str(result.get("output", ""))[:2000])
        return result

    # ---- talking to a node --------------------------------------------------

    async def _node_version(self, name: str):
        with session_scope() as session:
            node = session.query(Node).filter(Node.name == name).first()
            return node.nginx_version if node else None

    async def _call(self, name: str, verb: str, payload: dict):
        """
        Run an agent verb on this node or, via the peer API, on a peer.
        """
        settings = get_cluster().settings

        if name == settings.node_name:
            return await get_agent().call(verb, timeout=120, **payload)

        with session_scope() as session:
            node = session.query(Node).filter(Node.name == name).first()
            if not node:
                raise UpgradeError(f"{name} is not on the roster")
            client = PeerClient(node, get_cluster().ca)

        return await client.call("/peer/agent", {"verb": verb, "payload": payload},
                                 timeout=120)


_runner = None


def get_upgrade_runner() -> UpgradeRunner:
    global _runner
    if _runner is None:
        _runner = UpgradeRunner()
    return _runner
