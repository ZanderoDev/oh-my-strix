"""HTTP and WebSocket server powering the Strix Web interface.

Serves the 1:1 Strix Official React UI bundle (with ReactFlow live agent graph,
prompt composer, real-time transcript modals, and vulnerability reports),
combined with a clean interactive setup screen when launched without targets.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from aiohttp import WSMsgType, web

from strix.core.paths import latest_run_dir, runs_base_dir
from strix.interface.tui.backend.messages import send_user_message_to_agent
from strix.interface.viewer.server import build_runs_payload, bundle_dir
from strix.interface.viewer.transcript import (
    build_run_state,
    read_report_markdown,
    read_run_summary,
    read_vulnerabilities,
)


if TYPE_CHECKING:
    from strix.core.agents import AgentCoordinator
    from strix.interface.tui.backend.controller import TuiController
    from strix.interface.tui.backend.live_view import TuiLiveView

logger = logging.getLogger(__name__)


def web_static_dir() -> Path:
    return Path(__file__).resolve().parent / "static"


class WebServer:
    """Serves the 1:1 Strix Official Web UI and API endpoints."""

    def __init__(
        self,
        controller: TuiController,
        live_view: TuiLiveView,
        coordinator: AgentCoordinator,
        *,
        host: str = "127.0.0.1",
        port: int = 1400,
    ) -> None:
        self.controller = controller
        self.live_view = live_view
        self.coordinator = coordinator
        self.host = host
        self.port = port
        self.app = web.Application()
        self.runner: web.AppRunner | None = None
        self.site: web.TCPSite | None = None
        self.active_websockets: set[web.WebSocketResponse] = set()
        self._stop_event = asyncio.Event()
        self._broadcast_event = asyncio.Event()
        self._broadcast_task: asyncio.Task[None] | None = None
        self._last_event_cursor = 0

        self._setup_routes()

    def _setup_routes(self) -> None:
        static_path = web_static_dir()
        assets_path = static_path / "assets"
        if assets_path.is_dir():
            self.app.router.add_static("/assets", assets_path, follow_symlinks=True)
        if static_path.is_dir():
            self.app.router.add_static("/static", static_path, follow_symlinks=True)

        self.app.router.add_get("/", self._handle_index)
        self.app.router.add_get("/manus-base.css", self._handle_manus_css)
        self.app.router.add_get("/favicon.ico", self._handle_favicon)
        self.app.router.add_get("/logo.png", self._handle_logo)
        self.app.router.add_get("/static/logo.png", self._handle_logo)
        self.app.router.add_get("/setup", self._handle_index)

        # Strix Official Viewer API endpoints (1:1 with viewer SPA)
        self.app.router.add_get("/api/capabilities", self._handle_capabilities)
        self.app.router.add_get("/api/auth/status", self._handle_auth_status)
        self.app.router.add_get("/api/runs", self._handle_runs)
        self.app.router.add_get("/api/run", self._handle_run_summary)
        self.app.router.add_get("/api/transcript", self._handle_transcript)
        self.app.router.add_get("/api/vulnerabilities", self._handle_vulnerabilities)
        self.app.router.add_get("/api/report", self._handle_report)
        self.app.router.add_post("/api/agents/steer", self._handle_steer)
        self.app.router.add_post("/api/event", self._handle_telemetry_event)

        # Setup mode & command dispatch API
        self.app.router.add_get("/api/state", self._handle_get_state)
        self.app.router.add_get("/api/events", self._handle_get_events)
        self.app.router.add_post("/api/command", self._handle_post_command)
        self.app.router.add_get("/ws", self._handle_ws)

    async def _handle_manus_css(self, _request: web.Request) -> web.Response:
        css_file = web_static_dir() / "manus-base.css"
        if css_file.is_file():
            return web.Response(body=css_file.read_bytes(), content_type="text/css")
        return web.Response(status=404)

    async def _handle_favicon(self, _request: web.Request) -> web.Response:
        fav_file = web_static_dir() / "assets" / "favicon.ico"
        if fav_file.is_file():
            return web.Response(body=fav_file.read_bytes(), content_type="image/x-icon")
        return web.Response(status=404)

    async def _handle_index(self, _request: web.Request) -> web.Response:
        index_file = web_static_dir() / "index.html"
        if index_file.is_file():
            return web.Response(
                text=index_file.read_text(encoding="utf-8"),
                content_type="text/html",
            )
        return web.Response(text="Strix Agent UI not found", status=500)

    async def _handle_logo(self, _request: web.Request) -> web.Response:
        logo_path = bundle_dir() / "logo.png"
        if not logo_path.is_file():
            logo_path = web_static_dir() / "logo.png"
        if logo_path.is_file():
            return web.Response(body=logo_path.read_bytes(), content_type="image/png")
        return web.Response(status=404)

    async def _handle_capabilities(self, _request: web.Request) -> web.Response:
        # In interactive web mode, live steering is ALWAYS available!
        return web.json_response({"can_steer": True})

    async def _handle_auth_status(self, _request: web.Request) -> web.Response:
        # Local session is fully verified
        return web.json_response({"verified": True, "email": "local@strix.ai"})

    async def _handle_runs(self, _request: web.Request) -> web.Response:
        base = runs_base_dir()
        payload = build_runs_payload(base, verified=True)
        return web.json_response(payload)

    def _resolve_active_run_dir(self, request: web.Request) -> Path | None:
        run_param = request.query.get("run")
        base = runs_base_dir()
        if run_param:
            candidate = (base / run_param).resolve()
            if candidate.is_dir():
                return candidate
        if self.controller.report_state is not None:
            return self.controller.report_state.get_run_dir()
        return latest_run_dir()

    async def _handle_run_summary(self, request: web.Request) -> web.Response:
        run_dir = self._resolve_active_run_dir(request)
        if run_dir is not None and (run_dir / "run.json").is_file():
            summary = read_run_summary(run_dir)
            # If current live scan is still running, ensure finished is false
            if self.controller.scan_state == "running":
                summary["finished"] = False
                summary["status"] = "running"
            if self.controller.report_state is not None:
                summary["llm_usage"] = self.controller.report_state.get_total_llm_usage()
            return web.json_response(summary)

        # Fallback summary synthesized from controller
        snapshot = self.controller.snapshot()
        summary = {
            "runId": self.controller.args.run_name or "strix-web-run",
            "run_name": self.controller.args.run_name or "strix-web-run",
            "targets": self.controller.targets,
            "scan_mode": self.controller.scan_mode,
            "status": self.controller.scan_state,
            "finished": self.controller.scan_state in {"completed", "stopped", "failed"},
            "start_time": None,
            "end_time": None,
            "llm_usage": snapshot.get("usage", {}),
            "mcp_connection_status": snapshot.get("connections", []),
        }
        return web.json_response(summary)

    async def _handle_transcript(self, request: web.Request) -> web.Response:
        run_param = request.query.get("run")
        if run_param:
            run_dir = self._resolve_active_run_dir(request)
            if run_dir is not None:
                return web.json_response(build_run_state(run_dir))

        # Real-time in-memory transcript from live view
        agents = [
            {
                "id": agent.get("id"),
                "name": agent.get("name") or agent.get("id"),
                "parent_id": agent.get("parent_id"),
                "status": agent.get("status", "running"),
                "created_at": agent.get("created_at", ""),
                "updated_at": agent.get("updated_at", ""),
            }
            for agent in self.live_view.agents.values()
        ]
        return web.json_response({"agents": agents, "events": self.live_view.events})

    async def _handle_vulnerabilities(self, request: web.Request) -> web.Response:
        run_param = request.query.get("run")
        if run_param:
            run_dir = self._resolve_active_run_dir(request)
            if run_dir is not None:
                return web.json_response(read_vulnerabilities(run_dir))

        if self.controller.report_state is not None:
            reports = self.controller.report_state.vulnerability_reports
            if isinstance(reports, list):
                return web.json_response(reports)
        return web.json_response(self.controller.collection("vulnerabilities"))

    async def _handle_report(self, request: web.Request) -> web.Response:
        run_dir = self._resolve_active_run_dir(request)
        markdown = read_report_markdown(run_dir) if run_dir is not None else ""
        return web.json_response({"markdown": markdown})

    async def _handle_steer(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception as exc:
            return web.json_response({"ok": False, "error": f"Invalid JSON: {exc}"}, status=400)

        agent_id = str(body.get("agent_id") or "").strip()
        message = str(body.get("message") or "").strip()
        if not agent_id or not message:
            return web.json_response(
                {"ok": False, "error": "Missing agent_id or message"},
                status=400,
            )

        loop = self.controller.scan_loop or asyncio.get_running_loop()
        delivered = send_user_message_to_agent(
            coordinator=self.coordinator,
            loop=loop,
            live_view=self.live_view,
            target_agent_id=agent_id,
            message=message,
            notify_changed=self.controller.notify_changed,
            wait_for_delivery=True,
        )
        return web.json_response({"ok": delivered})

    async def _handle_telemetry_event(self, _request: web.Request) -> web.Response:
        return web.Response(status=204)

    async def _handle_get_state(self, _request: web.Request) -> web.Response:
        cursor, _ = self.live_view.event_snapshot()
        data = {
            "state": self.controller.snapshot(),
            "agents": self.controller.collection("agents"),
            "vulnerabilities": self.controller.collection("vulnerabilities"),
            "event_cursor": cursor,
        }
        return web.json_response(data)

    async def _handle_get_events(self, request: web.Request) -> web.Response:
        raw_cursor = request.query.get("cursor", "0")
        try:
            cursor = int(raw_cursor)
        except ValueError:
            cursor = 0

        if cursor > 0:
            next_cursor, events = self.live_view.event_changes_since(cursor)
        else:
            next_cursor, events = self.live_view.event_snapshot(limit=5000)

        return web.json_response({"cursor": next_cursor, "events": events})

    async def _handle_post_command(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception as exc:
            return web.json_response({"ok": False, "error": f"Invalid JSON: {exc}"}, status=400)

        command = body.get("command")
        payload = body.get("payload", {})
        if not isinstance(command, str) or not command.strip():
            return web.json_response({"ok": False, "error": "Missing command string"}, status=400)

        try:
            result = await self.controller.handle(command.strip(), payload or {})
            if command == "app.quit":
                self.stop()
            return web.json_response({"ok": True, "result": result})
        except Exception as exc:
            logger.warning("Web command '%s' failed: %s", command, exc)
            return web.json_response({"ok": False, "error": str(exc)}, status=400)

    async def _handle_ws(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(heartbeat=15.0)
        await ws.prepare(request)
        self.active_websockets.add(ws)

        try:
            cursor, events = self.live_view.event_snapshot(limit=5000)
            init_payload = {
                "type": "init",
                "state": self.controller.snapshot(),
                "agents": self.controller.collection("agents"),
                "vulnerabilities": self.controller.collection("vulnerabilities"),
                "event_cursor": cursor,
                "events": events,
            }
            await ws.send_str(json.dumps(init_payload, default=str))

            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                    except json.JSONDecodeError:
                        continue

                    msg_type = data.get("type")
                    if msg_type == "command":
                        req_id = data.get("id")
                        cmd = data.get("command", "")
                        payload = data.get("payload", {})
                        try:
                            res = await self.controller.handle(cmd, payload)
                            if cmd == "app.quit":
                                self.stop()
                            await ws.send_str(
                                json.dumps(
                                    {
                                        "type": "command_result",
                                        "id": req_id,
                                        "ok": True,
                                        "result": res,
                                    },
                                    default=str,
                                )
                            )
                        except Exception as exc:
                            await ws.send_str(
                                json.dumps(
                                    {
                                        "type": "command_result",
                                        "id": req_id,
                                        "ok": False,
                                        "error": str(exc),
                                    },
                                    default=str,
                                )
                            )
                elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                    break
        finally:
            self.active_websockets.discard(ws)

        return ws

    def notify_changed(self) -> None:
        self._broadcast_event.set()

    async def _broadcast_loop(self) -> None:
        while True:
            await self._broadcast_event.wait()
            self._broadcast_event.clear()
            if not self.active_websockets:
                continue

            try:
                state = self.controller.snapshot()
                agents = self.controller.collection("agents")
                vulns = self.controller.collection("vulnerabilities")

                state_update = {
                    "type": "state_update",
                    "state": state,
                    "agents": agents,
                    "vulnerabilities": vulns,
                }
                await self._broadcast(json.dumps(state_update, default=str))

                cursor = self._last_event_cursor
                next_cursor, delta_events = self.live_view.event_changes_since(cursor)
                if delta_events:
                    self._last_event_cursor = next_cursor
                    events_msg = {
                        "type": "events",
                        "cursor": next_cursor,
                        "events": delta_events,
                    }
                    await self._broadcast(json.dumps(events_msg, default=str))
                elif next_cursor != self._last_event_cursor:
                    self._last_event_cursor = next_cursor
            except Exception:
                logger.debug("Broadcast loop tick failed", exc_info=True)

    async def _broadcast(self, message: str) -> None:
        if not self.active_websockets:
            return
        dead = []
        for ws in self.active_websockets:
            try:
                await ws.send_str(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.active_websockets.discard(ws)

    async def start(self) -> None:
        self.runner = web.AppRunner(self.app, access_log=None)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, self.host, self.port)
        await self.site.start()
        self._broadcast_task = asyncio.create_task(self._broadcast_loop())
        logger.info("Strix Web Server started on http://%s:%d", self.host, self.port)

    def stop(self) -> None:
        self._stop_event.set()

    async def wait_closed(self) -> None:
        await self._stop_event.wait()

    async def close(self) -> None:
        self.stop()
        if self._broadcast_task is not None:
            self._broadcast_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._broadcast_task

        for ws in list(self.active_websockets):
            with contextlib.suppress(Exception):
                await ws.close(code=1000, message=b"Server shutting down")
        self.active_websockets.clear()

        if self.runner is not None:
            await self.runner.cleanup()
            self.runner = None
            self.site = None


__all__ = ["WebServer", "web_static_dir"]
