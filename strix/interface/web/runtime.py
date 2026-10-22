"""Web runtime for Strix: orchestrates the scan engine, state, and HTTP/WebSocket server."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from copy import deepcopy
from typing import TYPE_CHECKING, Any

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from strix.config import load_settings, persist_current
from strix.core.agents import AgentCoordinator
from strix.core.hooks import BudgetExceededError
from strix.core.runner import run_strix_scan
from strix.interface.scan_setup import (
    build_targets_info,
    preflight_model_connection,
    prepare_run,
    telemetry_start,
)
from strix.interface.tui.backend import TuiController
from strix.interface.tui.backend.live_view import TuiLiveView
from strix.interface.utils import read_workspace_files
from strix.interface.web.browser import open_chrome
from strix.interface.web.server import WebServer
from strix.report.state import ReportState, set_global_report_state
from strix.telemetry import report_error, set_scan_phase


if TYPE_CHECKING:
    import argparse

logger = logging.getLogger(__name__)


def _revision_count(report: dict[str, Any]) -> int:
    history = report.get("update_history")
    return len(history) if isinstance(history, list) else 0


class WebRuntime:
    """Manages the interactive web session and local server for Strix."""

    def __init__(
        self,
        args: argparse.Namespace,
        *,
        host: str = "127.0.0.1",
        port: int = 1400,
    ) -> None:
        self.args = args
        self.host = host
        self.port = port
        self.live_view = TuiLiveView()
        self.coordinator = AgentCoordinator()
        self.report_state: ReportState | None = None
        self.scan_config: dict[str, Any] = {}
        self.scan_task: asyncio.Task[None] | None = None
        self.scan_error: BaseException | None = None
        self._last_sync_fingerprint = ""
        self._error_noted_agents: set[str] = set()
        self._output_syncs: set[asyncio.Task[None]] = set()
        self.model_verified = False
        self._setup_preflight: asyncio.Task[None] | None = None
        self._sync_task: asyncio.Task[None] | None = None
        self._prepare_task: asyncio.Task[None] | None = None

        self.controller = TuiController(
            args,
            live_view=self.live_view,
            coordinator=self.coordinator,
            on_start=self.start_from_setup,
            on_verify=self.ensure_model_verified,
            on_quit=self.quit,
        )
        self.server = WebServer(
            self.controller,
            self.live_view,
            self.coordinator,
            host=self.host,
            port=self.port,
        )

    def init_run_state(self) -> None:
        self.scan_config = {
            "scan_id": self.args.run_name,
            "targets": self.args.targets_info,
            "user_instructions": self.args.instruction or "",
            "run_name": self.args.run_name,
            "diff_scope": self.args.diff_scope,
            "scan_mode": self.args.scan_mode,
            "non_interactive": False,
            "local_sources": self.args.local_sources or [],
            "workspace_files": getattr(self.args, "workspace_files", None) or [],
            "scope_mode": self.args.scope_mode,
            "diff_base": self.args.diff_base,
            "resume_instruction": self.args.user_explicit_instruction or "",
            "workspace_mount": getattr(self.args, "workspace_mount", None) or "",
            "workspace_subdir": getattr(self.args, "workspace_subdir", None) or "",
        }
        self.report_state = ReportState(self.scan_config["run_name"])
        self.report_state.hydrate_from_run_dir()
        self.report_state.set_scan_config(self.scan_config)
        self.report_state.save_run_data()
        set_global_report_state(self.report_state)
        self.live_view.hydrate_from_run_dir(self.report_state.get_run_dir())
        self.controller.set_runtime(
            report_state=self.report_state,
            scan_loop=asyncio.get_running_loop(),
        )
        self.report_state.vulnerability_found_callback = lambda _report: (
            self.controller.notify_changed()
        )
        self.report_state.vulnerability_updated_callback = lambda _report: (
            self.controller.notify_changed()
        )
        self.report_state.vulnerability_deleted_callback = lambda _report: (
            self.controller.notify_changed()
        )
        self.controller.notify_changed()

    async def check_setup_model(self) -> None:
        if not (load_settings().llm.model or "").strip():
            return
        try:
            await self._preflight_model()
        except Exception as exc:
            logger.exception("Web setup model preflight failed")
            self.controller.add_message(f"Model connection failed: {exc}", "error")
            return
        self.controller.add_message("Model connection verified")

    async def ensure_model_verified(self) -> None:
        preflight = self._setup_preflight
        if preflight is not None and not preflight.done():
            await asyncio.shield(preflight)
        if self.model_verified:
            return
        try:
            await self._preflight_model()
        except Exception as exc:
            logger.exception("Web setup model preflight failed")
            report_error("model_connection_failed", exc)
            raise RuntimeError(f"Model connection failed: {exc}") from exc

    async def _preflight_model(self) -> None:
        model = (load_settings().llm.model or "").strip()
        self.controller.add_message("Verifying model connection...")
        set_scan_phase("preflight")
        await preflight_model_connection(model)
        self.model_verified = True

    def _start_preparation(self) -> asyncio.Task[None] | None:
        if self.controller.setup_mode:
            self._setup_preflight = asyncio.create_task(self.check_setup_model())
            return self._setup_preflight
        self.start_scan()
        return None

    async def start_from_setup(self) -> None:
        candidate = deepcopy(self.args)
        candidate.scan_mode = self.controller.scan_mode
        candidate.instruction = self.controller.instruction
        candidate.user_instruction = self.controller.instruction or None
        candidate.max_budget_usd = self.controller.max_budget_usd
        candidate.max_turns = self.controller.max_turns
        candidate.scope_mode = self.controller.scope_mode
        candidate.diff_base = self.controller.diff_base
        existing_targets = [
            str(target["original"])
            for target in candidate.targets_info
            if isinstance(target, dict) and target.get("original")
        ]
        targets_changed = self.controller.targets != existing_targets
        persist_current()
        candidate.workspace_mount = self.controller.workspace_mount
        if targets_changed:
            candidate.target = list(self.controller.targets)
            candidate.target_list = []
            build_targets_info(candidate)
        try:
            prepare_run(candidate)
        except Exception as exc:
            report_error("scan_preparation_failed", exc)
            raise
        telemetry_start(candidate)

        vars(self.args).update(vars(candidate))
        self.init_run_state()
        self.start_scan()

    def start_scan(self) -> None:
        if self.scan_task is None:
            self.scan_task = asyncio.create_task(self._run_scan())

    async def _run_scan(self) -> None:
        image = str(load_settings().runtime.image or "strix-sandbox:latest")
        try:
            await run_strix_scan(
                scan_config=self.scan_config,
                scan_id=self.scan_config["run_name"],
                image=image,
                local_sources=self.args.local_sources or [],
                extra_files=read_workspace_files(getattr(self.args, "workspace_files", None)),
                coordinator=self.coordinator,
                interactive=True,
                max_turns=self.args.max_turns,
                max_budget_usd=self.args.max_budget_usd,
                event_sink=self.capture_event,
                mcp_status_sink=self.capture_mcp_status,
            )
            await self._sync_agent_state()
            if self.controller.scan_state == "running":
                self.controller.scan_state = "stopped"
        except (asyncio.CancelledError, BudgetExceededError):
            report_status = (
                self.report_state.run_record.get("status")
                if self.report_state is not None
                else None
            )
            self.controller.scan_state = "completed" if report_status == "completed" else "stopped"
        except Exception as exc:
            logger.exception("Web scan failed")
            report_error("unhandled_exception", exc)
            if self.report_state is not None and self.report_state.scan_ended_exit_reason is None:
                self.report_state.scan_ended_exit_reason = "error"
            self.scan_error = exc
            self.controller.error = str(exc)
            self.controller.scan_state = "failed"
        finally:
            with contextlib.suppress(Exception):
                await self._sync_agent_state()
            self.controller.notify_changed()

    def capture_event(self, agent_id: str, event: Any) -> None:
        self.live_view.ingest_sdk_event(agent_id, event)
        if getattr(getattr(event, "item", None), "type", "") == "tool_call_output_item":
            loop = asyncio.get_running_loop()
            task = loop.create_task(self._sync_and_notify())
            self._output_syncs.add(task)
            task.add_done_callback(self._output_syncs.discard)
            return
        self.controller.notify_changed()

    async def _sync_and_notify(self) -> None:
        with contextlib.suppress(Exception):
            await self._sync_agent_state()
        self.controller.notify_changed()

    def capture_mcp_status(self, roster: list[dict[str, Any]]) -> None:
        self.controller.set_mcp_connections(roster)

    async def _sync_agent_state(self) -> bool:
        parent_of, statuses, names, errors = await self.coordinator.graph_snapshot()
        changed = False
        for agent_id, status in statuses.items():
            error = errors.get(agent_id)
            changed = (
                self.live_view.upsert_agent(
                    agent_id,
                    name=names.get(agent_id, agent_id),
                    parent_id=parent_of.get(agent_id),
                    status=str(status),
                    error_message=error,
                )
                or changed
            )
            if status in {"failed", "crashed"} and error:
                if agent_id not in self._error_noted_agents:
                    self._error_noted_agents.add(agent_id)
                    self.live_view.record_agent_error(agent_id, error)
                    changed = True
            else:
                self._error_noted_agents.discard(agent_id)

        changed = self.live_view.flush_user_instruction() or changed

        roots = [agent_id for agent_id, parent_id in parent_of.items() if parent_id is None]
        root_id = roots[0] if roots else None
        root_status = statuses.get(root_id) if root_id is not None else None
        report_status = (
            self.report_state.run_record.get("status") if self.report_state is not None else None
        )
        scan_state = self.controller.scan_state
        if root_status in {"failed", "crashed"}:
            scan_state = "failed"
            if root_id is not None and errors.get(root_id):
                self.controller.error = errors[root_id]
        elif scan_state == "failed" and root_status in {"running", "waiting", "budget_paused"}:
            scan_state = "running"
            self.controller.error = None
        elif scan_state != "failed":
            if report_status == "completed":
                scan_state = "completed"
            elif root_status == "stopped":
                scan_state = "stopped"
            elif root_status == "completed":
                scan_state = "failed"
                self.controller.error = "Scan ended without a completed report"
        if scan_state != self.controller.scan_state:
            self.controller.scan_state = scan_state
            changed = True
        return changed

    def _runtime_sync_fingerprint(self) -> str:
        usage: dict[str, Any] = {}
        vulnerabilities: list[object] = []
        if self.report_state is not None:
            usage = dict(self.report_state.get_total_llm_usage())
            vulnerabilities = [
                (report.get("id", index), _revision_count(report))
                if isinstance(report, dict)
                else index
                for index, report in enumerate(self.report_state.vulnerability_reports)
            ]
        return json.dumps(
            {
                "scan_state": self.controller.scan_state,
                "usage": usage,
                "vulnerabilities": vulnerabilities,
            },
            default=str,
            sort_keys=True,
            separators=(",", ":"),
        )

    async def sync_state(self) -> None:
        while True:
            if self.scan_task is not None and not self.scan_task.done():
                try:
                    changed = await self._sync_agent_state()
                except Exception as exc:
                    logger.exception("Web agent-state sync failed")
                    self.controller.error = f"Agent-state sync failed: {exc}"
                    changed = True
                fingerprint = self._runtime_sync_fingerprint()
                if fingerprint != self._last_sync_fingerprint:
                    self._last_sync_fingerprint = fingerprint
                    changed = True
                if changed:
                    self.controller.notify_changed()
            await asyncio.sleep(0.5)

    async def quit(self) -> None:
        self.controller.close_viewer()
        self.coordinator.mark_shutting_down()
        scan_task = self.scan_task
        if scan_task is not None:
            if not scan_task.done():
                scan_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await scan_task
        if self._sync_task is not None:
            self._sync_task.cancel()
        if self._prepare_task is not None:
            self._prepare_task.cancel()
        await self.server.close()

    async def run(self) -> None:
        console = Console()
        url = f"http://{self.host}:{self.port}"

        # Connect controller notifications to WebServer broadcast
        self.controller.set_change_callback(self.server.notify_changed)

        if not self.controller.setup_mode:
            self.init_run_state()

        await self.server.start()
        self._prepare_task = self._start_preparation()
        self._sync_task = asyncio.create_task(self.sync_state())

        banner_text = Text()
        banner_text.append("STRIX INTERACTIVE WEB UI\n\n", style="bold #22c55e")
        banner_text.append("Local Server : ", style="dim")
        banner_text.append(f"{url}\n", style="bold #60a5fa")
        banner_text.append("Mode         : ", style="dim")
        mode_name = "Setup (Start Screen)" if self.controller.setup_mode else "Live Pentest"
        banner_text.append(f"{mode_name}\n", style="white")
        banner_text.append("Browser      : ", style="dim")
        banner_text.append("Opening Google Chrome automatically...\n\n", style="#4ade80")
        banner_text.append("Press ", style="dim")
        banner_text.append("Ctrl+C", style="bold yellow")
        banner_text.append(" in terminal or click 'Stop / Quit' in web UI to exit.", style="dim")

        console.print(
            Panel(
                banner_text,
                title="[bold white]STRIX WEB[/]",
                title_align="left",
                border_style="#22c55e",
                padding=(1, 2),
            )
        )

        open_chrome(url)

        try:
            await self.server.wait_closed()
        except asyncio.CancelledError:
            pass
        finally:
            await self.quit()

        if self.scan_error is not None:
            raise self.scan_error


async def run_web(args: argparse.Namespace) -> None:
    port = getattr(args, "port", 1400) or 1400
    runtime = WebRuntime(args, host="127.0.0.1", port=port)
    await runtime.run()
