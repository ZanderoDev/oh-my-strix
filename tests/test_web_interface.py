"""Tests for the interactive Strix Web interface and --web CLI option."""

from __future__ import annotations

import argparse
from unittest.mock import patch

import pytest
from aiohttp.test_utils import TestClient, TestServer

from strix.config.settings import DEFAULT_MAX_TURNS
from strix.core.agents import AgentCoordinator
from strix.interface.cli_args import parse_arguments
from strix.interface.tui.backend.controller import TuiController
from strix.interface.tui.backend.live_view import TuiLiveView
from strix.interface.web.browser import open_chrome
from strix.interface.web.server import WebServer


def sample_args() -> argparse.Namespace:
    return argparse.Namespace(
        needs_setup=True,
        targets_info=[],
        instruction=None,
        scan_mode="deep",
        max_budget_usd=None,
        max_turns=DEFAULT_MAX_TURNS,
        scope_mode="auto",
        diff_base=None,
        local_sources=[],
        diff_scope={"active": False},
        user_explicit_instruction=None,
        run_name=None,
        web=True,
        port=1400,
        non_interactive=False,
    )


@pytest.mark.asyncio
async def test_controller_set_config_and_remove_target() -> None:
    controller = TuiController(sample_args())
    await controller.handle("setup.add_target", {"target": "https://example.com"})
    await controller.handle("setup.add_target", {"target": "https://test.com"})
    assert controller.targets == ["https://example.com", "https://test.com"]

    # Remove target
    await controller.handle("setup.remove_target", {"target": "https://example.com"})
    assert controller.targets == ["https://test.com"]

    # Set configuration
    await controller.handle(
        "setup.set_config",
        {
            "scan_mode": "quick",
            "max_budget_usd": 15.5,
            "max_turns": 80,
            "scope_mode": "diff",
            "diff_base": "origin/main",
        },
    )
    assert controller.scan_mode == "quick"
    assert controller.max_budget_usd == 15.5
    assert controller.max_turns == 80
    assert controller.scope_mode == "diff"
    assert controller.diff_base == "origin/main"


def test_cli_args_web_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.argv", ["strix", "--web", "-t", "https://example.com"])
    args = parse_arguments()
    assert args.web is True
    assert args.port == 1400
    assert args.non_interactive is False


def test_cli_args_web_port_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "sys.argv", ["strix", "--web", "--port", "1400", "-t", "https://example.com"]
    )
    args = parse_arguments()
    assert args.web is True
    assert args.port == 1400


def test_cli_args_web_conflicts_with_non_interactive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.argv", ["strix", "--web", "-n", "-t", "https://example.com"])
    with pytest.raises(SystemExit):
        parse_arguments()


def test_open_chrome_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: None)
    with patch("webbrowser.open", return_value=True) as mock_wb:
        res = open_chrome("http://127.0.0.1:1400")
        assert res is True
        mock_wb.assert_called_once_with("http://127.0.0.1:1400")


@pytest.mark.asyncio
async def test_web_server_setup_and_commands() -> None:
    args = sample_args()
    live_view = TuiLiveView()
    coordinator = AgentCoordinator()
    controller = TuiController(args, live_view=live_view, coordinator=coordinator)
    server = WebServer(controller, live_view, coordinator, host="127.0.0.1", port=1498)

    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()

    try:
        # GET / (setup mode)
        resp = await client.get("/")
        assert resp.status == 200
        text = await resp.text()
        assert "Strix AI Agent" in text

        # GET /api/state
        resp = await client.get("/api/state")
        assert resp.status == 200
        data = await resp.json()
        assert data["state"]["setup_mode"] is True

        # POST /api/command
        resp = await client.post(
            "/api/command",
            json={"command": "setup.add_target", "payload": {"target": "https://target.com"}},
        )
        assert resp.status == 200
        res = await resp.json()
        assert res["ok"] is True
        assert "https://target.com" in controller.targets
    finally:
        await client.close()
        await test_server.close()


@pytest.mark.asyncio
async def test_web_server_viewer_endpoints() -> None:
    args = sample_args()
    live_view = TuiLiveView()
    coordinator = AgentCoordinator()
    controller = TuiController(args, live_view=live_view, coordinator=coordinator)
    server = WebServer(controller, live_view, coordinator, host="127.0.0.1", port=1499)

    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()

    try:
        # GET /api/capabilities
        resp = await client.get("/api/capabilities")
        assert resp.status == 200
        caps = await resp.json()
        assert caps["can_steer"] is True

        # GET /api/auth/status
        resp = await client.get("/api/auth/status")
        assert resp.status == 200
        auth_data = await resp.json()
        assert auth_data["verified"] is True

        # GET /api/run
        resp = await client.get("/api/run")
        assert resp.status == 200
        run_data = await resp.json()
        assert "status" in run_data

        # GET /api/transcript
        resp = await client.get("/api/transcript")
        assert resp.status == 200
        transcript_data = await resp.json()
        assert "agents" in transcript_data
        assert "events" in transcript_data

        # GET /api/vulnerabilities
        resp = await client.get("/api/vulnerabilities")
        assert resp.status == 200
        vulns_data = await resp.json()
        assert isinstance(vulns_data, list)

        # GET /logo.png
        resp = await client.get("/logo.png")
        assert resp.status == 200
        assert resp.content_type == "image/png"
    finally:
        await client.close()
        await test_server.close()
