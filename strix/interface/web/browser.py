"""Browser launcher targeting Google Chrome with cross-platform fallback."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import webbrowser
from pathlib import Path


logger = logging.getLogger(__name__)


def _launch_process(command: list[str], flags: int = 0) -> bool:
    try:
        subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=sys.platform != "win32",
            creationflags=flags,
        )
    except Exception:
        logger.debug("Failed to spawn browser with command %s", command, exc_info=True)
        return False
    else:
        return True


def open_chrome(url: str) -> bool:
    """Launch Google Chrome with the given URL, falling back gracefully.

    Tries system Chrome binaries directly on Linux, macOS, and Windows.
    If no dedicated Chrome executable is found or fails to start, falls back
    to Python's standard `webbrowser.open(url)`.
    """
    # 1. macOS specific application path
    if sys.platform == "darwin":
        mac_chrome = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        if mac_chrome.is_file() and _launch_process([str(mac_chrome), url]):
            return True
        if _launch_process(["/usr/bin/open", "-a", "Google Chrome", url]):
            return True

    # 2. Windows specific paths
    if sys.platform == "win32":
        for env_var in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
            base = os.environ.get(env_var)
            if base:
                exe = Path(base) / "Google" / "Chrome" / "Application" / "chrome.exe"
                if exe.is_file():
                    flags = getattr(subprocess, "DETACHED_PROCESS", 0)
                    if _launch_process([str(exe), url], flags=flags):
                        return True

    # 3. Linux & generic PATH candidates
    candidates = (
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
        "chrome",
    )
    for candidate in candidates:
        bin_path = shutil.which(candidate)
        if bin_path and _launch_process([bin_path, url]):
            return True

    # 4. Fallback to generic system browser
    try:
        return webbrowser.open(url)
    except Exception:
        logger.debug("Fallback webbrowser.open failed", exc_info=True)
        return False


__all__ = ["open_chrome"]
