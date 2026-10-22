# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Interactive Web Agent Mode (`strix --web`)**:
  - Full-featured browser-based AI agent interface running locally on port 1400.
  - Automatic Google Chrome launch upon startup with cross-platform desktop fallback.
  - Direct natural language chat interface: start scans directly from prompt without manual form configuration.
  - Automatic target extraction from chat messages (URLs, domains, IPs, file paths, repository links).
  - Real-time agent swarm coordination tracking (`running`, `waiting`, `completed`, `failed`).
  - Terminal-style tool execution widgets with collapsible drawers, live output inspection, and arguments preview.
  - Real-time reasoning/thinking process visualizer.
  - Live vulnerability findings side panel with formatted PoC markdown viewer and CVSS severity badges.
  - Interactive mid-scan agent steering via WebSocket and REST APIs.
  - CLI argument `--web` and `--port` in `strix.interface.cli_args`.

### Changed
- Refactored `TuiController` to support dynamic target removal, configuration adjustments, and unified chat dispatching.
- Added comprehensive unit and integration test suite for the Web interface (`tests/test_web_interface.py`).

### Security
- 100% preservation of core agent system prompts and pentesting skill knowledge packs.
