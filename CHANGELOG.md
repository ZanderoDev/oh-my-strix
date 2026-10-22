# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added
- `--web` flag and local web server on port 1400.
- Automatic browser launch opening Chrome on startup.
- Chat interface for issuing scan prompts directly without manual target forms.
- Target extraction from natural language messages (URLs, domains, IPs, and paths).
- Live activity stream showing subagents, tool execution drawers, and findings.
- Mid-scan agent steering via WebSocket and REST endpoints.
- Integration tests in `tests/test_web_interface.py`.

### Changed
- `TuiController` supports dynamic target changes, runtime configuration updates, and chat message dispatching.
