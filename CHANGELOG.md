# Changelog

All notable changes to Simple Network Scanner will be documented here.

## [1.1.0] - 2026-10-07

- Provide a downloadable Debian package with an application-menu entry and declared system dependencies.
- Rewrite installation, update, removal, and migration instructions for desktop users.

- Add a clean charcoal interface with clearly outlined buttons and light mode.
- Add a per-user installer, application icon, menu entry, and desktop shortcut.
- Keep the status bar visible when resizing the results area.

- Prevent overlapping scans and honor Stop requests made during startup.
- Keep the window open until a canceled scan has finished and files are cleaned up.
- Add a termination timeout and report denied cancellation of privileged scans.
- Preserve the active target and controls when background network detection finishes.
- Add timeouts to network detection commands.
- Report missing or invalid XML results as scan failures.
- Clearly reject unsupported IPv6 targets.
- Pre-create the XML file to preserve user ownership for privileged scans.
- Add regression tests without third-party Python dependencies.

## [1.0.0] - 2026-07-28

### Added

- Application version displayed in the title bar

### Changed

- Device results now clear when the scan type is changed
- Local host MAC field displays `Host device`
- Local host vendor field displays `This computer`
- Local host latency displays `Local host`
