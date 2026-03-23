"""
Shield Menu Bar — macOS system tray app for AgentSeal Shield.

Runs Shield's watchdog-based filesystem monitor in a background thread
while presenting a native macOS menu bar interface via rumps.

Usage:
    agentseal shield --menubar

Requires: pip install agentseal[shield-menubar]  (includes rumps + watchdog)
"""

import os
import queue

try:
    import rumps
    _RUMPS_AVAILABLE = True
except ImportError:
    _RUMPS_AVAILABLE = False


def _find_icon(name: str = "icon-menubar.png") -> str | None:
    """Locate bundled icon file relative to package."""
    # Check assets/ next to the package
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    for candidate in [
        os.path.join(pkg_dir, "..", "..", "assets", name),  # dev layout
        os.path.join(pkg_dir, "assets", name),              # installed
    ]:
        path = os.path.normpath(candidate)
        if os.path.isfile(path):
            return path
    return None


def check_rumps_available() -> None:
    """Raise ImportError with install instructions if rumps is missing."""
    if not _RUMPS_AVAILABLE:
        raise ImportError(
            "agentseal shield --menubar requires the 'rumps' package.\n"
            "Install with: pip install agentseal[shield-menubar]"
        )


# Shield event passed through the thread-safe queue
# Tuple of (event_type: str, path: str, summary: str)
ShieldEvent = tuple[str, str, str]

# Title constants for menu bar states (emoji fallback when no icon)
_TITLE_NORMAL = "🛡"
_TITLE_ALERT = "🛡️⚠️"
# Alert title when using icon (red dot indicator)
_TITLE_ICON_ALERT = " !"


if _RUMPS_AVAILABLE:

    class ShieldMenuBarApp(rumps.App):
        """macOS menu bar app wrapping AgentSeal Shield.

        Architecture:
            Main thread:  rumps.App.run() — owns NSRunLoop, handles UI
            Background:   Shield.start() — watchdog Observer daemon thread
            Bridge:       queue.Queue — thread-safe event passing
            Polling:      rumps.Timer(0.5s) — drains queue on main thread
        """

        def __init__(
            self,
            semantic: bool = True,
            notify: bool = True,
            debounce_seconds: float = 2.0,
            llm_judge=None,
        ):
            check_rumps_available()

            icon_path = _find_icon()
            super().__init__(
                name="AgentSeal Shield",
                title=None if icon_path else _TITLE_NORMAL,
                icon=icon_path,
                template=True,
                quit_button=None,
            )

            # Shield config (stored for pause/resume)
            self._shield_semantic = semantic
            self._shield_notify = notify
            self._shield_debounce = debounce_seconds
            self._shield_llm_judge = llm_judge

            # Thread-safe event queue: Shield (background) → rumps (main thread)
            self._event_queue: queue.Queue[ShieldEvent] = queue.Queue()

            # Shield instance (created on start, replaced on resume)
            self._shield = None  # type: ignore[assignment]
            self._paused = False

            # Counters (updated from queue drain on main thread)
            self._scan_count = 0
            self._threat_count = 0
            self._warning_count = 0

            # Recent threats log (max 10)
            self._max_recent = 10
            self._recent_events: list[tuple[str, str, str]] = []

            # Build menu structure
            # Items with callback=None are disabled (greyed out, non-clickable)
            self._header_item = rumps.MenuItem("AgentSeal Shield", callback=None)
            self._status_item = rumps.MenuItem("Status: Starting...", callback=None)
            self._stats_item = rumps.MenuItem(
                "Scans: 0 | Threats: 0 | Warnings: 0", callback=None
            )
            self._recent_header = rumps.MenuItem("Recent Findings", callback=None)
            self._no_threats_item = rumps.MenuItem(
                "  No threats detected", callback=None
            )
            self._version_item = rumps.MenuItem(
                f"AgentSeal v{self._get_version()}", callback=None
            )
            self._pause_item = rumps.MenuItem("Pause Monitoring")
            self._clear_item = rumps.MenuItem("Clear Findings")
            self._quit_item = rumps.MenuItem("Quit")

            self.menu = [
                self._header_item,
                None,  # separator
                self._status_item,
                self._stats_item,
                None,
                self._recent_header,
                self._no_threats_item,
                None,
                self._pause_item,
                self._clear_item,
                None,
                self._version_item,
                None,
                self._quit_item,
            ]

        @staticmethod
        def _get_version() -> str:
            """Read version from agentseal package."""
            try:
                from agentseal import __version__
                return __version__
            except ImportError:
                return "unknown"

        # ── Shield lifecycle ──────────────────────────────────────

        def _on_shield_event(
            self, event_type: str, path: str, summary: str
        ) -> None:
            """Shield callback — runs on watchdog's BACKGROUND thread.

            NEVER touch rumps UI here. Only push to the thread-safe queue.
            """
            self._event_queue.put((event_type, path, summary))

        def _start_shield(self) -> None:
            """Create and start a new Shield instance in a background thread."""
            from agentseal.shield import Shield

            self._shield = Shield(
                semantic=self._shield_semantic,
                notify=self._shield_notify,
                debounce_seconds=self._shield_debounce,
                on_event=self._on_shield_event,
                **({"llm_judge": self._shield_llm_judge}
                   if self._shield_llm_judge else {}),
            )
            try:
                dirs_watched, files_watched = self._shield.start()
                self._status_item.title = (
                    f"Status: Watching ({dirs_watched} dirs)"
                )
            except Exception as exc:
                self._status_item.title = f"Status: Error — {exc}"
                self._shield = None

        def _stop_shield(self) -> None:
            """Stop the current Shield instance."""
            if self._shield is not None:
                self._shield.stop()
                self._shield = None

        # ── rumps Timer: drain event queue on main thread ─────────

        @rumps.timer(0.5)
        def _poll_events(self, timer):
            """Drain the event queue and update UI.

            Runs on main thread via NSRunLoop.
            Do not block here — it freezes the entire menu bar app.
            """
            updated = False
            while True:
                try:
                    event_type, path, summary = (
                        self._event_queue.get_nowait()
                    )
                except queue.Empty:
                    break

                updated = True
                self._scan_count += 1

                if event_type in ("threat", "warning"):
                    if event_type == "threat":
                        self._threat_count += 1
                    else:
                        self._warning_count += 1
                    # Show alert: use red text if icon mode, emoji if not
                    if _find_icon():
                        self.title = _TITLE_ICON_ALERT
                    else:
                        self.title = _TITLE_ALERT

                    filename = path.split("/")[-1] if "/" in path else path
                    level = "THREAT" if event_type == "threat" else "WARNING"

                    # Add to recent findings menu with full path for actions
                    self._add_recent_finding(level, filename, summary, full_path=path)

                    try:
                        rumps.notification(
                            title=f"AgentSeal Shield - {level}",
                            subtitle=filename,
                            message=summary,
                        )
                    except Exception as exc:
                        import sys
                        print(f"[Shield] notification failed: {exc}", file=sys.stderr)

            if updated:
                self._stats_item.title = (
                    f"Scans: {self._scan_count} "
                    f"| Threats: {self._threat_count} "
                    f"| Warnings: {self._warning_count}"
                )

        # ── Menu click handlers ──────────────────────────────────

        @rumps.clicked("Pause Monitoring")
        def _toggle_pause(self, sender):
            """Toggle Shield monitoring on/off."""
            if not self._paused:
                self._stop_shield()
                self._paused = True
                sender.state = 1  # checkmark ON = paused
                self._status_item.title = "Status: Paused"
                self.title = _TITLE_NORMAL
            else:
                try:
                    self._start_shield()
                except Exception as exc:
                    self._status_item.title = f"Status: Error — {exc}"
                    return  # Stay paused — resume failed
                if self._shield is None:
                    # _start_shield caught an error internally
                    return  # Stay paused — shield didn't start
                self._paused = False
                sender.state = 0  # checkmark OFF = running

        def _add_recent_finding(
            self, level: str, filename: str, summary: str, full_path: str = ""
        ):
            """Add a finding to the Recent Findings submenu with actions."""
            import time as _time
            from pathlib import Path as _Path

            ts = _time.strftime("%H:%M:%S")
            label = f"  [{level}] {ts} {filename}"
            detail = summary[:80].replace("\n", " ")
            item = rumps.MenuItem(label, callback=None)
            item.title = label

            # Remove "No threats" placeholder
            if "No threats" in (self._no_threats_item.title or ""):
                try:
                    del self.menu["  No threats detected"]
                except KeyError:
                    pass

            # Detail line
            detail_item = rumps.MenuItem(f"    {detail}", callback=None)
            item[detail_item.title] = detail_item

            # Remedy suggestion
            remedy = self._get_remedy(level, summary, filename)
            remedy_item = rumps.MenuItem(f"    Remedy: {remedy}", callback=None)
            item[remedy_item.title] = remedy_item

            # Separator
            item[None] = None

            # Action: Quarantine (move to ~/.agentseal/quarantine/)
            if full_path and _Path(full_path).exists():
                def _quarantine_cb(_sender, _path=full_path, _label=label):
                    try:
                        from agentseal.fix import quarantine_skill
                        entry = quarantine_skill(_Path(_path), reason=summary)
                        rumps.notification(
                            title="AgentSeal Shield",
                            subtitle="File Quarantined",
                            message=f"Moved to {entry.quarantine_path}",
                        )
                        # Remove from menu
                        try:
                            del self.menu[_label]
                        except KeyError:
                            pass
                    except Exception as exc:
                        rumps.notification(
                            title="AgentSeal Shield - Error",
                            subtitle="Quarantine failed",
                            message=str(exc),
                        )
                quarantine_item = rumps.MenuItem(
                    "    Quarantine (remove file)", callback=_quarantine_cb
                )
                item[quarantine_item.title] = quarantine_item

                # Action: Show in Finder
                def _reveal_cb(_sender, _path=full_path):
                    import subprocess as _sp
                    _sp.Popen(["open", "-R", _path])
                reveal_item = rumps.MenuItem(
                    "    Show in Finder", callback=_reveal_cb
                )
                item[reveal_item.title] = reveal_item

            # Action: Ignore (dismiss from list)
            def _ignore_cb(_sender, _label=label):
                try:
                    del self.menu[_label]
                except KeyError:
                    pass
            ignore_item = rumps.MenuItem("    Ignore", callback=_ignore_cb)
            item[ignore_item.title] = ignore_item

            self.menu.insert_after(self._recent_header.title, item)

            # Keep max recent
            self._recent_events.append((level, filename, summary))
            if len(self._recent_events) > self._max_recent:
                self._recent_events.pop(0)

        @staticmethod
        def _get_remedy(level: str, summary: str, filename: str) -> str:
            """Return a short remediation suggestion based on the finding."""
            s = summary.lower()
            if "credential" in s or "ssh" in s or "aws" in s:
                return "Remove credential access patterns from this file"
            if "exfiltrat" in s or "send" in s or "evil" in s:
                return "Remove data exfiltration instructions"
            if "injection" in s or "ignore" in s or "override" in s:
                return "Remove prompt injection payload"
            if "baseline" in s or "rug pull" in s:
                return "Review changes since last baseline"
            if "toxic" in s or "flow" in s:
                return "Restrict MCP server permissions"
            if level == "THREAT":
                return f"Review and remove dangerous content from {filename}"
            return f"Review {filename} for suspicious patterns"

        @rumps.clicked("Clear Findings")
        def _clear_findings(self, sender):
            """Clear all recent findings from the menu."""
            self._recent_events.clear()
            self._threat_count = 0
            self._warning_count = 0
            self._scan_count = 0
            self._stats_item.title = "Scans: 0 | Threats: 0 | Warnings: 0"
            self.title = None if _find_icon() else _TITLE_NORMAL
            self.template = True
            # Remove finding items from menu
            keys = list(self.menu.keys())
            for k in keys:
                if k.startswith("  [THREAT]") or k.startswith("  [WARNING]"):
                    del self.menu[k]
            # Re-add placeholder
            self.menu.insert_after(
                self._recent_header.title, self._no_threats_item
            )

        @rumps.clicked("Quit")
        def _quit(self, sender):
            """Graceful shutdown: stop Shield, then exit rumps app."""
            self._stop_shield()
            rumps.quit_application()

        # ── App launch ───────────────────────────────────────────

        def run(self, **options):
            """Start Shield in background, then enter rumps event loop."""
            try:
                self._start_shield()
            except Exception as exc:
                self._status_item.title = f"Status: Error — {exc}"
            super().run(**options)
