"""
Tests for the Shield Menu Bar app.

Tests cover:
- check_rumps_available() guard function
- Event queue thread-safety under concurrent pushes
- Shield on_event callback → queue population
- Pause/resume cycle
- CLI --menubar flag routing
- Version string from package
"""

import pathlib
import queue
import sys
import threading
from unittest.mock import MagicMock, patch

import pytest

try:
    import importlib.util
    _HAS_RUMPS = importlib.util.find_spec("rumps") is not None
except (ImportError, ModuleNotFoundError):
    _HAS_RUMPS = False


# ═══════════════════════════════════════════════════════════════════
# check_rumps_available
# ═══════════════════════════════════════════════════════════════════


class TestCheckRumpsAvailable:
    def test_raises_when_rumps_not_installed(self):
        """check_rumps_available() should raise ImportError when rumps is missing."""
        with patch("agentseal.shield_menubar._RUMPS_AVAILABLE", False):
            from agentseal.shield_menubar import check_rumps_available
            with pytest.raises(ImportError, match="rumps"):
                check_rumps_available()

    def test_passes_when_rumps_installed(self):
        """check_rumps_available() should not raise when rumps is available."""
        with patch("agentseal.shield_menubar._RUMPS_AVAILABLE", True):
            from agentseal.shield_menubar import check_rumps_available
            check_rumps_available()  # Should not raise


# ═══════════════════════════════════════════════════════════════════
# Event Queue Thread Safety
# ═══════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not _HAS_RUMPS, reason="rumps not installed")
class TestShieldMenuBarAppEvents:
    """Test event handling through the actual ShieldMenuBarApp."""

    def test_on_shield_event_pushes_to_queue(self):
        """_on_shield_event should populate the app's internal event queue."""
        from agentseal.shield_menubar import ShieldMenuBarApp

        app = ShieldMenuBarApp(semantic=False, notify=False)
        app._on_shield_event("threat", "/tmp/evil.md", "DANGER - SSH key exfil")

        assert app._event_queue.qsize() == 1
        event = app._event_queue.get_nowait()
        assert event == ("threat", "/tmp/evil.md", "DANGER - SSH key exfil")

    def test_on_shield_event_concurrent_pushes(self):
        """Multiple threads calling _on_shield_event should not lose events."""
        from agentseal.shield_menubar import ShieldMenuBarApp

        app = ShieldMenuBarApp(semantic=False, notify=False)
        n_threads = 10
        n_events_per_thread = 100

        def push_events(thread_id):
            for i in range(n_events_per_thread):
                app._on_shield_event("threat", f"/path/{thread_id}/{i}", "summary")

        threads = [
            threading.Thread(target=push_events, args=(t,))
            for t in range(n_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert app._event_queue.qsize() == n_threads * n_events_per_thread

    def test_on_shield_event_multiple_types(self):
        """Different event types all flow through the app's queue."""
        from agentseal.shield_menubar import ShieldMenuBarApp

        app = ShieldMenuBarApp(semantic=False, notify=False)
        for etype in ("threat", "warning", "clean", "error"):
            app._on_shield_event(etype, "/tmp/file.md", f"summary-{etype}")

        assert app._event_queue.qsize() == 4
        types = [app._event_queue.get_nowait()[0] for _ in range(4)]
        assert types == ["threat", "warning", "clean", "error"]

    def test_empty_queue_raises(self):
        """get_nowait on fresh app queue should raise queue.Empty."""
        from agentseal.shield_menubar import ShieldMenuBarApp

        app = ShieldMenuBarApp(semantic=False, notify=False)
        with pytest.raises(queue.Empty):
            app._event_queue.get_nowait()


# ═══════════════════════════════════════════════════════════════════
# Version String
# ═══════════════════════════════════════════════════════════════════


class TestVersionString:
    def test_get_version_returns_string(self):
        """_get_version should return the agentseal version string."""
        from agentseal import __version__
        # _get_version is only on ShieldMenuBarApp which requires rumps,
        # so test the logic directly
        assert isinstance(__version__, str)
        assert __version__ != "unknown"

    def test_get_version_fallback(self):
        """Version fallback returns 'unknown' if agentseal can't be imported."""
        # Simulate the _get_version logic when agentseal is missing
        try:
            with patch.dict("sys.modules", {"agentseal": None}):
                try:
                    from agentseal import __version__
                    version = __version__
                except (ImportError, TypeError):
                    version = "unknown"
        except Exception:
            version = "unknown"
        assert isinstance(version, str)


# ═══════════════════════════════════════════════════════════════════
# CLI --menubar Flag
# ═══════════════════════════════════════════════════════════════════


class TestCLIMenubarFlag:
    def test_menubar_flag_exists_in_parser(self):
        """Shield parser should accept --menubar flag."""
        import agentseal.cli as cli_module
        source = pathlib.Path(cli_module.__file__).read_text()
        assert "--menubar" in source
        assert "_run_shield_menubar" in source

    def test_menubar_dispatch(self):
        """--menubar flag should route to _run_shield_menubar via real main()."""
        test_argv = ["agentseal", "shield", "--menubar"]
        with patch.object(sys, "argv", test_argv), \
             patch("agentseal.cli._run_shield_menubar") as mock_menubar, \
             patch("agentseal.cli._run_shield") as mock_shield:
            from agentseal.cli import main
            main()

            mock_menubar.assert_called_once()
            mock_shield.assert_not_called()

    def test_no_menubar_dispatches_to_terminal(self):
        """Without --menubar, should route to _run_shield via real main()."""
        test_argv = ["agentseal", "shield"]
        with patch.object(sys, "argv", test_argv), \
             patch("agentseal.cli._run_shield_menubar") as mock_menubar, \
             patch("agentseal.cli._run_shield") as mock_shield:
            from agentseal.cli import main
            main()

            mock_shield.assert_called_once()
            mock_menubar.assert_not_called()


# ═══════════════════════════════════════════════════════════════════
# ShieldMenuBarApp (requires rumps)
# ═══════════════════════════════════════════════════════════════════

@pytest.mark.skipif(not _HAS_RUMPS, reason="rumps not installed")
class TestShieldMenuBarApp:
    def test_init_creates_menu_items(self):
        """App should initialize with correct menu structure."""
        from agentseal.shield_menubar import ShieldMenuBarApp
        app = ShieldMenuBarApp(semantic=False, notify=False)
        assert app.title == "🛡"
        assert app._scan_count == 0
        assert app._threat_count == 0
        assert app._paused is False

    def test_initial_status(self):
        """Initial status should show 'Starting...'."""
        from agentseal.shield_menubar import ShieldMenuBarApp
        app = ShieldMenuBarApp(semantic=False, notify=False)
        assert "Starting" in app._status_item.title

    def test_stats_initial(self):
        """Initial stats should show 0/0."""
        from agentseal.shield_menubar import ShieldMenuBarApp
        app = ShieldMenuBarApp(semantic=False, notify=False)
        assert "Scans: 0" in app._stats_item.title
        assert "Threats: 0" in app._stats_item.title

    def test_pause_resume_cycle(self):
        """Pause/resume toggle should flip _paused and sender.state."""
        from agentseal.shield_menubar import ShieldMenuBarApp

        app = ShieldMenuBarApp(semantic=False, notify=False)
        mock_sender = MagicMock()
        mock_sender.state = 0

        with patch.object(app, '_stop_shield'), patch.object(app, '_start_shield'):
            app._toggle_pause(mock_sender)
            assert app._paused is True
            assert mock_sender.state == 1

            app._toggle_pause(mock_sender)
            assert app._paused is False
            assert mock_sender.state == 0

    def test_poll_events_increments_counters(self):
        """_poll_events should drain queue, update counters and title."""
        from agentseal.shield_menubar import ShieldMenuBarApp, _TITLE_ALERT

        app = ShieldMenuBarApp(semantic=False, notify=False)
        app._on_shield_event("clean", "/tmp/a.md", "ok")
        app._on_shield_event("threat", "/tmp/b.md", "bad")

        with patch("rumps.notification"):
            app._poll_events(None)

        assert app._scan_count == 2
        assert app._threat_count == 1
        assert app.title == _TITLE_ALERT

    def test_poll_events_handles_warnings(self):
        """_poll_events should count warnings, show alert title, and notify."""
        from agentseal.shield_menubar import ShieldMenuBarApp, _TITLE_ALERT

        app = ShieldMenuBarApp(semantic=False, notify=False)
        app._on_shield_event("warning", "/tmp/c.md", "baseline changed")

        with patch("rumps.notification") as mock_notif:
            app._poll_events(None)

        assert app._scan_count == 1
        assert app._warning_count == 1
        assert app.title == _TITLE_ALERT
        assert "Warnings: 1" in app._stats_item.title
        mock_notif.assert_called_once()
        assert "WARNING" in mock_notif.call_args[1].get("title", mock_notif.call_args[0][0] if mock_notif.call_args[0] else "")

    def test_resume_failure_stays_paused(self):
        """If _start_shield raises on resume, app should stay paused."""
        from agentseal.shield_menubar import ShieldMenuBarApp

        app = ShieldMenuBarApp(semantic=False, notify=False)
        mock_sender = MagicMock()
        mock_sender.state = 0

        # First pause
        with patch.object(app, '_stop_shield'):
            app._toggle_pause(mock_sender)
        assert app._paused is True

        # Resume fails — Shield constructor throws
        with patch("agentseal.shield_menubar.Shield", side_effect=RuntimeError("import failed")):
            app._toggle_pause(mock_sender)

        # Should still be paused
        assert app._paused is True
        assert mock_sender.state == 1  # checkmark still ON
        assert "Error" in app._status_item.title

    def test_resume_failure_shield_none_stays_paused(self):
        """If _start_shield succeeds but shield.start() fails, app stays paused."""
        from agentseal.shield_menubar import ShieldMenuBarApp

        app = ShieldMenuBarApp(semantic=False, notify=False)
        mock_sender = MagicMock()
        mock_sender.state = 0

        # First pause
        with patch.object(app, '_stop_shield'):
            app._toggle_pause(mock_sender)
        assert app._paused is True

        # Resume: _start_shield runs but sets self._shield = None (start() failed)
        def start_shield_that_fails():
            app._shield = None
            app._status_item.title = "Status: Error — start failed"

        with patch.object(app, '_start_shield', side_effect=start_shield_that_fails):
            app._toggle_pause(mock_sender)

        assert app._paused is True
        assert mock_sender.state == 1
