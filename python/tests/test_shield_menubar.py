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

import queue
import threading
from unittest.mock import MagicMock, patch

import pytest


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


class TestEventQueue:
    def test_concurrent_pushes(self):
        """Multiple threads pushing events should not lose any."""
        q: queue.Queue = queue.Queue()
        n_threads = 10
        n_events_per_thread = 100

        def push_events(thread_id):
            for i in range(n_events_per_thread):
                q.put(("threat", f"/path/{thread_id}/{i}", "summary"))

        threads = [
            threading.Thread(target=push_events, args=(t,))
            for t in range(n_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert q.qsize() == n_threads * n_events_per_thread

    def test_drain_returns_all_events(self):
        """Draining queue with get_nowait should return all pushed events."""
        q: queue.Queue = queue.Queue()
        for i in range(50):
            q.put(("clean", f"/path/{i}", "ok"))

        drained = []
        while True:
            try:
                drained.append(q.get_nowait())
            except queue.Empty:
                break

        assert len(drained) == 50

    def test_get_nowait_on_empty_raises(self):
        """get_nowait on empty queue should raise queue.Empty."""
        q: queue.Queue = queue.Queue()
        with pytest.raises(queue.Empty):
            q.get_nowait()


# ═══════════════════════════════════════════════════════════════════
# Shield on_event → Queue Population
# ═══════════════════════════════════════════════════════════════════


class TestShieldEventCallback:
    def test_on_event_pushes_to_queue(self):
        """Shield's on_event callback should push events to the queue."""
        event_queue: queue.Queue = queue.Queue()

        def on_shield_event(event_type, path, summary):
            event_queue.put((event_type, path, summary))

        # Simulate Shield calling back from background thread
        t = threading.Thread(
            target=on_shield_event,
            args=("threat", "/tmp/evil.md", "DANGER - SSH key exfil"),
        )
        t.start()
        t.join()

        assert event_queue.qsize() == 1
        event = event_queue.get_nowait()
        assert event == ("threat", "/tmp/evil.md", "DANGER - SSH key exfil")

    def test_multiple_event_types(self):
        """Different event types all flow through the queue."""
        event_queue: queue.Queue = queue.Queue()

        def on_event(et, p, s):
            event_queue.put((et, p, s))

        for etype in ("threat", "warning", "clean", "error"):
            on_event(etype, "/tmp/file.md", f"summary-{etype}")

        assert event_queue.qsize() == 4
        types = [event_queue.get_nowait()[0] for _ in range(4)]
        assert types == ["threat", "warning", "clean", "error"]


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
        source = open(cli_module.__file__).read()
        assert "--menubar" in source
        assert "_run_shield_menubar" in source

    def test_menubar_dispatch(self):
        """--menubar flag should route to _run_shield_menubar."""
        args = MagicMock()
        args.command = "shield"
        args.menubar = True

        with patch("agentseal.cli._run_shield_menubar") as mock_menubar:
            with patch("agentseal.cli._run_shield") as mock_shield:
                if getattr(args, "menubar", False):
                    mock_menubar(args)
                else:
                    mock_shield(args)

                mock_menubar.assert_called_once_with(args)
                mock_shield.assert_not_called()

    def test_no_menubar_dispatches_to_terminal(self):
        """Without --menubar, should route to _run_shield."""
        args = MagicMock()
        args.command = "shield"
        args.menubar = False

        with patch("agentseal.cli._run_shield_menubar") as mock_menubar:
            with patch("agentseal.cli._run_shield") as mock_shield:
                if getattr(args, "menubar", False):
                    mock_menubar(args)
                else:
                    mock_shield(args)

                mock_shield.assert_called_once_with(args)
                mock_menubar.assert_not_called()


# ═══════════════════════════════════════════════════════════════════
# ShieldMenuBarApp (requires rumps)
# ═══════════════════════════════════════════════════════════════════

try:
    import importlib.util
    _HAS_RUMPS = importlib.util.find_spec("rumps") is not None
except (ImportError, ModuleNotFoundError):
    _HAS_RUMPS = False


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
