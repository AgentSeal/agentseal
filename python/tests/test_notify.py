# tests/test_notify.py
"""
Tests for the desktop notification module.
"""

import subprocess
from unittest.mock import patch, MagicMock

import pytest

from agentseal.notify import Notifier


class TestNotifier:
    def setup_method(self):
        self.notifier = Notifier(enabled=True, min_interval=0.0)

    def test_disabled_returns_false(self):
        n = Notifier(enabled=False)
        assert n.notify("title", "message") is False

    def test_throttle_blocks_rapid_calls(self):
        n = Notifier(enabled=True, min_interval=60.0)
        with patch.object(n, "_dispatch", return_value=True):
            assert n.notify("title", "msg1") is True
            assert n.notify("title", "msg2") is False  # throttled

    def test_throttle_allows_after_interval(self):
        n = Notifier(enabled=True, min_interval=0.0)
        with patch.object(n, "_dispatch", return_value=True):
            assert n.notify("title", "msg1") is True
            assert n.notify("title", "msg2") is True  # no throttle

    def test_notify_threat_formats_correctly(self):
        calls = []
        with patch.object(self.notifier, "notify", side_effect=lambda *a, **kw: calls.append((a, kw)) or True):
            self.notifier.notify_threat("evil-skill", "Skill", "critical", "Credential theft")

        assert len(calls) == 1
        title, message = calls[0][0]
        assert "CRITICAL" in title
        assert "AgentSeal Shield" in title
        assert "evil-skill" in message
        assert "Credential theft" in message
        assert calls[0][1]["urgent"] is True

    def test_notify_threat_low_severity_not_urgent(self):
        calls = []
        with patch.object(self.notifier, "notify", side_effect=lambda *a, **kw: calls.append((a, kw)) or True):
            self.notifier.notify_threat("some-skill", "Skill", "low", "Minor issue")

        assert calls[0][1]["urgent"] is False


class TestNotifierMacOS:
    def test_macos_notification(self):
        n = Notifier(enabled=True, min_interval=0.0)
        n._platform = "Darwin"
        with patch("subprocess.run") as mock_run:
            result = n.notify("Test Title", "Test Message")
            assert result is True
            mock_run.assert_called_once()
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "swift"
            swift_code = mock_run.call_args.kwargs["input"]
            assert "Test Title" in swift_code
            assert "Test Message" in swift_code

    def test_macos_urgent_includes_sound(self):
        n = Notifier(enabled=True, min_interval=0.0)
        n._platform = "Darwin"
        with patch("subprocess.run") as mock_run:
            n.notify("Title", "Msg", urgent=True)
            swift_code = mock_run.call_args.kwargs["input"]
            assert "Basso" in swift_code

    def test_macos_escapes_quotes(self):
        n = Notifier(enabled=True, min_interval=0.0)
        n._platform = "Darwin"
        with patch("subprocess.run") as mock_run:
            n.notify('Has "quotes"', 'Message with "quotes"')
            swift_code = mock_run.call_args.kwargs["input"]
            assert '\\"' in swift_code

    def test_macos_falls_back_on_timeout(self):
        n = Notifier(enabled=True, min_interval=0.0)
        n._platform = "Darwin"
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("osascript", 5)):
            with patch("sys.stderr") as mock_stderr:
                mock_stderr.write = MagicMock()
                mock_stderr.flush = MagicMock()
                result = n.notify("Title", "Msg")
                assert result is True  # fallback always succeeds


class TestNotifierLinux:
    def test_linux_notification(self):
        n = Notifier(enabled=True, min_interval=0.0)
        n._platform = "Linux"
        with patch("subprocess.run") as mock_run:
            result = n.notify("Test Title", "Test Message")
            assert result is True
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "notify-send"
            assert "Test Title" in cmd
            assert "Test Message" in cmd

    def test_linux_urgent_critical(self):
        n = Notifier(enabled=True, min_interval=0.0)
        n._platform = "Linux"
        with patch("subprocess.run") as mock_run:
            n.notify("Title", "Msg", urgent=True)
            cmd = mock_run.call_args[0][0]
            assert "--urgency=critical" in cmd

    def test_linux_falls_back_if_not_found(self):
        n = Notifier(enabled=True, min_interval=0.0)
        n._platform = "Linux"
        with patch("subprocess.run", side_effect=FileNotFoundError):
            with patch("sys.stderr") as mock_stderr:
                mock_stderr.write = MagicMock()
                mock_stderr.flush = MagicMock()
                result = n.notify("Title", "Msg")
                assert result is True


class TestNotifierFallback:
    def test_unknown_platform_uses_fallback(self):
        n = Notifier(enabled=True, min_interval=0.0)
        n._platform = "FreeBSD"
        with patch("sys.stderr") as mock_stderr:
            mock_stderr.write = MagicMock()
            mock_stderr.flush = MagicMock()
            result = n.notify("Title", "Msg")
            assert result is True
            mock_stderr.write.assert_called_once()
            written = mock_stderr.write.call_args[0][0]
            assert "Title" in written
            assert "Msg" in written
