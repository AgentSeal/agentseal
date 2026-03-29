# agentseal/notify.py
"""
Desktop notifications for AgentSeal Shield.

Uses OS built-in notification mechanisms - no additional dependencies.
macOS: osascript, Linux: notify-send, Fallback: terminal bell + stderr.
"""

import platform
import subprocess
import sys
import time
from typing import Optional


_SEVERITY_ICONS = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}


class Notifier:
    """Cross-platform desktop notification dispatcher with throttling."""

    def __init__(self, enabled: bool = True, min_interval: float = 30.0):
        self._enabled = enabled
        self._min_interval = min_interval
        self._last_notify_time: float = float("-inf")
        self._platform = platform.system()

    def notify(
        self,
        title: str,
        message: str,
        *,
        urgent: bool = False,
    ) -> bool:
        """Send a desktop notification. Returns True if notification was sent.

        Respects throttle interval - returns False if called too soon after
        the previous notification.
        """
        if not self._enabled:
            return False

        now = time.monotonic()
        if now - self._last_notify_time < self._min_interval:
            return False

        sent = self._dispatch(title, message, urgent=urgent)
        if sent:
            self._last_notify_time = now
        return sent

    def notify_threat(
        self,
        item_name: str,
        item_type: str,
        severity: str,
        detail: str,
    ) -> bool:
        """Send a threat notification with standard formatting."""
        level = _SEVERITY_ICONS.get(severity, severity.upper())
        title = f"AgentSeal Shield - {level}"
        message = f"{item_type}: {item_name}\n{detail}"
        return self.notify(title, message, urgent=severity in ("critical", "high"))

    def _dispatch(self, title: str, message: str, *, urgent: bool = False) -> bool:
        """Send notification via platform-specific mechanism."""
        if self._platform == "Darwin":
            return self._notify_macos(title, message, urgent=urgent)
        elif self._platform == "Linux":
            return self._notify_linux(title, message, urgent=urgent)
        return self._notify_fallback(title, message)

    def _notify_macos(self, title: str, message: str, *, urgent: bool = False) -> bool:
        """macOS notification via Swift helper (no Script Editor on click)."""
        # Swift sends a proper UNUserNotification that dismisses on click
        # instead of opening Script Editor like osascript does
        safe_title = title.replace("\\", "\\\\").replace('"', '\\"')
        safe_message = message.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " - ")
        sound = "true" if urgent else "false"
        swift_code = f'''
import Foundation
import UserNotifications

let sem = DispatchSemaphore(value: 0)
let center = UNUserNotificationCenter.current()
center.requestAuthorization(options: [.alert, .sound]) {{ _, _ in
    let content = UNMutableNotificationContent()
    content.title = "{safe_title}"
    content.body = "{safe_message}"
    if {sound} {{ content.sound = UNNotificationSound(named: UNNotificationSoundName("Basso")) }}
    else {{ content.sound = .default }}
    let req = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
    center.add(req) {{ _ in sem.signal() }}
}}
_ = sem.wait(timeout: .now() + 4)
'''
        try:
            subprocess.run(
                ["swift", "-"],
                input=swift_code,
                capture_output=True,
                timeout=10,
                text=True,
            )
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            # Fall back to osascript if Swift is not available
            return self._notify_macos_fallback(title, message, urgent=urgent)

    def _notify_macos_fallback(self, title: str, message: str, *, urgent: bool = False) -> bool:
        """Fallback macOS notification via osascript."""
        safe_title = title.replace('"', '\\"')
        safe_message = message.replace('"', '\\"').replace("\n", " - ")
        sound = ' sound name "Basso"' if urgent else ""
        script = (
            f'display notification "{safe_message}" '
            f'with title "{safe_title}"{sound}'
        )
        try:
            subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                timeout=5,
            )
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return self._notify_fallback(title, message)

    def _notify_linux(self, title: str, message: str, *, urgent: bool = False) -> bool:
        """Linux notification via notify-send."""
        urgency = "critical" if urgent else "normal"
        try:
            subprocess.run(
                [
                    "notify-send",
                    title,
                    message,
                    f"--urgency={urgency}",
                    "--icon=dialog-warning",
                ],
                capture_output=True,
                timeout=5,
            )
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return self._notify_fallback(title, message)

    @staticmethod
    def _notify_fallback(title: str, message: str) -> bool:
        """Fallback: terminal bell + colored stderr output."""
        sys.stderr.write(f"\a\033[93m[{title}]\033[0m {message}\n")
        sys.stderr.flush()
        return True
