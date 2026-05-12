"""
Windows data collectors for the IntrusionAI agent.

This module wires together:
 - Keyboard & mouse listeners using ``pynput``
 - Periodic brightness sampling using ``screen_brightness_control``
 - Periodic system metrics sampling using ``psutil``

All observations are written into an :class:`EventBuffer`, which is later
consumed by the feature extraction and anomaly detection pipeline.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Optional

import psutil
from pynput import keyboard, mouse

try:
    import screen_brightness_control as sbc
except Exception:  # pragma: no cover - optional dependency / environment
    sbc = None  # type: ignore[assignment]

try:  # pragma: no cover - Windows-specific dependency
    import win32gui
    import win32process
except Exception:  # pragma: no cover - optional, best-effort only
    win32gui = None  # type: ignore[assignment]
    win32process = None  # type: ignore[assignment]

from app.collectors.events import (
    BrightnessSample,
    EventBuffer,
    KeyEvent,
    MouseClickEvent,
    MouseMoveEvent,
    MouseScrollEvent,
    SystemSample,
)
from app.config import CollectorConfig, get_default_config

logger = logging.getLogger(__name__)


class CollectorService:
   

    def __init__(
        self,
        buffer: EventBuffer,
        config: Optional[CollectorConfig] = None,
    ) -> None:
        self._buffer = buffer
        self._config = config or get_default_config().collectors

        self._keyboard_listener: Optional[keyboard.Listener] = None
        self._mouse_listener: Optional[mouse.Listener] = None

        self._brightness_thread: Optional[threading.Thread] = None
        self._system_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    #  lifecycle

    def start(self) -> None:

        logger.info("Starting Windows collectors")
        self._stop_event.clear()

        self._keyboard_listener = keyboard.Listener(
            on_press=self._on_key_press,
            on_release=self._on_key_release,
        )
        self._keyboard_listener.start()

        self._mouse_listener = mouse.Listener(
            on_move=self._on_move,
            on_click=self._on_click,
            on_scroll=self._on_scroll,
        )
        self._mouse_listener.start()

        self._brightness_thread = threading.Thread(
            target=self._brightness_loop,
            name="brightness-collector",
            daemon=True,
        )
        self._brightness_thread.start()

        self._system_thread = threading.Thread(
            target=self._system_loop,
            name="system-collector",
            daemon=True,
        )
        self._system_thread.start()

    def stop(self, timeout: float = 5.0) -> None:

        logger.info("Stopping Windows collectors")
        self._stop_event.set()

        if self._keyboard_listener is not None:
            self._keyboard_listener.stop()
            self._keyboard_listener = None

        if self._mouse_listener is not None:
            self._mouse_listener.stop()
            self._mouse_listener = None

        for thread in (self._brightness_thread, self._system_thread):
            if thread is not None and thread.is_alive():
                thread.join(timeout=timeout)

    # keyboard/mouse

    @staticmethod
    def _key_to_repr(key: keyboard.Key | keyboard.KeyCode) -> str:
       
        # Special keys (enter, backspace, etc.)
        if isinstance(key, keyboard.Key):
            return key.name or "special"

        # Character keys – we only keep a generic tag
        if isinstance(key, keyboard.KeyCode) and key.char is not None:
            # We purposefully do NOT record the actual character here to avoid
            # storing sensitive content; only the fact that a character key
            # was pressed.
            return "char"

        return "unknown"

    def _on_key_press(self, key: keyboard.Key | keyboard.KeyCode) -> None:
        ts = time.time()
        evt = KeyEvent(timestamp=ts, is_press=True, key_repr=self._key_to_repr(key))
        self._buffer.add_key_event(evt)

    def _on_key_release(self, key: keyboard.Key | keyboard.KeyCode) -> None:
        ts = time.time()
        evt = KeyEvent(timestamp=ts, is_press=False, key_repr=self._key_to_repr(key))
        self._buffer.add_key_event(evt)

    def _on_move(self, x: int, y: int) -> None:
        ts = time.time()
        self._buffer.add_mouse_move(MouseMoveEvent(timestamp=ts, x=x, y=y))

    def _on_click(self, x: int, y: int, button: mouse.Button, pressed: bool) -> None:
        ts = time.time()
        btn_name = getattr(button, "name", str(button))
        self._buffer.add_mouse_click(
            MouseClickEvent(timestamp=ts, button=btn_name, pressed=pressed)
        )

    def _on_scroll(self, x: int, y: int, dx: int, dy: int) -> None:
        ts = time.time()
        self._buffer.add_mouse_scroll(
            MouseScrollEvent(timestamp=ts, dx=dx, dy=dy)
        )

    def _brightness_loop(self) -> None:
        interval = max(self._config.brightness_interval_seconds, 0.5)
        if sbc is None:
            logger.warning(
                " brightness collection disabled"
            )
            return

        while not self._stop_event.is_set():
            ts = time.time()
            try:
                # ``get_brightness`` may return a list for multiple monitors.
                value = sbc.get_brightness()
                level: float
                if isinstance(value, list) and value:
                    level = float(sum(value) / len(value))
                else:
                    level = float(value)  # type: ignore[arg-type]

                self._buffer.add_brightness_sample(
                    BrightnessSample(timestamp=ts, level=level)
                )
            except Exception as exc:  
                logger.debug("Failed to sample brightness: %s", exc)

            self._stop_event.wait(interval)

    def _system_loop(self) -> None:
        interval = max(self._config.system_interval_seconds, 0.5)

        while not self._stop_event.is_set():
            ts = time.time()
            try:
                cpu = float(psutil.cpu_percent(interval=None))
                ram = float(psutil.virtual_memory().percent)
                net = psutil.net_io_counters()
                process_count = len(psutil.pids())

                battery = psutil.sensors_battery()
                battery_level = float(battery.percent) if battery is not None else None

                ip_address = ""
                try:
                    for _iface, addrs in psutil.net_if_addrs().items():
                        for addr in addrs:
                            if addr.family == socket.AF_INET and not addr.address.startswith(
                                "127."
                            ):
                                ip_address = addr.address
                                break
                        if ip_address:
                            break
                except Exception:
                    ip_address = ""

                active_window_title = ""
                active_app_hash = 0
                if win32gui is not None and win32process is not None:
                    try:
                        hwnd = win32gui.GetForegroundWindow()
                        if hwnd:
                            active_window_title = win32gui.GetWindowText(hwnd) or ""
                            _tid, pid = win32process.GetWindowThreadProcessId(hwnd)
                            try:
                                proc = psutil.Process(pid)
                                app_name = proc.name()
                                active_app_hash = hash(app_name) & 0xFFFFFFFF
                            except Exception:
                                active_app_hash = 0
                    except Exception:
                        active_window_title = ""
                        active_app_hash = 0

                self._buffer.add_system_sample(
                    SystemSample(
                        timestamp=ts,
                        cpu_percent=cpu,
                        ram_percent=ram,
                        bytes_sent=int(net.bytes_sent),
                        bytes_recv=int(net.bytes_recv),
                        process_count=process_count,
                        battery_level=battery_level,
                        ip_address=ip_address,
                        active_window_title=active_window_title,
                        active_app_hash=active_app_hash,
                    )
                )
            except Exception as exc:  # pragma: no cover - environment dependent
                logger.debug("Failed to sample system metrics: %s", exc)

            self._stop_event.wait(interval)

