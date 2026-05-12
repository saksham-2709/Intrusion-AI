"""
Time-window aggregation and feature extraction.

This module consumes :class:`WindowSlice` objects from the collectors'
in-memory :class:`EventBuffer` and turns them into per-window feature vectors
aligned with the `event_windows` schema in the project plan.

It focuses purely on numeric/statistical computation and does not depend on
any database or web framework code.
"""

from __future__ import annotations

import math
import platform
import statistics
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Event, Thread
from typing import Callable, Dict, Iterable, Optional, Sequence

from app.collectors.events import (
    EventBuffer,
    KeyEvent,
    MouseMoveEvent,
    SystemSample,
    WindowSlice,
)
from app.config import WindowConfig, get_default_config


FeatureDict = Dict[str, float]

OS_PLATFORM = platform.platform()
DEVICE_ID = platform.node() or "unknown-device"


@dataclass(slots=True)
class WindowFeatures:
    """
    Computed feature vector for a single behaviour window.

    Fields aligned with the requested storage schema.
    """

    # Core timing
    timestamp_utc: str
    window_seconds: int

    # Typing / keystroke dynamics
    wpm: float
    key_hold_mean: float
    key_flight_mean: float
    backspace_count: int
    keystroke_count: int

    # Mouse dynamics
    mouse_distance: float
    mouse_avg_speed: float
    mouse_clicks: int
    mouse_scrolls: int
    mouse_accel_mean: float

    # Context and environment
    active_window_title: str
    active_app_hash: int
    session_idle_time: float
    process_count: int
    cpu_usage: float
    memory_usage: float
    battery_level: float | None
    screen_brightness: float

    ip_address: str
    geo_location: str
    location_hash: int
    network_type: str
    wifi_ssid_hash: int

    hour_of_day: float
    is_night: int
    os_platform: str
    device_id: str


class FeatureExtractor:
    """Static helpers to compute per-window features from raw events."""

    # ------------------------------ keyboard / keystroke dynamics ------------------------------

    @staticmethod
    def _keyboard_metrics(
        events: Sequence[KeyEvent], window_duration: float
    ) -> Dict[str, float | int]:
        presses = [e for e in events if e.is_press]
        if window_duration <= 0 or not presses:
            return {
                "wpm": 0.0,
                "key_hold_mean": 0.0,
                "key_flight_mean": 0.0,
                "backspace_count": 0,
                "keystroke_count": 0,
            }

        keystroke_count = len(presses)

        # Words per minute: standard 5 chars per word approximation.
        minutes = window_duration / 60.0
        wpm = (keystroke_count / 5.0) / minutes if minutes > 0 else 0.0

        # Approximate key hold durations: time between press and subsequent release.
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        hold_durations: list[float] = []
        pressed_at: Optional[float] = None
        for e in sorted_events:
            if e.is_press:
                pressed_at = e.timestamp
            elif pressed_at is not None:
                dt = e.timestamp - pressed_at
                if dt > 0:
                    hold_durations.append(dt)
                pressed_at = None

        key_hold_mean = statistics.fmean(hold_durations) if hold_durations else 0.0

        # Key flight time: time from one key release to the next key press.
        releases = [e for e in sorted_events if not e.is_press]
        flights: list[float] = []
        i = j = 0
        while i < len(releases) and j < len(presses):
            if presses[j].timestamp <= releases[i].timestamp:
                j += 1
                continue
            dt = presses[j].timestamp - releases[i].timestamp
            if dt > 0:
                flights.append(dt)
            i += 1
            j += 1

        key_flight_mean = statistics.fmean(flights) if flights else 0.0

        backspace_count = len([e for e in presses if e.key_repr == "backspace"])

        return {
            "wpm": float(wpm),
            "key_hold_mean": float(key_hold_mean),
            "key_flight_mean": float(key_flight_mean),
            "backspace_count": int(backspace_count),
            "keystroke_count": int(keystroke_count),
        }

    @staticmethod
    def _mouse_metrics(
        moves: Sequence[MouseMoveEvent],
        click_count: int,
        scroll_count: int,
        window_duration: float,
    ) -> Dict[str, float | int]:
        if window_duration <= 0:
            return {
                "mouse_distance": 0.0,
                "mouse_avg_speed": 0.0,
                "mouse_clicks": int(click_count),
                "mouse_scrolls": int(scroll_count),
                "mouse_accel_mean": 0.0,
            }

        moves_sorted = sorted(moves, key=lambda e: e.timestamp)
        distances: list[float] = []
        speeds: list[float] = []
        for i in range(len(moves_sorted) - 1):
            a = moves_sorted[i]
            b = moves_sorted[i + 1]
            dt = b.timestamp - a.timestamp
            if dt <= 0:
                continue
            dx = b.x - a.x
            dy = b.y - a.y
            dist = math.hypot(dx, dy)
            distances.append(dist)
            speeds.append(dist / dt)

        total_distance = sum(distances) if distances else 0.0
        avg_speed = total_distance / window_duration if window_duration > 0 else 0.0

        # Approximate mean acceleration from speed differences.
        accelerations: list[float] = []
        for i in range(len(speeds) - 1):
            dv = speeds[i + 1] - speeds[i]
            # We do not have precise delta-t between speed samples here; treat as 1.
            accelerations.append(abs(dv))
        mouse_accel_mean = statistics.fmean(accelerations) if accelerations else 0.0

        return {
            "mouse_distance": float(total_distance),
            "mouse_avg_speed": float(avg_speed),
            "mouse_clicks": int(click_count),
            "mouse_scrolls": int(scroll_count),
            "mouse_accel_mean": float(mouse_accel_mean),
        }

    @staticmethod
    def _brightness_feature(slice_: WindowSlice) -> float:
        samples = list(slice_.brightness_samples)
        if not samples:
            return 0.0
        return float(
            sum(sample.level for sample in samples) / len(samples)
        )

    @staticmethod
    def _system_features(samples: Iterable[SystemSample]) -> Dict[str, float | int | str | None]:
        samples_list = list(samples)
        if not samples_list:
            return {
                "cpu_usage": 0.0,
                "memory_usage": 0.0,
                "process_count": 0,
                "battery_level": None,
                "ip_address": "",
                "active_window_title": "",
                "active_app_hash": 0,
            }

        # Use the most recent sample in the window as representative.
        samples_sorted = sorted(samples_list, key=lambda s: s.timestamp)
        last = samples_sorted[-1]
        cpu_usage = float(last.cpu_percent)
        memory_usage = float(last.ram_percent)
        process_count = int(last.process_count)
        battery_level = float(last.battery_level) if last.battery_level is not None else None
        ip_address = last.ip_address
        active_window_title = last.active_window_title
        active_app_hash = int(last.active_app_hash)

        return {
            "cpu_usage": float(cpu_usage),
            "memory_usage": float(memory_usage),
            "process_count": process_count,
            "battery_level": battery_level,
            "ip_address": ip_address,
            "active_window_title": active_window_title,
            "active_app_hash": active_app_hash,
        }

    # ------------------------------------------------------------------ public API

    @classmethod
    def compute_features(cls, slice_: WindowSlice) -> WindowFeatures:
        """Turn a :class:`WindowSlice` into a :class:`WindowFeatures` object."""

        duration = max(slice_.window_end - slice_.window_start, 0.0)

        # Core time features
        window_seconds = int(round(duration))
        ts_utc = datetime.fromtimestamp(slice_.window_end, tz=timezone.utc)
        timestamp_utc = ts_utc.isoformat()

        hour = ts_utc.hour + ts_utc.minute / 60.0
        is_night = 1 if (hour >= 22 or hour < 6) else 0

        keyboard_feats = cls._keyboard_metrics(slice_.keyboard_events, duration)

        mouse_feats = cls._mouse_metrics(
            moves=slice_.mouse_moves,
            click_count=len(slice_.mouse_clicks),
            scroll_count=len(slice_.mouse_scrolls),
            window_duration=duration,
        )

        brightness_avg = cls._brightness_feature(slice_)
        system_feats = cls._system_features(slice_.system_samples)

        # Session idle time: time since last input (keyboard/mouse) within/just before window.
        last_input_ts = None
        for seq in (slice_.keyboard_events, slice_.mouse_moves, slice_.mouse_clicks, slice_.mouse_scrolls):
            if seq:
                ts = max(e.timestamp for e in seq)
                if last_input_ts is None or ts > last_input_ts:
                    last_input_ts = ts
        if last_input_ts is None:
            session_idle_time = duration
        else:
            session_idle_time = max(0.0, slice_.window_end - last_input_ts)

        ip_address = str(system_feats["ip_address"])
        geo_location = ""  # Placeholder – can be filled via external geo-IP later.
        location_hash = hash((ip_address or "", geo_location)) & 0xFFFFFFFF

        # Network-specific details are not yet collected; use placeholders.
        network_type = "unknown"
        wifi_ssid_hash = 0

        return WindowFeatures(
            timestamp_utc=timestamp_utc,
            window_seconds=window_seconds,
            wpm=float(keyboard_feats["wpm"]),
            key_hold_mean=float(keyboard_feats["key_hold_mean"]),
            key_flight_mean=float(keyboard_feats["key_flight_mean"]),
            backspace_count=int(keyboard_feats["backspace_count"]),
            keystroke_count=int(keyboard_feats["keystroke_count"]),
            mouse_distance=float(mouse_feats["mouse_distance"]),
            mouse_avg_speed=float(mouse_feats["mouse_avg_speed"]),
            mouse_clicks=int(mouse_feats["mouse_clicks"]),
            mouse_scrolls=int(mouse_feats["mouse_scrolls"]),
            mouse_accel_mean=float(mouse_feats["mouse_accel_mean"]),
            active_window_title=str(system_feats["active_window_title"]),
            active_app_hash=int(system_feats["active_app_hash"]),
            session_idle_time=float(session_idle_time),
            process_count=int(system_feats["process_count"]),
            cpu_usage=float(system_feats["cpu_usage"]),
            memory_usage=float(system_feats["memory_usage"]),
            battery_level=(
                float(system_feats["battery_level"])
                if system_feats["battery_level"] is not None
                else None
            ),
            screen_brightness=float(brightness_avg),
            ip_address=ip_address,
            geo_location=geo_location,
            location_hash=int(location_hash),
            network_type=network_type,
            wifi_ssid_hash=int(wifi_ssid_hash),
            hour_of_day=float(hour),
            is_night=int(is_night),
            os_platform=OS_PLATFORM,
            device_id=DEVICE_ID,
        )

        return WindowFeatures(
            window_start=slice_.window_start,
            window_end=slice_.window_end,
            typing_speed=keyboard_feats["typing_speed"],
            key_interval_mean=keyboard_feats["key_interval_mean"],
            key_interval_std=keyboard_feats["key_interval_std"],
            backspace_rate=keyboard_feats["backspace_rate"],
            mouse_speed_avg=mouse_feats["mouse_speed_avg"],
            mouse_speed_std=mouse_feats["mouse_speed_std"],
            click_frequency=mouse_feats["click_frequency"],
            scroll_rate=mouse_feats["scroll_rate"],
            brightness_level_avg=brightness_avg,
            cpu_usage_avg=system_feats["cpu_usage_avg"],
            ram_usage_avg=system_feats["ram_usage_avg"],
            net_bytes_sent=system_feats["net_bytes_sent"],
            net_bytes_recv=system_feats["net_bytes_recv"],
        )


class WindowAggregator:
    """
    Background task that periodically drains windows from an :class:`EventBuffer`
    and emits computed :class:`WindowFeatures` via a callback.

    This component is intentionally simple. It does not talk to the database
    directly; callers can persist features in the callback and later plug in
    baseline learning and anomaly detection.
    """

    def __init__(
        self,
        buffer: EventBuffer,
        on_window: Callable[[WindowFeatures], None],
        config: Optional[WindowConfig] = None,
    ) -> None:
        self._buffer = buffer
        self._on_window = on_window
        self._config = config or get_default_config().windows

        self._stop_event = Event()
        self._thread: Optional[Thread] = None
        self._last_window_end: Optional[float] = None

    def start(self) -> None:
        """Start the background aggregation thread."""

        if self._thread is not None and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = Thread(target=self._run_loop, daemon=True, name="window-aggregator")
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the aggregation thread to stop."""

        self._stop_event.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    # ---------------------------------------------------------------- private

    def _run_loop(self) -> None:
        window_size = max(self._config.window_size_seconds, 1.0)
        self._last_window_end = time.time()

        while not self._stop_event.is_set():
            # Wait until the next window boundary.
            self._stop_event.wait(window_size)
            if self._stop_event.is_set():
                break

            now = time.time()
            window_start = self._last_window_end
            window_end = now
            self._last_window_end = now

            slice_ = self._buffer.drain_window(window_start, window_end)
            features = FeatureExtractor.compute_features(slice_)
            self._on_window(features)

