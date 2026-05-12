"""
sirf events note kar raha hai
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from typing import List, Sequence, Tuple


@dataclass(slots=True)
class KeyEvent:
    """
     keyboard ke liye 
    """
    timestamp: float  
    is_press: bool
    key_repr: str  


@dataclass(slots=True)
class MouseMoveEvent:
    timestamp: float
    x: int
    y: int


@dataclass(slots=True)
class MouseClickEvent:
    timestamp: float
    button: str  # left right
    pressed: bool

@dataclass(slots=True)
class MouseScrollEvent:
    timestamp: float
    dx: int
    dy: int

@dataclass(slots=True)
class BrightnessSample:
    timestamp: float
    level: float  # percentage 

@dataclass(slots=True)
class SystemSample:

    timestamp: float
    cpu_percent: float
    ram_percent: float
    bytes_sent: int
    bytes_recv: int
    process_count: int
    battery_level: float | None
    ip_address: str
    active_window_title: str
    active_app_hash: int

@dataclass(slots=True)
class WindowSlice:

    window_start: float
    window_end: float
    keyboard_events: Sequence[KeyEvent]
    mouse_moves: Sequence[MouseMoveEvent]
    mouse_clicks: Sequence[MouseClickEvent]
    mouse_scrolls: Sequence[MouseScrollEvent]
    brightness_samples: Sequence[BrightnessSample]
    system_samples: Sequence[SystemSample]


class EventBuffer:
    """
    Thread-safe in-memory buffer shared between collectors and the aggregator.

    Collectors continuously append events, while the aggregator periodically
    snapshots and prunes events that fall into completed windows.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._keyboard_events: List[KeyEvent] = []
        self._mouse_moves: List[MouseMoveEvent] = []
        self._mouse_clicks: List[MouseClickEvent] = []
        self._mouse_scrolls: List[MouseScrollEvent] = []
        self._brightness_samples: List[BrightnessSample] = []
        self._system_samples: List[SystemSample] = []

    # --- Append APIs used by collectors 

    def add_key_event(self, event: KeyEvent) -> None:
        with self._lock:
            self._keyboard_events.append(event)

    def add_mouse_move(self, event: MouseMoveEvent) -> None:
        with self._lock:
            self._mouse_moves.append(event)

    def add_mouse_click(self, event: MouseClickEvent) -> None:
        with self._lock:
            self._mouse_clicks.append(event)

    def add_mouse_scroll(self, event: MouseScrollEvent) -> None:
        with self._lock:
            self._mouse_scrolls.append(event)

    def add_brightness_sample(self, sample: BrightnessSample) -> None:
        with self._lock:
            self._brightness_samples.append(sample)

    def add_system_sample(self, sample: SystemSample) -> None:
        with self._lock:
            self._system_samples.append(sample)

    # --- Window slicing API -------------------------------------------------------------

    def snapshot_window(self, window_start: float, window_end: float) -> WindowSlice:
        """
        Return all events in (window_start, window_end] without pruning.

        The caller can decide what to do with the data; this is useful if you
        want overlapping or sliding windows. For non-overlapping windows that
        discard old data, prefer :meth:`drain_window`.
        """

        with self._lock:
            keyboard = [e for e in self._keyboard_events if window_start < e.timestamp <= window_end]
            moves = [e for e in self._mouse_moves if window_start < e.timestamp <= window_end]
            clicks = [e for e in self._mouse_clicks if window_start < e.timestamp <= window_end]
            scrolls = [e for e in self._mouse_scrolls if window_start < e.timestamp <= window_end]
            brightness = [e for e in self._brightness_samples if window_start < e.timestamp <= window_end]
            system = [e for e in self._system_samples if window_start < e.timestamp <= window_end]

        return WindowSlice(
            window_start=window_start,
            window_end=window_end,
            keyboard_events=keyboard,
            mouse_moves=moves,
            mouse_clicks=clicks,
            mouse_scrolls=scrolls,
            brightness_samples=brightness,
            system_samples=system,
        )

    def drain_window(self, window_start: float, window_end: float) -> WindowSlice:
        """
        Similar to :meth:`snapshot_window`, but also prunes events up to
        ``window_end`` so memory usage stays bounded for long-running agents.
        """

        with self._lock:
            keyboard_window, self._keyboard_events = self._split(
                self._keyboard_events, window_start, window_end
            )
            moves_window, self._mouse_moves = self._split(
                self._mouse_moves, window_start, window_end
            )
            clicks_window, self._mouse_clicks = self._split(
                self._mouse_clicks, window_start, window_end
            )
            scrolls_window, self._mouse_scrolls = self._split(
                self._mouse_scrolls, window_start, window_end
            )
            brightness_window, self._brightness_samples = self._split(
                self._brightness_samples, window_start, window_end
            )
            system_window, self._system_samples = self._split(
                self._system_samples, window_start, window_end
            )

        return WindowSlice(
            window_start=window_start,
            window_end=window_end,
            keyboard_events=keyboard_window,
            mouse_moves=moves_window,
            mouse_clicks=clicks_window,
            mouse_scrolls=scrolls_window,
            brightness_samples=brightness_window,
            system_samples=system_window,
        )

    @staticmethod
    def _split(
        events: Sequence[object], window_start: float, window_end: float
    ) -> Tuple[List[object], List[object]]:
        """
        Partition events into:
        - in_window: timestamps in (window_start, window_end]
        - remaining: timestamps > window_end

        Events with timestamps <= window_start are discarded, since they
        belong to older windows that should already have been processed.
        """

        in_window: List[object] = []
        remaining: List[object] = []
        for e in events:
            ts = getattr(e, "timestamp", None)
            if ts is None:
                continue
            if window_start < ts <= window_end:
                in_window.append(e)
            elif ts > window_end:
                remaining.append(e)
            # else: ts <= window_start, drop it
        return in_window, remaining

