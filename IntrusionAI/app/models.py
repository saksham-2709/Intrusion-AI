"""
saaare features ko sqlite ke table mai define karna 
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, Float, Integer, String, Text

from app.db import Base


class EventWindow(Base):
    

    __tablename__ = "event_windows"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Core timing
    timestamp_utc = Column(Text, nullable=False)  
    window_seconds = Column(Integer, nullable=False)

    # Typing / keystroke dynamics
    wpm = Column(Float, nullable=False)
    key_hold_mean = Column(Float, nullable=False)
    key_flight_mean = Column(Float, nullable=False)
    backspace_count = Column(Integer, nullable=False)
    keystroke_count = Column(Integer, nullable=False)

    # Mouse dynamics
    mouse_distance = Column(Float, nullable=False)
    mouse_avg_speed = Column(Float, nullable=False)
    mouse_clicks = Column(Integer, nullable=False)
    mouse_scrolls = Column(Integer, nullable=False)
    mouse_accel_mean = Column(Float, nullable=False)

    # Context and environment
    active_window_title = Column(Text, nullable=False)
    active_app_hash = Column(Integer, nullable=False)
    session_idle_time = Column(Float, nullable=False)
    process_count = Column(Integer, nullable=False)
    cpu_usage = Column(Float, nullable=False)
    memory_usage = Column(Float, nullable=False)
    battery_level = Column(Float, nullable=True)
    screen_brightness = Column(Float, nullable=False)

    ip_address = Column(String(64), nullable=False)
    geo_location = Column(Text, nullable=False)
    location_hash = Column(Integer, nullable=False)
    network_type = Column(String(32), nullable=False)
    wifi_ssid_hash = Column(Integer, nullable=False)

    hour_of_day = Column(Float, nullable=False)
    is_night = Column(Integer, nullable=False)  # 0/1
    os_platform = Column(Text, nullable=False)
    device_id = Column(Text, nullable=False)

    # Metadata
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

