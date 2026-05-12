from app.collectors.events import EventBuffer
from app.config import get_default_config
from app.db import SessionLocal, init_db
from app.models import EventWindow
from app.services.collector_service import CollectorService
from app.services.feature_extraction import WindowAggregator, WindowFeatures


def on_window(features: WindowFeatures) -> None:
    """
    Persist each computed feature window into the SQLite database.
    """

    session = SessionLocal()
    try:
        row = EventWindow(
            timestamp_utc=features.timestamp_utc,
            window_seconds=features.window_seconds,
            wpm=features.wpm,
            key_hold_mean=features.key_hold_mean,
            key_flight_mean=features.key_flight_mean,
            backspace_count=features.backspace_count,
            keystroke_count=features.keystroke_count,
            mouse_distance=features.mouse_distance,
            mouse_avg_speed=features.mouse_avg_speed,
            mouse_clicks=features.mouse_clicks,
            mouse_scrolls=features.mouse_scrolls,
            mouse_accel_mean=features.mouse_accel_mean,
            active_window_title=features.active_window_title,
            active_app_hash=features.active_app_hash,
            session_idle_time=features.session_idle_time,
            process_count=features.process_count,
            cpu_usage=features.cpu_usage,
            memory_usage=features.memory_usage,
            battery_level=features.battery_level,
            screen_brightness=features.screen_brightness,
            ip_address=features.ip_address,
            geo_location=features.geo_location,
            location_hash=features.location_hash,
            network_type=features.network_type,
            wifi_ssid_hash=features.wifi_ssid_hash,
            hour_of_day=features.hour_of_day,
            is_night=features.is_night,
            os_platform=features.os_platform,
            device_id=features.device_id,
        )
        session.add(row)
        session.commit()
    finally:
        session.close()


if __name__ == "__main__":
    # Ensure tables exist in the SQLite DB inside the IntrusionAI folder.
    init_db()

    cfg = get_default_config()
    buffer = EventBuffer()

    collector = CollectorService(buffer, cfg.collectors)
    aggregator = WindowAggregator(buffer, on_window, cfg.windows)

    collector.start()
    aggregator.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        collector.stop()
        aggregator.stop()