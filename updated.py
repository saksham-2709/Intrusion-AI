
import os
import time
import json
import math
import threading
from collections import deque, defaultdict
from datetime import datetime
import csv
import platform
import sys

# Optional imports
try:
    from pynput import keyboard, mouse
except Exception:
    keyboard = None
    mouse = None

try:
    import screen_brightness_control as sbc
except Exception:
    sbc = None

try:
    import requests
except Exception:
    requests = None

try:
    import psutil
except Exception:
    psutil = None

try:
    import joblib
except Exception:
    joblib = None

try:
    import numpy as np
    import pandas as pd
except Exception:
    np = None
    pd = None

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
except Exception:
    IsolationForest = None
    StandardScaler = None

# Active window (cross-platform best-effort)
try:
    import pygetwindow as gw
except Exception:
    gw = None

# WiFi (optional)
try:
    import pywifi
    from pywifi import PyWiFi
except Exception:
    pywifi = None

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# --- Config ---
WINDOW_SECONDS = 30      # feature aggregation window
BASELINE_SECONDS = 300   # default baseline collection time (5 minutes)
MODEL_FILE = "if_model_full.joblib"
SCALER_FILE = "scaler_full.joblib"
LOG_FILE = "anomaly_log_full.csv"
PROFILE_FILE = "intrusionai_full_profile.json"

# --- Collector & Feature extraction ---
class Collector:
    def __init__(self):
        # keyboard events: store (ts, key, event_type)
        self.key_events = deque()
        # key hold times (map key -> last_press_ts)
        self._press_times = {}
        self.hold_times = deque(maxlen=5000)
        self.flight_times = deque(maxlen=5000)
        self.backspace_count = 0

        # mouse positions and events
        self.mouse_positions = deque()
        self.mouse_clicks = deque()
        self.mouse_scrolls = deque()
        self._last_mouse_pos = None
        self._last_mouse_ts = None
        self.mouse_accel_samples = deque(maxlen=1000)

        # system & network samples history
        self.samples = []
        self.location = None

        # locks
        self.lock = threading.Lock()

        # load profile if exists
        self._load_profile()

        #application 
        self.last_app = None
        self.last_app_ts = time.time()
        self.app_durations = defaultdict(float)
        self.app_switches = 0

    def _load_profile(self):
        if os.path.exists(PROFILE_FILE):
            try:
                with open(PROFILE_FILE, "r") as f:
                    data = json.load(f)
                self.location = data.get("location")
            except Exception:
                self.location = None

    def _save_profile(self):
        data = {"location": self.location, "last_saved": datetime.utcnow().isoformat() + "Z"}
        try:
            with open(PROFILE_FILE, "w") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    # --- keyboard handlers ---
    def record_key_press(self, key, ts=None):
        if ts is None:
            ts = time.time()
        with self.lock:
            self.key_events.append((ts, str(key), "down"))
            # if previous key exists, compute flight time
            if len(self.key_events) >= 2:
                prev_ts = self.key_events[-2][0]
                ft = ts - prev_ts
                self.flight_times.append(ft)
            # store press time for hold calculation
            self._press_times[str(key)] = ts
            # quick backspace check
            if str(key).lower().find("backspace") != -1:
                self.backspace_count += 1

    def record_key_release(self, key, ts=None):
        if ts is None:
            ts = time.time()
        with self.lock:
            self.key_events.append((ts, str(key), "up"))
            # compute hold time if press recorded
            k = str(key)
            press_ts = self._press_times.pop(k, None)
            if press_ts is not None:
                hold = ts - press_ts
                self.hold_times.append(hold)

    # --- mouse handlers ---
    def record_mouse_move(self, x, y, ts=None):
        if ts is None:
            ts = time.time()
        with self.lock:
            self.mouse_positions.append((ts, x, y))
            # trim history to last 10 minutes
            while self.mouse_positions and (ts - self.mouse_positions[0][0]) > 600:
                self.mouse_positions.popleft()
            # compute speed/accel sample if last exists
            if self._last_mouse_pos is not None and self._last_mouse_ts is not None:
                dt = ts - self._last_mouse_ts
                if dt > 0:
                    dist = math.hypot(x - self._last_mouse_pos[0], y - self._last_mouse_pos[1])
                    speed = dist / dt
                    # compute accel relative to prior speed if available
                    if hasattr(self, "_last_speed"):
                        accel = (speed - self._last_speed) / dt if dt>0 else 0.0
                        self.mouse_accel_samples.append(accel)
                    self._last_speed = speed
            self._last_mouse_pos = (x, y)
            self._last_mouse_ts = ts

    def record_mouse_click(self, ts=None):
        if ts is None:
            ts = time.time()
        with self.lock:
            self.mouse_clicks.append(ts)

    def record_mouse_scroll(self, dx, dy, ts=None):
        if ts is None:
            ts = time.time()
        with self.lock:
            self.mouse_scrolls.append((ts, dx, dy))

    # --- system metrics ---
    def get_brightness(self):
        if sbc is None:
            return None
        try:
            vals = sbc.get_brightness()
            if isinstance(vals, (list, tuple)):
                return float(vals[0]) if len(vals)>0 else None
            else:
                return float(vals)
        except Exception:
            return None

    def get_active_window(self):
        # best-effort cross-platform via pygetwindow
        try:
            if gw is None:
                return None
            w = gw.getActiveWindow()
            if w is None:
                return None
            title = w.title or w.__repr__()
            now = time.time()
            if self.last_app is None:
                self.last_app = title
                self.last_app_ts = now
            else:
                if title != self.last_app:
                    dt = now - self.last_app_ts
                    self.app_durations[self.last_app] += dt
                    self.app_switches += 1
                    self.last_app = title
                    self.last_app_ts = now
            return title[:200]
        except Exception:
            return None

    def get_system_metrics(self):
        if psutil is None:
            return {"cpu": None, "mem": None, "disk_io": None, "net_up": None, "net_down": None, "battery": None, "conns": None}
        try:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent
            # net IO since boot, will compute deltas in aggregator
            net = psutil.net_io_counters()
            disk = psutil.disk_io_counters()
            # battery
            try:
                bat = psutil.sensors_battery()
                battery = bat.percent if bat is not None else None
            except Exception:
                battery = None
            # open connections count
            try:
                conns = len(psutil.net_connections())
            except Exception:
                conns = None
            return {"cpu": cpu, "mem": mem, "disk_read": disk.read_bytes if disk else None, "disk_write": disk.write_bytes if disk else None, "net_bytes_sent": net.bytes_sent, "net_bytes_recv": net.bytes_recv, "battery": battery, "conns": conns}
        except Exception:
            return {"cpu": None, "mem": None, "disk_io": None, "net_up": None, "net_down": None, "battery": None, "conns": None}

    def lookup_location(self):
        if requests is None:
            self.location = "requests_missing"
            return
        services = ["https://ipinfo.io/json", "https://ipapi.co/json/"]
        for url in services:
            try:
                r = requests.get(url, timeout=4)
                if r.status_code == 200:
                    j = r.json()
                    city = j.get("city") or j.get("region") or j.get("country_name") or j.get("country") or ""
                    ip = j.get("ip") or j.get("query") or ""
                    self.location = f"{city}, IP:{ip}"
                    self._save_profile()
                    return
            except Exception:
                continue
        self.location = "unavailable"
        self._save_profile()

    def get_wifi_ssid(self):
        if pywifi is None:
            return None
        try:
            wifi = PyWiFi()
            iface = wifi.interfaces()[0]
            profile = iface.network_profiles()
            # returning interface name as fallback
            return iface.name() if iface else None
        except Exception:
            return None

    # --- feature aggregation ---
    def aggregate_features(self):
        now = time.time()
        cutoff = now - WINDOW_SECONDS
        # keys: compute WPM (characters in window -> words per minute)
        with self.lock:
            key_count = sum(1 for (ts, k, ev) in self.key_events if ts >= cutoff)
            # key holds & flight times statistics
            hold_samples = [h for h in list(self.hold_times) if h is not None]
            flight_samples = [f for f in list(self.flight_times) if f is not None]
            avg_hold = float(np.mean(hold_samples)) if (np is not None and len(hold_samples)>0) else (sum(hold_samples)/len(hold_samples) if len(hold_samples)>0 else 0.0)
            avg_flight = float(np.mean(flight_samples)) if (np is not None and len(flight_samples)>0) else (sum(flight_samples)/len(flight_samples) if len(flight_samples)>0 else 0.0)
            backspaces = self.backspace_count
            # mouse stats
            pts = [p for p in self.mouse_positions if p[0] >= cutoff]
            clicks = sum(1 for t in self.mouse_clicks if t >= cutoff)
            scrolls = sum(1 for (t,dx,dy) in self.mouse_scrolls if t >= cutoff)
            if len(pts) < 2:
                avg_speed = 0.0
                total_dist = 0.0
            else:
                total_dist = 0.0
                total_time = 0.0
                prev_t, prev_x, prev_y = pts[0]
                for (t,x,y) in pts[1:]:
                    dt = t - prev_t
                    if dt <= 0:
                        prev_t, prev_x, prev_y = t,x,y
                        continue
                    dist = math.hypot(x - prev_x, y - prev_y)
                    total_dist += dist
                    total_time += dt
                    prev_t, prev_x, prev_y = t,x,y
                avg_speed = (total_dist / total_time) if total_time>0 else 0.0
            # accel stats
            accel_samples = list(self.mouse_accel_samples)
            avg_accel = float(np.mean(accel_samples)) if (np is not None and len(accel_samples)>0) else (sum(accel_samples)/len(accel_samples) if len(accel_samples)>0 else 0.0)
            # system metrics
            sysm = self.get_system_metrics()
            bright = self.get_brightness()
            active_window = self.get_active_window()
                        # app usage features
            total_app_time = sum(self.app_durations.values()) + 1e-6
            unique_apps = len(self.app_durations)
            top_app_ratio = max(self.app_durations.values()) / total_app_time if self.app_durations else 0.0
            app_switches = self.app_switches

            wifi = self.get_wifi_ssid()
            # time features
            dt = datetime.now()
            hour = dt.hour + dt.minute/60.0
            is_night = 1 if (dt.hour < 6 or dt.hour > 22) else 0
            # location encoding
            loc_enc = 0.0
            if self.location and isinstance(self.location, str):
                try:
                    loc_enc = float(abs(hash(self.location)) % 1000)
                except Exception:
                    loc_enc = 0.0
            # compute WPM
            chars_per_min = (key_count / WINDOW_SECONDS) * 60.0 if WINDOW_SECONDS>0 else 0.0
            wpm = chars_per_min / 5.0
            # package features
            vec = {
                "wpm": round(wpm,2),
                "key_hold_mean": round(avg_hold,4),
                "key_flight_mean": round(avg_flight,4),
                "backspace_count": int(backspaces),
                "mouse_avg_speed": round(avg_speed,2),
                "mouse_distance": round(total_dist,2),
                "mouse_clicks": int(clicks),
                "mouse_scrolls": int(scrolls),
                "mouse_accel_mean": round(avg_accel,4),
                "brightness": float(bright) if bright is not None else -1.0,
                "cpu": float(sysm["cpu"]) if sysm.get("cpu") is not None else -1.0,
                "mem": float(sysm["mem"]) if sysm.get("mem") is not None else -1.0,
                "net_bytes_sent": float(sysm["net_bytes_sent"]) if sysm.get("net_bytes_sent") is not None else -1.0,
                "net_bytes_recv": float(sysm["net_bytes_recv"]) if sysm.get("net_bytes_recv") is not None else -1.0,
                "conns": float(sysm["conns"]) if sysm.get("conns") is not None else -1.0,
                "battery": float(sysm["battery"]) if sysm.get("battery") is not None else -1.0,
                "hour_of_day": hour,
                "is_night": is_night,
                "loc_hash": loc_enc,
                "active_window_hash": float(abs(hash(active_window))%10000) if active_window else 0.0,
                "wifi": float(abs(hash(wifi))%10000) if wifi else 0.0,
                "unique_apps": unique_apps,
                "top_app_ratio": round(top_app_ratio, 3),
                "app_switches": app_switches,

            }
            # reset some counters periodically (e.g., backspace)
            self.backspace_count = 0
            self.app_durations.clear()
            self.app_switches = 0

        return vec

collector = Collector()

# --- Input listeners ---
kbd_listener = None
mouse_listener = None

def on_key_press(key):
    collector.record_key_press(key)

def on_key_release(key):
    collector.record_key_release(key)

def on_mouse_move(x, y):
    collector.record_mouse_move(x, y)

def on_mouse_click(x, y, button, pressed):
    if pressed:
        collector.record_mouse_click(x, y, button, pressed) if False else collector.record_mouse_click()

def on_mouse_scroll(x, y, dx, dy):
    collector.record_mouse_scroll(dx, dy)

def start_listeners():
    global kbd_listener, mouse_listener
    if keyboard is None or mouse is None:
        print("pynput not available; install pynput to capture keyboard/mouse.")
        return
    try:
        kbd_listener = keyboard.Listener(on_press=on_key_press, on_release=on_key_release)
        mouse_listener = mouse.Listener(on_move=on_mouse_move, on_click=on_mouse_click, on_scroll=on_mouse_scroll)
        kbd_listener.daemon = True
        mouse_listener.daemon = True
        kbd_listener.start()
        mouse_listener.start()
    except Exception as e:
        print("Failed to start listeners:", e)

def stop_listeners():
    try:
        if kbd_listener and kbd_listener.running:
            kbd_listener.stop()
        if mouse_listener and mouse_listener.running:
            mouse_listener.stop()
    except Exception:
        pass

# --- Model training & detection ---
model = None
scaler = None
training_data = []

def train_model(X_df):
    global model, scaler
    if IsolationForest is None or StandardScaler is None:
        print("scikit-learn is required for training the model.")
        return False
    X = X_df.fillna(-1.0).values
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    model = IsolationForest(n_estimators=200, contamination=0.02, random_state=42)
    model.fit(Xs)
    # save
    try:
        joblib.dump(model, MODEL_FILE)
        joblib.dump(scaler, SCALER_FILE)
    except Exception:
        pass
    print("Model trained. Samples:", X.shape[0])
    return True

def load_model_if_exists():
    global model, scaler
    if os.path.exists(MODEL_FILE) and os.path.exists(SCALER_FILE):
        try:
            model = joblib.load(MODEL_FILE)
            scaler = joblib.load(SCALER_FILE)
            print("Loaded existing model & scaler.")
            return True
        except Exception:
            return False
    return False

def anomaly_score_for_vector(vec):
    global model, scaler
    if model is None or scaler is None:
        return None, None
    df = pd.DataFrame([vec])
    X = df.fillna(-1.0).values
    Xs = scaler.transform(X)
    score = model.decision_function(Xs)[0]
    pred = model.predict(Xs)[0]
    is_anom = True if pred == -1 else False
    return float(score), is_anom

# --- Logging ---
def ensure_log_header():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            header = ["timestamp"] + list(aggregate_feature_keys())
            header += ["score", "is_anomaly"]
            writer.writerow(header)

def aggregate_feature_keys():
    # must match the order used when writing vector
    sample = collector.aggregate_features()
    return list(sample.keys())

def log_row(vec, score, is_anom):
    exists = os.path.exists(LOG_FILE)
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        if not exists:
            header = ["timestamp"] + list(vec.keys()) + ["score", "is_anomaly"]
            writer.writerow(header)
        row = [datetime.utcnow().isoformat() + "Z"] + [vec[k] for k in vec.keys()] + [score if score is not None else "", int(is_anom) if is_anom is not None else ""]
        writer.writerow(row)

# --- Background aggregator ---
stop_event = threading.Event()
trained_flag = False
training_data = []

def aggregator_loop(ui_callback=None):
    global training_data, trained_flag
    start_time = time.time()
    baseline_end = start_time + BASELINE_SECONDS
    loaded = load_model_if_exists()
    if loaded:
        trained_flag = True
    while not stop_event.is_set():
        vec = collector.aggregate_features()
        training_data.append(vec)
        # training logic
        now = time.time()
        if not trained_flag and now >= baseline_end and len(training_data) >= max(5, BASELINE_SECONDS // WINDOW_SECONDS):
            # create DataFrame and train
            try:
                df = pd.DataFrame(training_data)
                ok = train_model(df)
                if ok:
                    trained_flag = True
                    if ui_callback:
                        ui_callback(trained=True, vec=vec, score=None, is_anom=False)
            except Exception as e:
                print("Training failed:", e)
        elif trained_flag:
            score, is_anom = anomaly_score_for_vector(vec)
            # callback + logging
            if ui_callback:
                ui_callback(trained=True, vec=vec, score=score, is_anom=is_anom)
            log_row(vec, score, is_anom)
        else:
            if ui_callback:
                ui_callback(trained=False, vec=vec, score=None, is_anom=False)
        # sleep until next window (granular)
        for _ in range(int(WINDOW_SECONDS)):
            if stop_event.is_set():
                break
            time.sleep(1)

# --- UI ---
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IntrusionAI - Full Featured Detector")
        self.geometry("760x520")
        self.resizable(True, True)
        self.style = ttk.Style(self)
        try:
            self.style.theme_use('clam')
        except Exception:
            pass

        # variables
        self.trained_var = tk.StringVar(value="Model: Not trained")
        self.status_var = tk.StringVar(value="Stopped")
        self.score_var = tk.StringVar(value="Score: -")
        self.anom_var = tk.StringVar(value="Anomaly: -")
        # feature variables (subset for UI)
        self.wpm_var = tk.StringVar(value="WPM: -")
        self.key_hold_var = tk.StringVar(value="Hold: -")
        self.key_flight_var = tk.StringVar(value="Flight: -")
        self.mouse_var = tk.StringVar(value="Mouse: -")
        self.cpu_var = tk.StringVar(value="CPU: -")
        self.mem_var = tk.StringVar(value="Mem: -")
        self.net_var = tk.StringVar(value="Net: -")
        self.brightness_var = tk.StringVar(value="Brightness: -")
        self.loc_var = tk.StringVar(value="Location: -")
        # layout panes
        top_frame = ttk.Frame(self)
        top_frame.pack(fill="x", padx=8, pady=6)
        ttk.Label(top_frame, textvariable=self.trained_var, font=("Segoe UI", 11, "bold")).pack(side="left", padx=(4,8))
        ttk.Label(top_frame, textvariable=self.status_var).pack(side="left", padx=(4,8))
        btn_frame = ttk.Frame(top_frame)
        btn_frame.pack(side="right")
        ttk.Button(btn_frame, text="Start", command=self.start).pack(side="left", padx=4)
        ttk.Button(btn_frame, text="Stop", command=self.stop).pack(side="left", padx=4)
        ttk.Button(btn_frame, text="Train Now", command=self.force_train).pack(side="left", padx=4)
        ttk.Button(btn_frame, text="Export Logs", command=self.export_logs).pack(side="left", padx=4)

        # main feature grid
        main = ttk.Frame(self)
        main.pack(fill="both", expand=True, padx=8, pady=6)

        left = ttk.Frame(main)
        left.pack(side="left", fill="both", expand=True)

        right = ttk.Frame(main, width=320)
        right.pack(side="right", fill="y")

        # left: feature list
        f = ttk.Frame(left)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="Live Features", font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(4,4))
        ttk.Label(f, textvariable=self.wpm_var).pack(anchor="w", padx=6)
        ttk.Label(f, textvariable=self.key_hold_var).pack(anchor="w", padx=6)
        ttk.Label(f, textvariable=self.key_flight_var).pack(anchor="w", padx=6)
        ttk.Label(f, textvariable=self.mouse_var).pack(anchor="w", padx=6)
        ttk.Label(f, textvariable=self.brightness_var).pack(anchor="w", padx=6)
        ttk.Label(f, textvariable=self.cpu_var).pack(anchor="w", padx=6)
        ttk.Label(f, textvariable=self.mem_var).pack(anchor="w", padx=6)
        ttk.Label(f, textvariable=self.net_var).pack(anchor="w", padx=6)
        ttk.Label(f, textvariable=self.loc_var).pack(anchor="w", padx=6)

        # right: model & anomaly panel
        panel = ttk.Frame(right)
        panel.pack(fill="y", padx=6, pady=6)
        ttk.Label(panel, text="Model & Anomaly", font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(4,4))
        ttk.Label(panel, textvariable=self.score_var, font=("Segoe UI", 11)).pack(anchor="w", pady=(4,2))
        ttk.Label(panel, textvariable=self.anom_var, font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(2,10))

        # verbose log box
        self.log_box = tk.Text(right, height=12, width=40, state="disabled")
        self.log_box.pack(fill="both", expand=True, padx=6, pady=6)

        self.agg_thread = None

    def ui_callback(self, trained, vec, score, is_anom):
        # update UI - executed from aggregator thread; use after to schedule on main thread
        def _update():
            self.trained_var.set("Model: Trained" if trained else "Model: Not trained")
            self.status_var.set("Running" if not stop_event.is_set() else "Stopped")
            # feature updates
            self.wpm_var.set(f"WPM: {vec.get('wpm','-')}")
            self.key_hold_var.set(f"Hold: {vec.get('key_hold_mean','-')}, Flight: {vec.get('key_flight_mean','-')}")
            self.key_flight_var.set(f"Backspaces: {vec.get('backspace_count','-')}")
            self.mouse_var.set(f"Speed: {vec.get('mouse_avg_speed','-')} px/s, Clicks: {vec.get('mouse_clicks','-')}")
            self.brightness_var.set(f"Brightness: {vec.get('brightness','-')}")
            self.cpu_var.set(f"CPU: {vec.get('cpu','-')}%")
            self.mem_var.set(f"Mem: {vec.get('mem','-')}%")
            self.net_var.set(f"Up: {vec.get('net_bytes_sent','-')}, Down: {vec.get('net_bytes_recv','-')}")
            self.loc_var.set(f"LocHash: {vec.get('loc_hash','-')}")
            if score is not None:
                self.score_var.set(f"Score: {score:.4f}")
                self.anom_var.set("Anomaly: YES" if is_anom else "Anomaly: NO")
                # log short message
                self.append_log(f"{datetime.utcnow().isoformat()}Z | Score: {score:.4f} | Anomaly: {is_anom}")
            else:
                self.score_var.set("Score: -")
                self.anom_var.set("Anomaly: -")
                self.append_log(f"{datetime.utcnow().isoformat()}Z | Collecting baseline...")

        self.after(0, _update)

    def append_log(self, text):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", text + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def start(self):
        stop_event.clear()
        start_listeners()
        threading.Thread(target=collector.lookup_location, daemon=True).start()
        if self.agg_thread is None or not self.agg_thread.is_alive():
            self.agg_thread = threading.Thread(target=aggregator_loop, args=(self.ui_callback,), daemon=True)
            self.agg_thread.start()
        self.append_log("Started data collection.")

    def stop(self):
        stop_event.set()
        stop_listeners()
        collector._save_profile()
        self.append_log("Stopped collection. Profile saved.")

    def force_train(self):
        global training_data, trained_flag
        if len(training_data) < 5:
            messagebox.showwarning("Not enough data", "Collect more samples before training (at least 5 windows).")
            return
        try:
            df = pd.DataFrame(training_data)
            ok = train_model(df)
            if ok:
                trained_flag = True
                messagebox.showinfo("Trained", "Model trained on collected samples.")
        except Exception as e:
            messagebox.showerror("Error", f"Training failed: {e}")

    def export_logs(self):
        if not os.path.exists(LOG_FILE):
            messagebox.showinfo("No logs", "No logs present yet.")
            return
        dest = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if dest:
            try:
                with open(LOG_FILE, "rb") as fr, open(dest, "wb") as fw:
                    fw.write(fr.read())
                messagebox.showinfo("Exported", f"Logs exported to {dest}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export logs: {e}")

def main():
    # ensure log header exists
    ensure_log_header()
    load_model_if_exists()
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
