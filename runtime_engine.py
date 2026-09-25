"""
M3 Runtime Engine — Full Featured
- Async UDP listener for MAVLink
- EKF physics-based GPS spoofing detection
- Rate limiter for DoS detection
- Sequence/sysid validator for injection detection
- Isolation Forest for unknown anomaly detection
- Rule-based known-attack detection
- Failsafe dispatch
- SHA-256 tamper-evident logging
- JSON alerts to M5
- Unknown anomaly collection for retraining
"""

import os
import sys
import time
import json
import socket
import pickle
import signal
import joblib
import numpy as np
import pandas as pd
from collections import deque
from pymavlink import mavutil

from rules import apply_rules
from ekf_engine import DroneEKF
from cyber_engine import RateLimiter, SequenceValidator
from mitigation import dispatch_failsafe
from forensics import IncidentLedger

# =====================================================
# CONFIGURATION
# =====================================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

MAVLINK_URL = 'udp:0.0.0.0:14556'    # Incoming MAVLink from M2's router
ALERT_TO_M5_HOST = '10.22.39.217'          # M5's dashboard IP
ALERT_TO_M5_PORT = 9000                 # M5's JSON alert port
ATTACK_NOTIFY_PORT = 9001               # M4 sends attack start signals here
LATENCY_LOG_PATH = os.path.join(PROJECT_ROOT, 'logs', 'latency_log.json')
UNKNOWN_ANOMALIES_PATH = os.path.join(PROJECT_ROOT, 'data', 'unknown_anomalies.pkl')

WINDOW_SEC = 1.0
STEP_SEC = 0.5
ALERT_COOLDOWN_SEC = 2.0
EXPECTED_MSG_INTERVAL_MS = 250

# =====================================================
# LOAD MODEL
# =====================================================
print("[M3] " + "=" * 50)
print("[M3] Starting Drone IDS Runtime Engine")
print("[M3] " + "=" * 50)

try:
    model = joblib.load(os.path.join(PROJECT_ROOT, 'models', 'ids_model_full.pkl'))
    scaler = joblib.load(os.path.join(PROJECT_ROOT, 'models', 'scaler_full.pkl'))
    feature_names = joblib.load(os.path.join(PROJECT_ROOT, 'models', 'feature_names.pkl'))
    print(f"[M3] Model loaded. Expects {len(feature_names)} features.")
except Exception as e:
    print(f"[M3] ❌ Failed to load model: {e}")
    print(f"[M3] Run train_model.py first.")
    sys.exit(1)

# =====================================================
# INITIALIZE ENGINES
# =====================================================
print("[M3] Initializing engines...")
ekf = DroneEKF(dt=0.1)
rate_limiter = RateLimiter(max_hz=150, window_sec=1.0)
seq_validator = SequenceValidator(expected_sysid=1)
ledger = IncidentLedger()
print("[M3] EKF, RateLimiter, SequenceValidator, Ledger ready")

# =====================================================
# STATE
# =====================================================
alert_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
notify_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
notify_sock.bind(('127.0.0.1', ATTACK_NOTIFY_PORT))
notify_sock.setblocking(False)

last_alert_time = 0
buffer = deque(maxlen=500)
unknown_anomalies = []
attack_markers = {}          # {attack_type: timestamp}
latency_records = []         # [(attack_type, latency_ms, detected_by)]
running = True

# =====================================================
# SIGNAL HANDLER
# =====================================================
def handle_shutdown(signum, frame):
    global running
    print("\n[M3] Shutdown signal received")
    running = False

signal.signal(signal.SIGINT, handle_shutdown)
signal.signal(signal.SIGTERM, handle_shutdown)

# =====================================================
# HELPERS
# =====================================================
def save_unknown_anomalies():
    """Persist unknown anomalies to disk for later retraining."""
    if not unknown_anomalies:
        return
    try:
        with open(UNKNOWN_ANOMALIES_PATH, 'wb') as f:
            pickle.dump(unknown_anomalies, f)
        print(f"[M3] Saved {len(unknown_anomalies)} unknown anomalies to {UNKNOWN_ANOMALIES_PATH}")
    except Exception as e:
        print(f"[M3] Failed to save anomalies: {e}")


def save_latency_records():
    """Save latency measurements for proposal."""
    if not latency_records:
        return
    try:
        os.makedirs(os.path.dirname(LATENCY_LOG_PATH), exist_ok=True)
        with open(LATENCY_LOG_PATH, 'w') as f:
            json.dump(latency_records, f, indent=2)
        print(f"[M3] Saved {len(latency_records)} latency records")
    except Exception as e:
        print(f"[M3] Failed to save latency: {e}")


def check_attack_notifications():
    """Check for M4's attack start signals (non-blocking)."""
    try:
        while True:
            data, _ = notify_sock.recvfrom(4096)
            try:
                payload = json.loads(data.decode())
                attack_type = payload.get('type', 'UNKNOWN')
                attack_markers[attack_type] = time.time()
                print(f"[M3] 🔔 M4 notified attack: {attack_type}")
            except Exception:
                pass
    except BlockingIOError:
        pass
    except Exception:
        pass


def compute_latency(attack_type):
    """Compute detection latency if M4 notified us."""
    if attack_type in attack_markers:
        start_ts = attack_markers.pop(attack_type)
        latency_ms = (time.time() - start_ts) * 1000
        return latency_ms
    return None


def emit_alert(master, attack_type, confidence, source, features=None):
    """Send alert to M5, log to ledger, dispatch failsafe, record latency."""
    global last_alert_time

    if time.time() - last_alert_time < ALERT_COOLDOWN_SEC:
        return

    last_alert_time = time.time()

    # Tamper-evident logging
    ledger.log(attack_type, confidence, source, features)

    # Compute latency if M4 notified us
    latency_ms = compute_latency(attack_type)
    if latency_ms is not None:
        latency_records.append({
            'attack_type': attack_type,
            'detected_by': source,
            'latency_ms': round(latency_ms, 2),
            'timestamp': time.time()
        })
        print(f"[M3] ⏱️  Latency: {latency_ms:.1f} ms")

    # Save unknown anomalies for retraining
    if attack_type == 'UNKNOWN_ANOMALY' and features:
        unknown_anomalies.append({
            'timestamp': time.time(),
            'confidence': confidence,
            'features': features
        })
        if len(unknown_anomalies) % 5 == 0:
            save_unknown_anomalies()

    # Send JSON to M5
    alert = {
        'timestamp': time.time(),
        'iso_time': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'attack_type': attack_type,
        'confidence': round(confidence, 3),
        'source': source,
        'latency_ms': latency_ms
    }
    try:
        alert_sock.sendto(json.dumps(alert).encode(), (ALERT_TO_M5_HOST, ALERT_TO_M5_PORT))
    except Exception as e:
        print(f"[M3] Alert send failed: {e}")

    print(f"[M3] 🚨 {attack_type} (conf={confidence:.2f}, src={source})")

    # Failsafe
    try:
        dispatch_failsafe(master, attack_type, confidence)
    except Exception as e:
        print(f"[M3] Failsafe error: {e}")


def extract_from_window(messages):
    """Extract 20+ features from a window of MAVLink messages."""
    if len(messages) < 5:
        return None

    lats, lons, alts, vxs, vys, vzs, times = [], [], [], [], [], [], []

    for msg in messages:
        t = msg.get_type()
        if t == 'GLOBAL_POSITION_INT':
            lats.append(msg.lat / 1e7)
            lons.append(msg.lon / 1e7)
            alts.append(msg.alt / 1000.0)
            vxs.append(msg.vx / 100.0)
            vys.append(msg.vy / 100.0)
            vzs.append(msg.vz / 100.0)
        times.append(time.time() * 1000)

    if len(lats) < 3:
        return None

    lat = pd.Series(lats)
    lon = pd.Series(lons)
    alt = pd.Series(alts)
    vx = pd.Series(vxs)
    vy = pd.Series(vys)
    vz = pd.Series(vzs)
    t = pd.Series(times)

    feat = {}

    # Navigation
    lat_delta = abs(lat.iloc[-1] - lat.iloc[0])
    lon_delta = abs(lon.iloc[-1] - lon.iloc[0])
    feat['gps_jump'] = np.sqrt(lat_delta ** 2 + lon_delta ** 2)
    feat['gps_cumulative_drift'] = lat.diff().abs().sum() + lon.diff().abs().sum()
    feat['altitude_drift'] = abs(alt.iloc[-1] - alt.iloc[0])
    feat['altitude_variance'] = alt.var()
    feat['latitude_variance'] = lat.var()
    feat['longitude_variance'] = lon.var()
    dt = t.iloc[-1] - t.iloc[0] + 1e-6
    feat['gps_change_rate'] = feat['gps_jump'] / dt

    # Control
    speed_3d = np.sqrt(vx ** 2 + vy ** 2 + vz ** 2)
    feat['velocity_magnitude'] = speed_3d.mean()
    feat['velocity_variance'] = vz.var()
    feat['horizontal_speed'] = np.sqrt(vx ** 2 + vy ** 2).mean()
    feat['vertical_speed_mean'] = vz.mean()
    feat['vz_jump'] = abs(vz.iloc[-1] - vz.iloc[0])
    feat['max_velocity_jump'] = vz.diff().abs().max()

    speed_horiz = np.sqrt(vx ** 2 + vy ** 2)
    if speed_horiz.mean() > 0.5:
    	heading = np.arctan2(vy, vx + 1e-6)
    	feat['heading_change'] = abs(heading.iloc[-1] - heading.iloc[0])
    else:
    	feat['heading_change'] = 0.0

    # Communication
    time_diffs = t.diff().dropna()
    feat['timestamp_variance'] = time_diffs.var() if len(time_diffs) > 1 else 0
    feat['timestamp_mean_interval'] = time_diffs.mean() if len(time_diffs) > 0 else 0
    feat['timestamp_max_gap'] = time_diffs.max() if len(time_diffs) > 0 else 0
    if len(time_diffs) > 0:
        feat['packet_loss_rate'] = max(0, (time_diffs.max() - EXPECTED_MSG_INTERVAL_MS) / EXPECTED_MSG_INTERVAL_MS)
    else:
        feat['packet_loss_rate'] = 0

    # Cross-consistency
    feat['gps_velocity_mismatch'] = feat['gps_jump'] / (feat['velocity_magnitude'] + 1e-6)
    feat['position_stability'] = feat['gps_jump'] / (feat['velocity_magnitude'] + 1e-6)
    feat['altitude_velocity_mismatch'] = feat['altitude_drift'] / (abs(feat['vertical_speed_mean']) + 1e-6)

    return feat


# =====================================================
# MAIN LOOP
# =====================================================
def main():
    global running

    print(f"[M3] Connecting to MAVLink at {MAVLINK_URL}...")
    try:
        master = mavutil.mavlink_connection(MAVLINK_URL)
        master.wait_heartbeat(timeout=30)
        print(f"[M3] ✅ Connected (sysid={master.target_system}, compid={master.target_component})")
    except Exception as e:
        print(f"[M3] ❌ Connection failed: {e}")
        sys.exit(1)

    print(f"[M3] Alerts → M5 at {ALERT_TO_M5_HOST}:{ALERT_TO_M5_PORT}")
    print(f"[M3] Listening for M4 attack signals on {ATTACK_NOTIFY_PORT}")
    print(f"[M3] Press Ctrl+C to stop\n")

    last_extract = time.time()
    msg_count = 0

    while running:
        try:
            # Check M4 notifications (non-blocking)
            check_attack_notifications()

            # Receive MAVLink
            msg = master.recv_match(blocking=True, timeout=0.1)
            if msg is None:
                continue

            msg_count += 1
            msg_type = msg.get_type()

            # ---- Rate limiter ----
            exceeded, rate = rate_limiter.check()
            if exceeded:
                emit_alert(master, 'DOS_FLOOD_ALERT', 0.95, 'rate_limiter', {'rate_hz': rate})

            # ---- Sequence validator ----
            sysid = msg.get_srcSystem() if hasattr(msg, 'get_srcSystem') else 1
            compid = msg.get_srcComponent() if hasattr(msg, 'get_srcComponent') else 1
            seq = getattr(msg, 'seq', 0)
            seq_alerts = seq_validator.check(sysid, compid, seq)
            for a in seq_alerts:
                emit_alert(master, a, 0.90, 'seq_validator')

            # ---- EKF ----
            if msg_type == 'RAW_IMU':
                ekf.predict()
            elif msg_type == 'GLOBAL_POSITION_INT':
                gps = (msg.lat / 1e7, msg.lon / 1e7, msg.alt / 1000.0)
                nis = ekf.update_gps(gps)
                if ekf.is_spoofed(nis):
                    emit_alert(master, 'GPS_SPOOFING_ALERT', 0.95, 'ekf', {'nis': float(nis)})

            # ---- Buffer message ----
            buffer.append((time.time(), msg))
            while buffer and time.time() - buffer[0][0] > WINDOW_SEC * 2:
                buffer.popleft()

            # ---- Feature extraction + ML every STEP_SEC ----
            if time.time() - last_extract >= STEP_SEC and len(buffer) > 10:
                messages = [m for _, m in buffer]
                features = extract_from_window(messages)

                if features:
                    feat_vector = [features.get(f, 0) for f in feature_names]
                    X = pd.DataFrame([feat_vector], columns=feature_names)
                    X_scaled = scaler.transform(X)

                    ml_pred = model.predict(X_scaled)[0]
                    ml_score = model.decision_function(X_scaled)[0]

                    rule_alerts = apply_rules(features)

                    if rule_alerts:
                        # Rule wins — known attack with high confidence
                        best = max(rule_alerts, key=lambda x: x[1])
                        emit_alert(master, best[0], best[1], 'rule', features)
                    elif ml_pred == -1:
                        # ML flags unknown anomaly
                        confidence = min(1.0, max(0.0, (0.1 - ml_score) / 0.2))
                        emit_alert(master, 'UNKNOWN_ANOMALY', confidence, 'ml', features)
                    else:
                        # Normal
                        if msg_count % 20 == 0:
                            print(f"[M3] ✅ Normal (score={ml_score:.3f}, msgs={msg_count})")

                last_extract = time.time()

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[M3] Loop error: {e}")
            time.sleep(0.1)

    # ---- Shutdown ----
    print("\n[M3] Shutting down...")
    save_unknown_anomalies()
    save_latency_records()

    ok, bad = ledger.verify()
    print(f"[M3] Ledger integrity: {'✅ VALID' if ok else '❌ TAMPERED at ' + str(bad)}")
    print(f"[M3] Total messages processed: {msg_count}")
    print(f"[M3] Total alerts: {len(ledger.entries)}")

    if latency_records:
        avg_latency = sum(r['latency_ms'] for r in latency_records) / len(latency_records)
        print(f"[M3] Average detection latency: {avg_latency:.1f} ms")

    print("[M3] Stopped.")


if __name__ == '__main__':
    main()
