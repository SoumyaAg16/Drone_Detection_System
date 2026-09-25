"""
M3 Rule-Based Detection
Loads statistically-derived thresholds from models/thresholds.json.
No hardcoded values — every threshold comes from training data (μ + 5σ).
"""

import os
import json

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
THRESHOLD_PATH = os.path.join(PROJECT_ROOT, 'models', 'thresholds.json')

# Load thresholds once at import
with open(THRESHOLD_PATH, 'r') as f:
    T = json.load(f)


def apply_rules(features):
    """
    Apply thresholds derived from normal flight statistics (mean + 5σ).
    Returns list of (attack_type, confidence) tuples.
    """
    alerts = []

    # --- GPS Spoofing ---
    if features.get('gps_jump', 0) > T['gps_jump']:
        alerts.append(('GPS_SPOOFING', 0.90))
    if features.get('gps_cumulative_drift', 0) > T['gps_cumulative_drift']:
        alerts.append(('GPS_SPOOFING_SLOW', 0.85))
    if features.get('gps_change_rate', 0) > T['gps_change_rate']:
        alerts.append(('GPS_SPOOFING_FAST', 0.85))

    # --- GPS Jamming ---
    if features.get('packet_loss_rate', 0) > T['packet_loss_rate']:
        alerts.append(('GPS_JAMMING', 0.85))
    if features.get('timestamp_max_gap', 0) > T['timestamp_max_gap']:
        alerts.append(('JAMMING_DETECTED', 0.80))
    if features.get('timestamp_variance', 0) > T['timestamp_variance']:
        alerts.append(('JAMMING_DETECTED', 0.75))

    # --- Control Hijack ---
    if features.get('heading_change', 0) > T['heading_change']:
        alerts.append(('CONTROL_HIJACK', 0.85))
    if features.get('vz_jump', 0) > T['vz_jump']:
        alerts.append(('CONTROL_HIJACK', 0.75))
    if features.get('max_velocity_jump', 0) > T['max_velocity_jump']:
        alerts.append(('SUDDEN_CONTROL', 0.75))

    # --- Altitude Spoofing ---
    if features.get('altitude_drift', 0) > T['altitude_drift']:
        alerts.append(('ALTITUDE_SPOOFING', 0.80))
    if features.get('altitude_velocity_mismatch', 0) > T['altitude_velocity_mismatch']:
        alerts.append(('ALTITUDE_SPOOFING', 0.75))

    return alerts