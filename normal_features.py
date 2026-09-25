import pandas as pd
import numpy as np

def extract_features(csv_path, output_path='data/extract_features.csv'):
    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df)} rows")

    WINDOW = 10
    STEP = 5
    features = []

    # Detect expected interval from data (not hardcoded)
    raw_diffs = df['timestamp_ms'].diff().dropna()
    expected_interval = raw_diffs.median() if len(raw_diffs) > 0 else 250
    print(f"Detected expected interval: {expected_interval} ms")

    for i in range(0, len(df) - WINDOW, STEP):
        window = df.iloc[i:i+WINDOW].copy()
        feat = {}

        lat = window['latitude']
        lon = window['longitude']
        alt = window['altitude_m']
        vx = window['vx']
        vy = window['vy']
        vz = window['vz']
        t = window['timestamp_ms']

        # --- Navigation ---
        lat_delta = abs(lat.iloc[-1] - lat.iloc[0])
        lon_delta = abs(lon.iloc[-1] - lon.iloc[0])
        feat['gps_jump'] = np.sqrt(lat_delta**2 + lon_delta**2)

        feat['gps_cumulative_drift'] = (
            lat.diff().abs().sum() + lon.diff().abs().sum()
        )

        feat['altitude_drift'] = abs(alt.iloc[-1] - alt.iloc[0])
        feat['altitude_variance'] = alt.var()
        feat['latitude_variance'] = lat.var()
        feat['longitude_variance'] = lon.var()

        dt = t.iloc[-1] - t.iloc[0] + 1e-6
        feat['gps_change_rate'] = feat['gps_jump'] / dt

        # --- Control ---
        speed_3d = np.sqrt(vx**2 + vy**2 + vz**2)
        feat['velocity_magnitude'] = speed_3d.mean()
        feat['velocity_variance'] = vz.var()
        feat['horizontal_speed'] = np.sqrt(vx**2 + vy**2).mean()
        feat['vertical_speed_mean'] = vz.mean()
        feat['vz_jump'] = abs(vz.iloc[-1] - vz.iloc[0])
        feat['max_velocity_jump'] = vz.diff().abs().max()

        heading = np.arctan2(vy, vx + 1e-6)
        feat['heading_change'] = abs(heading.iloc[-1] - heading.iloc[0])

        # --- Communication / timing ---
        time_diffs = t.diff().dropna()

        # Variance feature (will be 0 until M2 adds jitter)
        feat['timestamp_variance'] = time_diffs.var() if len(time_diffs) > 1 else 0

        # Mean interval (constant 250 until jitter)
        feat['timestamp_mean_interval'] = time_diffs.mean() if len(time_diffs) > 0 else 0

        # Max gap (constant 250 until jitter)
        feat['timestamp_max_gap'] = time_diffs.max() if len(time_diffs) > 0 else 0

        # Packet loss (constant 0 until jitter)
        if len(time_diffs) > 0:
            feat['packet_loss_rate'] = max(0, (time_diffs.max() - expected_interval) / expected_interval)
        else:
            feat['packet_loss_rate'] = 0

        # --- Cross-consistency ---
        feat['gps_velocity_mismatch'] = feat['gps_jump'] / (feat['velocity_magnitude'] + 1e-6)
        feat['position_stability'] = feat['gps_jump'] / (feat['velocity_magnitude'] + 1e-6)
        feat['altitude_velocity_mismatch'] = feat['altitude_drift'] / (abs(feat['vertical_speed_mean']) + 1e-6)

        features.append(feat)

    feature_df = pd.DataFrame(features)
    feature_df = feature_df.fillna(0).replace([np.inf, -np.inf], 0)

    feature_df.to_csv(output_path, index=False)
    print(f"✅ Extracted {len(feature_df)} windows × {feature_df.shape[1]} features")
    print(f"✅ Saved to {output_path}")

    # Report which features are constant (informational only, no warning)
    constant = [c for c in feature_df.columns if feature_df[c].std() < 1e-9]
    if constant:
        print(f"ℹ️  Constant features (will be auto-dropped during training): {constant}")
    
    print("\n=== Feature Statistics ===")
    print(feature_df.describe().T[['mean', 'std', 'min', 'max']].to_string())
    return feature_df


if __name__ == "__main__":
    extract_features('data/flight_data.csv', 'data/extract_features.csv')
