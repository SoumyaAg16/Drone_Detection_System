"""
M3 Forensics
SHA-256 tamper-evident incident ledger.
"""

import os
import json
import hashlib
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DEFAULT_LEDGER = os.path.join(PROJECT_ROOT, 'logs', 'incident_ledger.json')


class IncidentLedger:
    def __init__(self, path=DEFAULT_LEDGER):
        self.path = path
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.entries = []
        if os.path.exists(self.path):
            try:
                with open(self.path, 'r') as f:
                    self.entries = json.load(f)
            except Exception:
                self.entries = []

    def _last_hash(self):
        return self.entries[-1]['hash'] if self.entries else '0' * 64

    def log(self, attack_type, confidence, source, features=None):
        entry = {
            'timestamp': time.time(),
            'iso_time': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'attack_type': attack_type,
            'confidence': round(confidence, 4),
            'source': source,
            'features': features or {},
            'prev_hash': self._last_hash(),
        }
        payload = json.dumps({k: v for k, v in entry.items() if k != 'hash'}, sort_keys=True).encode()
        entry['hash'] = hashlib.sha256(payload).hexdigest()
        self.entries.append(entry)

        with open(self.path, 'w') as f:
            json.dump(self.entries, f, indent=2)
        return entry['hash']

    def verify(self):
        prev = '0' * 64
        for e in self.entries:
            if e['prev_hash'] != prev:
                return False, e['timestamp']
            payload = json.dumps({k: v for k, v in e.items() if k != 'hash'}, sort_keys=True).encode()
            if hashlib.sha256(payload).hexdigest() != e['hash']:
                return False, e['timestamp']
            prev = e['hash']
        return True, None