"""
M3 Cyber Engine
Rate limiter, sequence validator, sysid check.
"""

import time
from collections import deque


class RateLimiter:
    def __init__(self, max_hz=1000, window_sec=1.0):
        self.max_hz = max_hz
        self.window_sec = window_sec
        self.timestamps = deque()

    def check(self, timestamp=None):
        now = timestamp if timestamp else time.time()
        self.timestamps.append(now)
        while self.timestamps and now - self.timestamps[0] > self.window_sec:
            self.timestamps.popleft()
        rate = len(self.timestamps) / self.window_sec
        return rate > self.max_hz, rate


class SequenceValidator:
    def __init__(self, expected_sysid=1):
        self.expected_sysid = expected_sysid
        self.last_seq = {}

    def check(self, sysid, compid, seq):
        alerts = []
        key = (sysid, compid)

        if sysid != self.expected_sysid:
            alerts.append('ROGUE_INJECTION_ALERT')

        if key in self.last_seq:
            expected = (self.last_seq[key] + 1) % 256
            if seq != expected:
                if seq < self.last_seq[key] and self.last_seq[key] - seq < 128:
                    alerts.append('ROGUE_INJECTION_ALERT')
                elif abs(seq - expected) > 5:
                    alerts.append('ROGUE_INJECTION_ALERT')

        self.last_seq[key] = seq
        return alerts
