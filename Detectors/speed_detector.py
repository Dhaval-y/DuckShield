import time
from collections import deque


class SpeedDetector:

    WARNING_THRESHOLD = 20
    CRITICAL_THRESHOLD = 50

    def __init__(self):

        # Store timestamps of recent keystrokes
        self.timestamps = deque()

    def process_key(self):

        current_time = time.time()

        # Add current keystroke timestamp
        self.timestamps.append(current_time)

        # Remove timestamps older than 1 second
        while (
            self.timestamps and
            current_time - self.timestamps[0] > 1
        ):
            self.timestamps.popleft()

        kps = len(self.timestamps)

        # Critical Alert
        if kps >= self.CRITICAL_THRESHOLD:

            return {
                "detected": True,
                "severity": "CRITICAL",
                "speed": kps,
                "score": 50
            }

        # Warning Alert
        if kps >= self.WARNING_THRESHOLD:

            return {
                "detected": True,
                "severity": "WARNING",
                "speed": kps,
                "score": 30
            }

        return {
            "detected": False,
            "severity": "NORMAL",
            "speed": kps,
            "score": 0
        }

    def get_current_speed(self):
        return len(self.timestamps)

    def reset(self):
        self.timestamps.clear()