import time

class WinRDetector:

    ALERT_WINDOW = 10  # seconds

    def __init__(self):

        self.windows_pressed = False
        self.last_detection_time = 0

    def process_key(self, key):

        key = key.lower()

        # Detect Windows Key Press
        if key in (
            "windows",
            "left windows",
            "right windows",
            "left windows key",
            "right windows key"
        ):
            self.windows_pressed = True

            return {
                "detected": False
            }

        # Detect Win + R
        if self.windows_pressed and key == "r":

            self.windows_pressed = False
            self.last_detection_time = time.time()

            return {
                "detected": True,
                "type": "WIN_R",
                "timestamp": self.last_detection_time,
                "score": 30,
                "consume_key": True
            }

        # Reset flag if another key is pressed
        if self.windows_pressed and key != "r":
            self.windows_pressed = False

        return {
            "detected": False,
            "consume_key": False
        }

    def is_alert_window_active(self):

        return (
            time.time() - self.last_detection_time
            <= self.ALERT_WINDOW
        )

    def get_remaining_alert_time(self):

        remaining = (
            self.ALERT_WINDOW
            - (time.time() - self.last_detection_time)
        )

        return max(0, round(remaining, 2))

    def reset(self):

        self.windows_pressed = False
        self.last_detection_time = 0