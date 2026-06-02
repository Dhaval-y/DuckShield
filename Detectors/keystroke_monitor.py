import keyboard

from speed_detector import SpeedDetector
from command_detector import CommandDetector
from winr_detector import WinRDetector
from threat_score import ThreatScore


class KeystrokeMonitor:

    IGNORED_KEYS = {
        "shift",
        "left shift",
        "right shift",
        "ctrl",
        "left ctrl",
        "right ctrl",
        "alt",
        "left alt",
        "right alt",
        "caps lock"
    }

    def __init__(self):

        self.speed_detector = SpeedDetector()
        self.command_detector = CommandDetector()
        self.winr_detector = WinRDetector()
        self.threat_score = ThreatScore()

    def process_key(self, event):

        key = event.name.lower()

        if key in self.IGNORED_KEYS:
            return

        speed_result = self.speed_detector.process_key()

        winr_result = self.winr_detector.process_key(key)
        print(winr_result)

        # Win+R ke 'r' ko command buffer me mat bhejo
        if winr_result.get("consume_key", False):

            command_result = {
            "detected": False,
            "command": None
            }

        else:

            command_result = self.command_detector.process_key(key)

        result = {
            "key": key,
            "speed": speed_result,
            "winr": winr_result,
            "command": command_result
                }

        self.handle_detection(result)

    def handle_detection(self, result):

        # Calculate Threat Score

        threat = self.threat_score.calculate(
            result["speed"],
            result["command"],
            result["winr"]
        )

        if threat["score"] > 0:

            print(
                f"\n[THREAT] {threat['level']} "
                f"(Score: {threat['score']})"
            )

            print(
                f"Reasons: "
                f"{', '.join(threat['reasons'])}"
            )

        # Speed Detection

        if result["speed"]["detected"]:

            print(
                f"[{result['speed']['severity']}] "
                f"Typing Speed: "
                f"{result['speed']['speed']} KPS"
            )

        # Win + R Detection

        if result["winr"]["detected"]:

            print(
                "[ALERT] Win + R Detected"
            )

        # Command Detection

        if result["command"]["detected"]:

            print(
                f"[ALERT] Suspicious Command: "
                f"{result['command']['keyword']}"
            )

            print(
                f"Command: "
                f"{result['command']['command']}"
            )

    def start(self):

        print("DuckShield Started...")
        print("Monitoring Keyboard Activity...")
        print("Press ESC to stop.\n")

        keyboard.on_press(self.process_key)

        keyboard.wait("esc")


if __name__ == "__main__":

    monitor = KeystrokeMonitor()
    monitor.start()