import keyboard

from Detectors.speed_detector import SpeedDetector
from Detectors.command_detector import CommandDetector
from Detectors.winr_detector import WinRDetector
from Detectors.threat_score import ThreatScore
from database.db_manager import DBManager
from logs.export_manager import ExportManager

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
        self.db = DBManager()
        self.export_manager = ExportManager()

    def process_key(self, event):

        key = event.name.lower()

        if key in self.IGNORED_KEYS:
            return

        speed_result = self.speed_detector.process_key()

        winr_result = self.winr_detector.process_key(key)

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

            self.db.save_incident(threat)
            self.export_manager.export_incident(threat)

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
