import keyboard

from Detectors.speed_detector import SpeedDetector
from Detectors.command_detector import CommandDetector
from Detectors.winr_detector import WinRDetector
from Detectors.threat_score import ThreatScore

from database.db_manager import DBManager
from logs.export_manager import ExportManager

from response.process_killer import ProcessKiller


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

        self.process_killer = ProcessKiller()

    def process_key(self, event):

        key = event.name.lower()

        if key in self.IGNORED_KEYS:
            return

        speed_result = (
            self.speed_detector.process_key()
        )

        winr_result = (
            self.winr_detector.process_key(key)
        )

        # Win+R ke "r" ko
        # command buffer me mat bhejo

        if winr_result.get(
            "consume_key",
            False
        ):

            command_result = {
                "detected": False,
                "command": None
            }

        else:

            command_result = (
                self.command_detector.process_key(
                    key
                )
            )

        result = {

            "key": key,

            "speed": speed_result,

            "winr": winr_result,

            "command": command_result

        }

        self.handle_detection(
            result
        )

    def handle_detection(
        self,
        result
    ):

        # -------------------------
        # Threat Score Calculation
        # -------------------------

        threat = (
            self.threat_score.calculate(

                result["speed"],

                result["command"],

                result["winr"]

            )
        )

        # -------------------------
        # Threat Output
        # -------------------------

        if threat["score"] > 0:

            print(
                f"\n[THREAT] "
                f"{threat['level']} "
                f"(Score: {threat['score']})"
            )

            print(
                f"Reasons: "
                f"{', '.join(threat['reasons'])}"
            )

            self.db.save_incident(
                threat
            )

            self.export_manager.export_incident(
                threat
            )

            self.process_killer.handle_threat(

                threat,

                result["command"]

            )

        # -------------------------
        # Speed Detection
        # -------------------------

        if result["speed"]["detected"]:

            print(

                f"[{result['speed']['severity']}] "

                f"Typing Speed: "

                f"{result['speed']['speed']} KPS"

            )

        # -------------------------
        # Win + R Detection
        # -------------------------

        if result["winr"]["detected"]:

            print(
                "[ALERT] Win + R Detected"
            )

        # -------------------------
        # Command Detection
        # -------------------------

        if result["command"]["detected"]:

            print(
                "\n" + "=" * 55
            )

            print(
                f"[ALERT] Suspicious Command: "
                f"{result['command']['keyword']}"
            )

            print(
                f"Command        : "
                f"{result['command']['command']}"
            )

            print(
                f"Command Score  : "
                f"{result['command']['score']}"
            )

            print(
                f"Threat Score   : "
                f"{threat['score']}"
            )

            print(
                f"Threat Level   : "
                f"{threat['level']}"
            )

            print(
                f"Reasons        : "
                f"{', '.join(threat['reasons'])}"
            )

            print(
                "=" * 55
            )

    def start(self):

        print(
            "DuckShield Started..."
        )

        print(
            "Monitoring Keyboard Activity..."
        )

        print(
            "Press ESC to stop.\n"
        )

        keyboard.on_press(
            self.process_key
        )

        keyboard.wait(
            "esc"
        )