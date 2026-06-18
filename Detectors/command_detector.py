class CommandDetector:

    MAX_BUFFER_SIZE = 500

    def __init__(self):

        self.buffer = ""

        self.suspicious_commands = {

            # -------------------------
            # Shell Execution
            # -------------------------

            "powershell": 20,
            "cmd": 25,

            # -------------------------
            # Download Utilities
            # -------------------------

            "curl": 20,
            "wget": 20,
            "certutil": 35,
            "bitsadmin": 35,

            # -------------------------
            # Payload Download Patterns
            # -------------------------

            "invoke-webrequest": 40,
            "start-bitstransfer": 40,
            "downloadstring": 50,
            "iex": 50,

            # -------------------------
            # Encoded PowerShell
            # -------------------------

            "-enc": 60,
            "encodedcommand": 60,

            # -------------------------
            # Reconnaissance
            # -------------------------

            "whoami": 10,
            "ipconfig": 10,
            "wmic": 25,
            "net user": 30,
            "netsh": 25,

            # -------------------------
            # Persistence / Registry
            # -------------------------

            "reg add": 30,

            # -------------------------
            # Process Manipulation
            # -------------------------

            "taskkill": 25,

            # -------------------------
            # LOLBins
            # -------------------------

            "mshta": 40,
            "rundll32": 40,

            # -------------------------
            # System Impact
            # -------------------------

            "shutdown": 20
        }

    def process_key(self, key):

        SPECIAL_KEYS = {
            "shift",
            "left shift",
            "right shift",
            "ctrl",
            "left ctrl",
            "right ctrl",
            "alt",
            "left alt",
            "right alt",
            "tab",
            "caps lock",
            "esc",
            "left windows",
            "right windows",
            "windows"
        }

        # Ignore modifier/system keys

        if key in SPECIAL_KEYS:

            return {
                "detected": False,
                "command": None
            }

        # Normal character keys

        if len(key) == 1 and key.isprintable():

            self.buffer += key.lower()

        # Space key

        elif key == "space":

            self.buffer += " "

        # Backspace support

        elif key == "backspace":

            self.buffer = self.buffer[:-1]

        # Prevent unlimited buffer growth

        if len(self.buffer) > self.MAX_BUFFER_SIZE:

            self.buffer = (
                self.buffer[
                    -self.MAX_BUFFER_SIZE:
                ]
            )

        # Analyze command on Enter

        if key == "enter":

            command = (
                self.buffer
                .strip()
                .lower()
            )

            # Clear buffer after processing

            self.buffer = ""

            if not command:

                return {
                    "detected": False,
                    "command": ""
                }

            highest_match = None

            for keyword, score in (
                self.suspicious_commands.items()
            ):

                if keyword in command:

                    if (
                        highest_match is None
                        or
                        score >
                        highest_match["score"]
                    ):

                        highest_match = {
                            "keyword": keyword,
                            "score": score
                        }

            if highest_match:

                return {
                    "detected": True,
                    "keyword":
                        highest_match["keyword"],
                    "command": command,
                    "score":
                        highest_match["score"]
                }

            return {
                "detected": False,
                "command": command
            }

        return {
            "detected": False,
            "command": None
        }

    def get_buffer(self):

        return self.buffer

    def clear_buffer(self):

        self.buffer = ""