class CommandDetector:

    MAX_BUFFER_SIZE = 500

    def __init__(self):

        self.buffer = ""

        self.suspicious_commands = {
            "powershell": 40,
            "cmd": 25,
            "curl": 20,
            "wget": 20,
            "net user": 30,
            "reg add": 30,
            "shutdown": 20,
            "taskkill": 25,
            "wmic": 25,
            "certutil": 35,
            "bitsadmin": 35,
            "whoami": 10,
            "ipconfig": 10,
            "netsh": 25,
            "mshta": 40,
            "rundll32": 40
        }

    def process_key(self, key):
        
        print(f"KEY: {key}")

        # Normal character keys
        if len(key) == 1:
            self.buffer += key.lower()

        # Space key
        elif key == "space":
            self.buffer += " "

        # Backspace support
        elif key == "backspace":
            self.buffer = self.buffer[:-1]

        # Prevent unlimited buffer growth
        if len(self.buffer) > self.MAX_BUFFER_SIZE:
            self.buffer = self.buffer[-self.MAX_BUFFER_SIZE:]

        # Analyze command on Enter key
        if key == "enter":

            print(f"BUFFER: {self.buffer}")

            command = self.buffer.strip().lower()

            # Clear buffer after command execution
            self.buffer = ""

            for keyword, score in self.suspicious_commands.items():

                if keyword in command:

                    return {
                        "detected": True,
                        "keyword": keyword,
                        "command": command,
                        "score": score
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