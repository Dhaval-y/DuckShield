import os


class ProcessKiller:

    def __init__(self):

        self.blocked_processes = {

            "powershell": "powershell.exe",
            "cmd": "cmd.exe",
            "wscript": "wscript.exe",
            "cscript": "cscript.exe",
            "mshta": "mshta.exe",
            "rundll32": "rundll32.exe"

        }

    def kill_process(self, process_name):

        try:

            os.system(
                f'taskkill /F /IM "{process_name}" > nul 2>&1'
            )

            print(
                f"[ACTION] Terminated: "
                f"{process_name}"
            )

            return True

        except Exception as e:

            print(
                f"[ERROR] {e}"
            )

            return False

    def handle_threat(
        self,
        threat,
        command_result
    ):

        if not command_result["detected"]:
            return

        keyword = command_result["keyword"]

        if keyword not in self.blocked_processes:
            return

        process_name = (
            self.blocked_processes[keyword]
        )

        # ------------------------
        # HIGH Threat
        # ------------------------

        if threat["level"] == "HIGH":

            choice = input(

                f"\n[HIGH THREAT]\n"
                f"Terminate {process_name} ? "
                f"(Y/N): "

            )

            if choice.lower() == "y":

                self.kill_process(
                    process_name
                )

        # ------------------------
        # CRITICAL Threat
        # ------------------------

        elif threat["level"] == "CRITICAL":

            print(
                "\n[CRITICAL THREAT]"
            )

            print(
                "Automatic Response Triggered"
            )

            self.kill_process(
                process_name
            )