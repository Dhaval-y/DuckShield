import os


class ProcessKiller:

    def __init__(self):

        self.blocked_processes = {

            "powershell": "powershell.exe",
            "cmd": "cmd.exe",

            "wscript": "wscript.exe",
            "cscript": "cscript.exe",

            "mshta": "mshta.exe",
            "rundll32": "rundll32.exe",

            "certutil": "certutil.exe",
            "bitsadmin": "bitsadmin.exe",

            "taskkill": "taskkill.exe"

        }

    def kill_process(
        self,
        process_name
    ):

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

        keyword = (
            command_result["keyword"]
        )

        process_name = None

        # Direct keyword match

        if keyword in self.blocked_processes:

            process_name = (
                self.blocked_processes[keyword]
            )

        # Special handling

        elif keyword in {
            "-enc",
            "encodedcommand",
            "invoke-webrequest",
            "downloadstring",
            "iex",
            "start-bitstransfer"
        }:

            process_name = (
                "powershell.exe"
            )

        if process_name is None:
            return

        # ------------------------
        # HIGH Threat
        # ------------------------

        if threat["level"] == "HIGH":

            print(
                "\n[HIGH THREAT DETECTED]"
            )

            print(
                f"Process : {process_name}"
            )

            choice = input(
                "Terminate process? "
                "(Y/N): "
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

            print(
                f"Target Process : "
                f"{process_name}"
            )

            self.kill_process(
                process_name
            )