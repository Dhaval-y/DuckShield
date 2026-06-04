from response.threat_popup import ThreatPopup

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

        # ------------------------
        # Direct Mapping
        # ------------------------

        if keyword in self.blocked_processes:

            process_name = (
                self.blocked_processes[keyword]
            )

        # ------------------------
        # PowerShell Payloads
        # ------------------------

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

        print(
            "[DEBUG] Popup Object Created"
        )

        popup = ThreatPopup()

        # ------------------------
        # HIGH Threat
        # ------------------------

        if threat["level"] == "HIGH":

            print(
                "[DEBUG] Showing HIGH Popup"
            )

            result = popup.show_popup(

                process_name=
                process_name,

                threat_level=
                threat["level"],

                threat_score=
                threat["score"],

                reasons=
                threat["reasons"],

                countdown=False

            )

            print(
                f"[DEBUG] Result = {result}"
            )

            if result:

                self.kill_process(
                    process_name
                )

        # ------------------------
        # CRITICAL Threat
        # ------------------------

        elif threat["level"] == "CRITICAL":

            print(
                "[DEBUG] Showing CRITICAL Popup"
            )

            result = popup.show_popup(

                process_name=
                process_name,

                threat_level=
                threat["level"],

                threat_score=
                threat["score"],

                reasons=
                threat["reasons"],

                countdown=True

            )

            print(
                f"[DEBUG] Result = {result}"
            )

            if result:

                self.kill_process(
                    process_name
                )