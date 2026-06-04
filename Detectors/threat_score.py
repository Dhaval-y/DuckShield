import time


class ThreatScore:

    CORRELATION_WINDOW = 10

    def __init__(self):

        self.last_winr_time = 0
        self.last_command_time = 0
        self.last_speed_time = 0

        self.command_count = 0

        self.last_command_sequence_time = 0

    def calculate(
        self,
        speed_result,
        command_result,
        winr_result
    ):

        total_score = 0
        reasons = []

        current_time = time.time()

        new_event = (

            speed_result["detected"]

            or

            command_result["detected"]

            or

            winr_result["detected"]

        )

        # -------------------------
        # Individual Events
        # -------------------------

        if speed_result["detected"]:

            total_score += (
                speed_result["score"]
            )

            self.last_speed_time = (
                current_time
            )

            reasons.append(
                f"High Speed "
                f"({speed_result['speed']} KPS)"
            )

        if command_result["detected"]:

            # Reset command sequence
            # if inactivity exceeds window

            if (

                current_time
                - self.last_command_sequence_time

                > self.CORRELATION_WINDOW

            ):

                self.command_count = 0

            total_score += (
                command_result["score"]
            )

            self.last_command_time = (
                current_time
            )

            self.last_command_sequence_time = (
                current_time
            )

            self.command_count += 1

            print(
                f"[DEBUG] Command Count = "
                f"{self.command_count}"
            )

            reasons.append(
                f"Command: "
                f"{command_result['keyword']}"
            )

        if winr_result["detected"]:

            total_score += (
                winr_result["score"]
            )

            self.last_winr_time = (
                current_time
            )

            reasons.append(
                "Win+R Detected"
            )

        # -------------------------
        # Correlation Rules
        # -------------------------

        if new_event:

            # Win+R -> Command

            if (

                current_time
                - self.last_winr_time

                <= self.CORRELATION_WINDOW

                and

                current_time
                - self.last_command_time

                <= self.CORRELATION_WINDOW

            ):

                total_score += 40

                reasons.append(
                    "Win+R → Command Execution"
                )

            # Fast Typing + Command

            if (

                current_time
                - self.last_command_time

                <= self.CORRELATION_WINDOW

                and

                current_time
                - self.last_speed_time

                <= self.CORRELATION_WINDOW

            ):

                total_score += 30

                reasons.append(
                    "Automated Typing Pattern"
                )

            # Full Rubber Ducky Chain

            if (

                current_time
                - self.last_winr_time

                <= self.CORRELATION_WINDOW

                and

                current_time
                - self.last_command_time

                <= self.CORRELATION_WINDOW

                and

                current_time
                - self.last_speed_time

                <= self.CORRELATION_WINDOW

            ):

                total_score += 50

                reasons.append(
                    "Possible Rubber Ducky Attack"
                )

        # -------------------------
        # Multiple Commands Rule
        # -------------------------

        if (

            self.command_count >= 3

            and

            current_time
            - self.last_command_sequence_time

            <= self.CORRELATION_WINDOW

        ):

            total_score += 30

            reasons.append(
                "Multiple Suspicious Commands"
            )

        # -------------------------
        # Threat Level
        # -------------------------

        if total_score >= 100:

            level = "CRITICAL"

        elif total_score >= 80:

            level = "HIGH"

        elif total_score >= 30:

            level = "MEDIUM"

        else:

            level = "LOW"

        return {
            "score": total_score,
            "level": level,
            "reasons": reasons
        }