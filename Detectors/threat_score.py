import time


class ThreatScore:

    CORRELATION_WINDOW = 10

    def __init__(self):

        self.last_winr_time = 0
        self.last_command_time = 0
        self.last_speed_time = 0

    def calculate(
        self,
        speed_result,
        command_result,
        winr_result
    ):

        total_score = 0
        reasons = []

        current_time = time.time()

        # -------------------------
        # Individual Events
        # -------------------------

        if speed_result["detected"]:

            total_score += speed_result["score"]

            self.last_speed_time = current_time

            reasons.append(
                f"High Speed ({speed_result['speed']} KPS)"
            )

        if command_result["detected"]:

            total_score += command_result["score"]

            self.last_command_time = current_time

            reasons.append(
                f"Command: {command_result['keyword']}"
            )

        if winr_result["detected"]:

            total_score += winr_result["score"]

            self.last_winr_time = current_time

            reasons.append(
                "Win+R Detected"
            )

        # -------------------------
        # Correlation Rules
        # -------------------------

        if (
            current_time - self.last_winr_time
            <= self.CORRELATION_WINDOW
            and
            current_time - self.last_command_time
            <= self.CORRELATION_WINDOW
        ):

            total_score += 40

            reasons.append(
                "Win+R → Command Execution"
            )

        if (
            current_time - self.last_command_time
            <= self.CORRELATION_WINDOW
            and
            current_time - self.last_speed_time
            <= self.CORRELATION_WINDOW
        ):

            total_score += 30

            reasons.append(
                "Automated Typing Pattern"
            )

        if (
            current_time - self.last_winr_time
            <= self.CORRELATION_WINDOW
            and
            current_time - self.last_command_time
            <= self.CORRELATION_WINDOW
            and
            current_time - self.last_speed_time
            <= self.CORRELATION_WINDOW
        ):

            total_score += 50

            reasons.append(
                "Possible Rubber Ducky Attack"
            )

        # -------------------------
        # Threat Level
        # -------------------------

        if total_score >= 100:

            level = "CRITICAL"

        elif total_score >= 70:

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