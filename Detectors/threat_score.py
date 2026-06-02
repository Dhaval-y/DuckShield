class ThreatScore:

    def calculate(
        self,
        speed_result,
        command_result,
        winr_result
    ):

        total_score = 0
        reasons = []

        if speed_result["detected"]:
            total_score += speed_result["score"]
            reasons.append(
                f"High Speed ({speed_result['speed']} KPS)"
            )

        if command_result["detected"]:
            total_score += command_result["score"]
            reasons.append(
                f"Command: {command_result['keyword']}"
            )

        if winr_result["detected"]:
            total_score += winr_result["score"]
            reasons.append(
                "Win+R Detected"
            )

        if total_score >= 80:
            level = "CRITICAL"

        elif total_score >= 50:
            level = "HIGH"

        elif total_score >= 20:
            level = "MEDIUM"

        else:
            level = "LOW"

        return {
            "score": total_score,
            "level": level,
            "reasons": reasons
        }