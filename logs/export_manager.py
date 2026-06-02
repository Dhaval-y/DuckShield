import csv
import os
from datetime import datetime


class ExportManager:

    def __init__(
        self,
        txt_path="logs/incident_log.txt",
        csv_path="logs/incident_log.csv"
    ):

        self.txt_path = txt_path
        self.csv_path = csv_path

        self.initialize_csv()

    def initialize_csv(self):

        if not os.path.exists(self.csv_path):

            with open(
                self.csv_path,
                "w",
                newline="",
                encoding="utf-8"
            ) as file:

                writer = csv.writer(file)

                writer.writerow(
                    [
                        "Timestamp",
                        "Threat Level",
                        "Threat Score",
                        "Reasons"
                    ]
                )

    def export_incident(self, threat):

        timestamp = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        reasons = ", ".join(
            threat["reasons"]
        )

        self.export_to_txt(
            timestamp,
            threat["level"],
            threat["score"],
            reasons
        )

        self.export_to_csv(
            timestamp,
            threat["level"],
            threat["score"],
            reasons
        )

    def export_to_txt(
        self,
        timestamp,
        level,
        score,
        reasons
    ):

        with open(
            self.txt_path,
            "a",
            encoding="utf-8"
        ) as file:

            file.write(
                f"\n[{timestamp}]\n"
            )

            file.write(
                f"Threat Level : {level}\n"
            )

            file.write(
                f"Threat Score : {score}\n"
            )

            file.write(
                f"Reasons      : {reasons}\n"
            )

            file.write(
                "-" * 50 + "\n"
            )

    def export_to_csv(
        self,
        timestamp,
        level,
        score,
        reasons
    ):

        with open(
            self.csv_path,
            "a",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)

            writer.writerow(
                [
                    timestamp,
                    level,
                    score,
                    reasons
                ]
            )