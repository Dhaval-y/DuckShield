import sqlite3
from datetime import datetime


class DBManager:

    def __init__(self, db_path="database/incidents.db"):

        self.db_path = db_path

        self.create_table()

    def create_connection(self):

        return sqlite3.connect(self.db_path)

    def create_table(self):

        conn = self.create_connection()

        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                timestamp TEXT NOT NULL,

                threat_level TEXT NOT NULL,

                threat_score INTEGER NOT NULL,

                reasons TEXT NOT NULL
            )
            """
        )

        conn.commit()
        conn.close()

    def save_incident(self, threat):

        conn = self.create_connection()

        cursor = conn.cursor()

        timestamp = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        reasons = ", ".join(
            threat["reasons"]
        )

        cursor.execute(
            """
            INSERT INTO incidents
            (
                timestamp,
                threat_level,
                threat_score,
                reasons
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                timestamp,
                threat["level"],
                threat["score"],
                reasons
            )
        )

        conn.commit()
        conn.close()

    def get_all_incidents(self):

        conn = self.create_connection()

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT *
            FROM incidents
            ORDER BY id DESC
            """
        )

        records = cursor.fetchall()

        conn.close()

        return records

    def get_incident_count(self):

        conn = self.create_connection()

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM incidents
            """
        )

        count = cursor.fetchone()[0]

        conn.close()

        return count

    def clear_database(self):

        conn = self.create_connection()

        cursor = conn.cursor()

        cursor.execute(
            """
            DELETE FROM incidents
            """
        )

        conn.commit()
        conn.close()