import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from datetime import datetime
import sqlite3
import shutil
import os


class Dashboard:

    def __init__(self):

        self.root = tk.Tk()

        self.root.title(
            "DuckShield Dashboard"
        )

        self.root.geometry(
            "1100x750"
        )

        self.root.resizable(
            False,
            False
        )

        # -----------------------
        # Header
        # -----------------------

        title = tk.Label(
            self.root,
            text="DUCKSHIELD DASHBOARD",
            font=("Arial", 22, "bold")
        )

        title.pack(
            pady=15
        )

        # -----------------------
        # Statistics
        # -----------------------

        self.total_incidents_label = tk.Label(
            self.root,
            text="Total Incidents : 0",
            font=("Arial", 14)
        )

        self.total_incidents_label.pack()

        self.last_level_label = tk.Label(
            self.root,
            text="Last Threat Level : N/A",
            font=("Arial", 14)
        )

        self.last_level_label.pack()

        self.last_score_label = tk.Label(
            self.root,
            text="Last Threat Score : N/A",
            font=("Arial", 14)
        )

        self.last_score_label.pack()

        # -----------------------
        # Threat Distribution
        # -----------------------

        distribution_frame = tk.Frame(
            self.root
        )

        distribution_frame.pack(
            pady=15
        )

        self.low_label = tk.Label(
            distribution_frame,
            text="LOW : 0",
            font=("Arial", 12, "bold"),
            fg="green"
        )

        self.low_label.grid(
            row=0,
            column=0,
            padx=20
        )

        self.medium_label = tk.Label(
            distribution_frame,
            text="MEDIUM : 0",
            font=("Arial", 12, "bold"),
            fg="orange"
        )

        self.medium_label.grid(
            row=0,
            column=1,
            padx=20
        )

        self.high_label = tk.Label(
            distribution_frame,
            text="HIGH : 0",
            font=("Arial", 12, "bold"),
            fg="red"
        )

        self.high_label.grid(
            row=0,
            column=2,
            padx=20
        )

        self.critical_label = tk.Label(
            distribution_frame,
            text="CRITICAL : 0",
            font=("Arial", 12, "bold"),
            fg="dark red"
        )

        self.critical_label.grid(
            row=0,
            column=3,
            padx=20
        )

        # -----------------------
        # Monitoring Status
        # -----------------------

        self.status_label = tk.Label(
            self.root,
            text="🟢 Monitoring Status : ACTIVE",
            font=("Arial", 12, "bold")
        )

        self.status_label.pack(
            pady=5
        )

                # -----------------------
        # Search Box
        # -----------------------

        search_frame = tk.Frame(
            self.root
        )

        search_frame.pack(
            pady=5
        )

        tk.Label(
            search_frame,
            text="Search:"
        ).pack(
            side="left"
        )

        self.search_var = tk.StringVar()

        search_entry = tk.Entry(
            search_frame,
            textvariable=self.search_var,
            width=30
        )

        search_entry.pack(
            side="left",
            padx=5
        )

        search_entry.bind(
            "<KeyRelease>",
            lambda event: self.refresh_data()
        )
        
                # -----------------------
        # Threat Filter
        # -----------------------

        filter_frame = tk.Frame(
            self.root
        )

        filter_frame.pack(
            pady=5
        )

        tk.Label(
            filter_frame,
            text="Filter:"
        ).pack(
            side="left"
        )

        self.filter_var = tk.StringVar(
            value="ALL"
        )

        filter_menu = ttk.Combobox(
            filter_frame,
            textvariable=self.filter_var,
            values=[
                "ALL",
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL"
            ],
            state="readonly",
            width=15
        )

        filter_menu.pack(
            side="left",
            padx=5
        )

        filter_menu.bind(
            "<<ComboboxSelected>>",
            lambda event: self.refresh_data()
        )

        # -----------------------
        # Buttons
        # -----------------------

        button_frame = tk.Frame(
            self.root
        )

        button_frame.pack(
            pady=10
        )

        refresh_button = tk.Button(
            button_frame,
            text="Refresh",
            width=15,
            command=self.refresh_data
        )

        refresh_button.grid(
            row=0,
            column=0,
            padx=10
        )

        clear_button = tk.Button(
            button_frame,
            text="Clear Database",
            width=15,
            command=self.clear_database
        )

        clear_button.grid(
            row=0,
            column=1,
            padx=10
        )

        export_csv_button = tk.Button(
            button_frame,
            text="Export CSV",
            width=15,
            command=self.export_csv
        )

        export_csv_button.grid(
            row=0,
            column=2,
            padx=10
        )

        export_txt_button = tk.Button(
            button_frame,
            text="Export TXT",
            width=15,
            command=self.export_txt
        )

        export_txt_button.grid(
            row=0,
            column=3,
            padx=10
        )

        # -----------------------
        # Incident Table
        # -----------------------

        self.tree = ttk.Treeview(
            self.root,
            columns=(
                "ID",
                "Timestamp",
                "Level",
                "Score",
                "Reason"
            ),
            show="headings"
        )

        self.tree.tag_configure(
        "LOW",
        foreground="green"
            )

        self.tree.tag_configure(
        "MEDIUM",
        foreground="orange"
            )

        self.tree.tag_configure(
        "HIGH",
        foreground="red"
        )

        self.tree.tag_configure(
        "CRITICAL",
        foreground="dark red"
        )

        self.tree.heading(
            "ID",
            text="ID"
        )

        self.tree.heading(
            "Timestamp",
            text="Timestamp"
        )

        self.tree.heading(
            "Level",
            text="Level"
        )

        self.tree.heading(
            "Score",
            text="Score"
        )

        self.tree.heading(
            "Reason",
            text="Reason"
        )

        self.tree.column(
            "ID",
            width=50
        )

        self.tree.column(
            "Timestamp",
            width=180
        )

        self.tree.column(
            "Level",
            width=100
        )

        self.tree.column(
            "Score",
            width=80
        )

        self.tree.column(
            "Reason",
            width=600
        )

        self.tree.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )
        
        

        self.refresh_data()

    def get_connection(self):

        return sqlite3.connect(
            "database/incidents.db"
        )

    def refresh_data(self):

        conn = self.get_connection()

        cursor = conn.cursor()

        search_text = (
            self.search_var.get()
            if hasattr(self, "search_var")
            else ""
        )

        selected_filter = (
            self.filter_var.get()
            if hasattr(self, "filter_var")
            else "ALL"
        )

        query = """
            SELECT *
            FROM incidents
            WHERE 1=1
        """

        params = []

        if selected_filter != "ALL":

            query += (
                " AND threat_level = ?"
            )

            params.append(
                selected_filter
            )

        if search_text:

            query += (
                " AND reasons LIKE ?"
            )

            params.append(
                f"%{search_text}%"
            )

        query += (
            " ORDER BY id DESC"
        )

        cursor.execute(
            query,
            params
        )

        records = cursor.fetchall()
        print("Records Found =", len(records))
        conn.close()

        low_count = 0
        medium_count = 0
        high_count = 0
        critical_count = 0

        for record in records:

            level = record[2]

            if level == "LOW":
                low_count += 1

            elif level == "MEDIUM":
                medium_count += 1

            elif level == "HIGH":
                high_count += 1

            elif level == "CRITICAL":
                critical_count += 1

        self.low_label.config(
            text=f"LOW : {low_count}"
        )

        self.medium_label.config(
            text=f"MEDIUM : {medium_count}"
        )

        self.high_label.config(
            text=f"HIGH : {high_count}"
        )

        self.critical_label.config(
            text=f"CRITICAL : {critical_count}"
        )

        total = len(records)

        self.total_incidents_label.config(
            text=f"Total Incidents : {total}"
        )

        if total > 0:

            latest = records[0]

            self.last_level_label.config(
                text=f"Last Threat Level : {latest[2]}"
            )

            self.last_score_label.config(
                text=f"Last Threat Score : {latest[3]}"
            )

        else:

            self.last_level_label.config(
                text="Last Threat Level : N/A"
            )

            self.last_score_label.config(
                text="Last Threat Score : N/A"
            )

        for row in self.tree.get_children():

            self.tree.delete(row)

        for row in records:

            level = row[2]

            self.tree.insert(
                "",
                "end",
                values=row,
                tags=(level,)
            )

        # self.root.after(
        #     5000,
        #     self.refresh_data
        # )

    def clear_database(self):

        confirm = messagebox.askyesno(
            "Confirm",
            "Delete all incidents?"
        )

        if not confirm:
            return

        conn = self.get_connection()

        cursor = conn.cursor()

        print("Search =", search_text)
        print("Filter =", selected_filter)
        print("Query =", query)
        print("Params =", params)

        cursor.execute(
            "DELETE FROM incidents"
        )

        conn.commit()

        conn.close()

        self.refresh_data()

    def export_csv(self):

        try:

            os.makedirs(
                "exports",
                exist_ok=True
            )

            timestamp = datetime.now().strftime(
                "%Y%m%d_%H%M%S"
            )

            source = os.path.join(
                "logs",
                "incident_log.csv"
            )

            destination = os.path.join(
                "exports",
                f"incidents_{timestamp}.csv"
            )

            shutil.copy(
                source,
                destination
            )

            messagebox.showinfo(
                "Export Complete",
                f"CSV exported successfully.\n\n{destination}"
            )

        except Exception as e:

            messagebox.showerror(
                "Export Error",
                str(e)
            )

    def export_txt(self):

        try:

            os.makedirs(
                "exports",
                exist_ok=True
            )

            timestamp = datetime.now().strftime(
                "%Y%m%d_%H%M%S"
            )

            source = os.path.join(
                "logs",
                "incident_log.txt"
            )

            destination = os.path.join(
                "exports",
                f"incidents_{timestamp}.txt"
            )

            shutil.copy(
                source,
                destination
            )

            messagebox.showinfo(
                "Export Complete",
                f"TXT exported successfully.\n\n{destination}"
            )

        except Exception as e:

            messagebox.showerror(
                "Export Error",
                str(e)
            )

    def run(self):

        self.root.mainloop()


if __name__ == "__main__":

    dashboard = Dashboard()

    dashboard.run()