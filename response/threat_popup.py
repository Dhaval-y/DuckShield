import tkinter as tk


class ThreatPopup:

    def show_popup(
        self,
        process_name,
        threat_level,
        threat_score,
        reasons,
        countdown=False
    ):

        self.result = False

        root = tk.Tk()

        root.title(
            "DuckShield Security Alert"
        )

        root.geometry(
            "550x400"
        )

        root.resizable(
            False,
            False
        )

        root.attributes(
            "-topmost",
            True
        )

        root.grab_set()

        root.protocol(
            "WM_DELETE_WINDOW",
            lambda: None
        )

        root.bind(
            "<Alt-F4>",
            lambda e: "break"
        )

        # --------------------
        # Theme
        # --------------------

        root.configure(
            bg="#0A0F1E"
        )

        # --------------------
        # Header
        # --------------------

        tk.Label(
            root,
            text="DUCKSHIELD SECURITY ALERT",
            font=("Arial", 16, "bold"),
            fg="#00D9FF",
            bg="#0A0F1E"
        ).pack(
            pady=15
        )

        # --------------------
        # Threat Info
        # --------------------

        tk.Label(
            root,
            text=f"Threat Level : {threat_level}",
            font=("Arial", 13, "bold"),
            fg="#FF4040",
            bg="#0A0F1E"
        ).pack()

        tk.Label(
            root,
            text=f"Threat Score : {threat_score}",
            font=("Arial", 12),
            fg="white",
            bg="#0A0F1E"
        ).pack(
            pady=5
        )

        tk.Label(
            root,
            text=f"Target Process : {process_name}",
            font=("Arial", 12),
            fg="white",
            bg="#0A0F1E"
        ).pack(
            pady=5
        )

        # --------------------
        # Reasons
        # --------------------

        tk.Label(
            root,
            text="Detection Reasons",
            font=("Arial", 12, "bold"),
            fg="#00D9FF",
            bg="#0A0F1E"
        ).pack(
            pady=10
        )

        reasons_text = "\n".join(
            reasons
        )

        tk.Label(
            root,
            text=reasons_text,
            justify="left",
            font=("Consolas", 10),
            fg="white",
            bg="#0A0F1E"
        ).pack()

        # --------------------
        # Countdown
        # --------------------

        countdown_label = tk.Label(
            root,
            text="",
            font=("Arial", 14, "bold"),
            fg="#FF4040",
            bg="#0A0F1E"
        )

        countdown_label.pack(
            pady=15
        )

        # --------------------
        # Button Actions
        # --------------------

        def yes():

            self.result = True

            root.destroy()

        def no():

            self.result = False

            root.destroy()

        # --------------------
        # Buttons
        # --------------------

        button_frame = tk.Frame(
            root,
            bg="#0A0F1E"
        )

        button_frame.pack(
            pady=10
        )

        tk.Button(
            button_frame,
            text="TERMINATE",
            width=18,
            bg="#1B263B",
            fg="#00D9FF",
            command=yes
        ).grid(
            row=0,
            column=0,
            padx=10
        )

        tk.Button(
            button_frame,
            text="IGNORE",
            width=18,
            bg="#1B263B",
            fg="white",
            command=no
        ).grid(
            row=0,
            column=1,
            padx=10
        )

        # --------------------
        # CRITICAL Countdown
        # --------------------

        if countdown:

            self.remaining = 10

            def update_timer():

                countdown_label.config(
                    text=
                    f"Automatic Termination In : "
                    f"{self.remaining} sec"
                )

                if self.remaining <= 0:

                    self.result = True

                    root.destroy()

                    return

                self.remaining -= 1

                root.after(
                    1000,
                    update_timer
                )

            update_timer()

        root.mainloop()

        return self.result