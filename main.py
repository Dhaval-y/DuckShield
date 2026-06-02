from Detectors.keystroke_monitor import KeystrokeMonitor


def main():

    print("\n" + "=" * 60)
    print("DuckShield - USB HID Intrusion Detection System")
    print("=" * 60)

    monitor = KeystrokeMonitor()

    monitor.start()


if __name__ == "__main__":

    main()