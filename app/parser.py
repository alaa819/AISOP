LOG_FILE = "/var/log/syslog"


def parse_logs():
    try:
        with open(LOG_FILE, "r") as file:
            logs = file.readlines()

        print("\n===== Parsed Linux Logs =====\n")

        for line in logs[-10:]:

            parts = line.split()

            if len(parts) < 6:
                continue

            date = " ".join(parts[:3])
            host = parts[3]
            service = parts[4].rstrip(":")
            message = " ".join(parts[5:])

            print("=" * 40)
            print(f"Date    : {date}")
            print(f"Host    : {host}")
            print(f"Service : {service}")
            print(f"Message : {message}")

        print("=" * 40)

    except FileNotFoundError:
        print("Log file not found.")

    except PermissionError:
        print("Permission denied. Try running with sudo.")


if __name__ == "__main__":
    parse_logs()