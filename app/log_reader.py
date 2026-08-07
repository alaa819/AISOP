from pathlib import Path

LOG_FILE = "/var/log/syslog"

def read_logs():
    try:
        with open(LOG_FILE, "r") as file:
            logs = file.readlines()

        print("\n===== Latest 10 Log Entries =====\n")

        for line in logs[-10:]:
            print(line.strip())

    except FileNotFoundError:
        print(f"Log file '{LOG_FILE}' not found.")

    except PermissionError:
        print("Permission denied. Try running with sudo.")

if __name__ == "__main__":
    read_logs()