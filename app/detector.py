LOG_FILE = "/var/log/syslog"


def detect_threats():
    try:
        with open(LOG_FILE, "r") as file:
            logs = file.readlines()

        print("\n===== AISOP Threat Detection =====\n")

        for line in logs[-100:]:

            if "Failed password" in line:
                print("🚨 ALERT: Failed SSH Login")
                print(line.strip())
                print()

            elif "Accepted password" in line:
                print("✅ Successful SSH Login")
                print(line.strip())
                print()

            elif "Invalid user" in line:
                print("⚠️ Invalid Username Attempt")
                print(line.strip())
                print()

            elif "root" in line and "Accepted password" in line:
                print("🔥 Root Login Detected")
                print(line.strip())
                print()

    except FileNotFoundError:
        print("Log file not found.")

    except PermissionError:
        print("Permission denied. Try running with sudo.")


if __name__ == "__main__":
    detect_threats()