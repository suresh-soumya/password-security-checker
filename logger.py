from datetime import datetime
import hashlib

def log_result(password, strength, breached):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    with open("security_log.txt", "a") as file:
        file.write(
            f"{datetime.now()} | {hashed_password} | "
            f"{strength} | Breached: {breached}\n"
        )
