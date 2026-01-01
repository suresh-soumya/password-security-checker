import getpass
from strength import check_strength, calculate_entropy, estimate_crack_time
from breach_check import check_breach
from logger import log_result

def main():
    password = getpass.getpass("Enter password to check: ")

    strength = check_strength(password)
    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)
    breached = check_breach(password)

    print("\n--- Password Security Analysis ---")
    print(f"Password Strength       : {strength}")
    print(f"Password Entropy        : {entropy} bits")
    print(f"Estimated Crack Time    : {crack_time}")

    if breached:
        print("Breach Status           : ⚠️ Found in known data breaches")
    else:
        print("Breach Status           : ✅ Not found in known data breaches")

    log_result(password, strength, breached)

if __name__ == "__main__":
    main()

