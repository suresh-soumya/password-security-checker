import hashlib
import requests

def check_breach(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    if response.status_code != 200:
        print("Error checking breach database")
        return False

    hashes = response.text.splitlines()
    for line in hashes:
        hash_suffix, _ = line.split(":")
        if hash_suffix == suffix:
            return True

    return False

