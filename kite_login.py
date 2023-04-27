# Standard Python library imports
import os
import sys
import json
import datetime
import logging

## Requests
import requests

## Pyotp
from pyotp import TOTP

## Kite Connect
from kiteconnect import KiteConnect


# Parameters
today = datetime.datetime.now().date()
logging.basicConfig(level=logging.DEBUG)


class LoginCredentials:
    """ to create access token and other details """

    def __init__(self):
        self.date = today
        self.credentials = "login_credentials.json"
        self.basic_data = self.basic_credentials()
        self.api_key = self.basic_data["api_key"]
        self.api_secret = self.basic_data['api_secret']
        self.user_id = self.basic_data['user_name']
        self.password = self.basic_data['password']
        self.totp = TOTP(self.basic_data['totp_secret']).now()

        # Change kwargs "auto=True to auto=False" for manual "access-token" generation
        self.access_token = self.gen_access_token()  # (auto=False)

    def basic_credentials(self):
        """ to create api_key, api_secret, totp_secret """
        log_file = None
        file = self.credentials

        while log_file is None:

            try:
                # try to access the existing file
                with open(file, "r") as f:
                    log_file = json.load(f)

            except FileNotFoundError:
                # Will create a file with user input
                print("---- Enter you Zerodha Login Credentials ----")

                log_credential = {"api_key": str(input("Enter API key :")),
                                  "api_secret": str(input("Enter API Secret :")),
                                  "totp_secret": str(input("Enter TOTP Secret :")),
                                  "user_name": str(input('Enter zerodha user name :')),
                                  "password": str(input('Enter zerodha password :'))
                                  }
                # Give an option to save the data entered by the user
                user_decision = input("Press Y to save login credential and press any key to bypass : ").upper()
                if user_decision == "Y":
                    with open(file, "w") as data:
                        json.dump(log_credential, data)
                    print("Data Saved...")

                elif user_decision == 'EXIT':
                    print("Session canceled!!!!!")
                    sys.exit()

                else:
                    print("Data Save canceled!!!!!")

        return log_file

    def gen_access_token(self, auto=True):
        """ to create access token """

        request_token = None
        access_token = None
        kite = KiteConnect(api_key=self.api_key)
        file_path = f"AccessToken/{self.date}.json"
        folder = "AccessToken"

        if os.path.exists(file_path):
            with open(file_path, 'r') as acc_data:
                access_token = json.load(acc_data)
                return access_token

        elif auto:
            # Initiate auto login with requests

            # Parameters
            url = kite.login_url()
            headers = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:74.0) Gecko/20100101 Firefox/74.0',
                       "X-Kite-Userid": self.user_id, 'X-Kite-Version': '3.0.14', 'Referer': url}

            # Generate request_token
            data = requests.post('https://kite.zerodha.com/api/login', headers=headers,
                                 data={'user_id': self.user_id, 'password': self.password})

            request_token = data.json()['data']['request_id']

            # Generate access_token
            data = requests.post('https://kite.zerodha.com/api/twofa', headers=headers,
                                 data={'user_id': self.user_id, 'request_id': request_token, 'twofa_value': self.totp})

            cookies = dict(data.cookies)

            access_token = cookies.get("public_token")

        else:
            print("---Getting Access Token manually---")
            print("Trying log In...")
            print("Login url : ", kite.login_url())
            request_token = input("Login and enter your 'request token' here : ")
            access_token = kite.generate_session(request_token=request_token,
                                                 api_secret=self.api_secret)["access_token"]

        try:
            os.makedirs(folder, exist_ok=True)
            with open(file_path, "w") as f:
                json.dump(access_token, f)
            print("Login successful...")

        except Exception as e:
            print(f"Login Failed {e}")

        return access_token


if __name__ == "__main__":
    log = LoginCredentials()
    print(log.gen_access_token())
