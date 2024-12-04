import sys
import os
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from email import message_from_string
from bs4 import BeautifulSoup
from datetime import datetime
from loguru import logger
from dotenv import load_dotenv

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def authenticate_gmail():
    creds = None

    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            print("Credentials expired, requesting a refresh...")
            try:
                creds.refresh(Request())
            except Exception as e:
                logger.error(str(e))

                print("Deleting old token.json...")
                os.remove("token.json")
                exit()
        else:
            print("No existing credentials, creating new...")
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)

        with open("token.json", "w") as token:
            token.write(creds.to_json())

    return creds
