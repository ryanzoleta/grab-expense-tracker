from __future__ import print_function

import re
import json
import os.path
import base64
import redis
import requests
import sys
import argparse
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

load_dotenv()

logger.remove()
logger.add(
    "logs/logs_{time:YYYYMMDD}.log",
    rotation="1 week",
    format="{time:YYYY-MM-DD.HH:mm:ss} [{level}] {message}",
)

parser = argparse.ArgumentParser(description="Grab Expense Tracker")
parser.add_argument("--processlast", action="store_true", help="Process the last item")
args = parser.parse_args()


ynab_ids_file = open("ynab_ids.json")
ynab_ids = json.load(ynab_ids_file)
account_ids = ynab_ids["accounts"]


# def connect_redis():
#     if os.getenv("REDISHOST") is None:
#         logger.error("Connection environment variables are undefined!")
#         exit()

#     r = redis.Redis(
#         host=os.getenv("REDISHOST"),
#         username=os.getenv("REDISUSER"),
#         password=os.getenv("REDISPASSWORD"),
#         port=os.getenv("REDISPORT"),
#     )

#     return r


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


def get_grab_emails(creds):
    emails = []

    data_file = open("data.json")
    data = json.load(data_file)
    last_processed_email_id = data["last_processed_email_id"]

    try:
        service = build("gmail", "v1", credentials=creds)
        grabmsgs = (
            service.users()
            .messages()
            .list(userId="me", labelIds="Label_6207772532920259483")
            .execute()
        )

        for msg in grabmsgs["messages"]:            
            if not args.processlast and msg["id"] == last_processed_email_id:
                break

            email = (
                service.users()
                .messages()
                .get(id=msg["id"], userId="me", format="raw")
                .execute()
            )

            raw_message = email["raw"]
            decoded_message = base64.urlsafe_b64decode(raw_message.encode("UTF-8"))
            raw_email = decoded_message.decode("UTF-8")
            email_message = message_from_string(raw_email)

            for part in email_message.walk():
                if part.get_all("Subject") is None:
                    continue

                subject = part.get_all("Subject")[0]

                if subject is not None and subject == "Your Grab E-Receipt":
                    emails.append(email)
                    break

            if args.processlast:
                break

            # if len(emails) > 0:
            #     break

        if len(emails) > 0 and not args.processlast:
            data["last_processed_email_id"] = emails[0]["id"]
            with open("data.json", "w") as outfile:
                json.dump(data, outfile)

    except HttpError as error:
        print(f"An error occured: {error}")

    print(f"Retrieved {len(emails)} emails!")

    return emails


def extract_plain_text(email):
    raw_message = email["raw"]
    decoded_message = base64.urlsafe_b64decode(raw_message.encode("UTF-8"))
    raw_email = decoded_message.decode("UTF-8")
    email = message_from_string(raw_email)

    plain_text = ""
    for part in email.walk():
        if part.get_content_type() == "text/plain":
            plain_text = part.get_payload(decode=True).decode("UTF-8")
            break

    if not plain_text:
        for part in email.walk():
            if part.get_content_type() == "text/html":
                html_text = part.get_payload(decode=True).decode("UTF-8")
                soup = BeautifulSoup(html_text, "html.parser")
                plain_text = soup.get_text()

    all_text = ""

    for s in soup:
        all_text += s.text

    all_text = all_text.replace("\n", " ")
    all_text = re.sub(" +", " ", all_text)

    return all_text


def extract_data(text):
    pattern_file = open("data_patterns.json")
    patterns = json.load(pattern_file)

    data_extract = {}

    for pattern in patterns["pattern_list"]:
        matches = re.search(pattern["pattern"], text)
        if not matches:
            return None
        data_extract[pattern["data"]] = matches.groups()[0].strip()

    return data_extract


def add_to_ynab(transaction):
    date_obj = datetime.strptime(transaction["date"], "%d %b %y")
    date = date_obj.strftime("%Y-%m-%d")

    amount = "-" + transaction["amount"].replace(".", "") + "0"
    shop = transaction["shop"]
    account = [x for x in account_ids if x["name"] == transaction["pay_method"]][0][
        "id"
    ]

    json = {
        "transaction": {
            "date": date,
            "amount": amount,
            "memo": shop,
            "cleared": "cleared",
            "approved": True,
            "account_id": account,
            "payee_id": "e8c1dc4a-ecf4-4d94-80e9-7161d884916a",
            "category_id": "293f682f-8a36-4ba4-9e9e-64f3877711c7",
        }
    }

    headers = {
        "Content-type": "application/json",
        "Authorization": f'Bearer {os.environ["YNAB_TOKEN"]}',
    }

    r = requests.post(
        "https://api.youneedabudget.com/v1/budgets/bfb94261-b4e3-4e9d-aa19-58b8d9d47678/transactions",
        headers=headers,
        json=json,
    )

    if r.status_code == 201:
        print(f"Successfully added {shop} transaction on {date}")
    else:
        print(r.json())


def extract_transactions(emails):
    transactions = []
    for email in emails:
        plain_text = extract_plain_text(email)
        data = extract_data(plain_text)

        if data is not None:
            transactions.append(data)

    print(f"Found {len(transactions)} transactions!")

    return transactions


def main():
    # Login to gmail
    creds = authenticate_gmail()

    if creds is None:
        logger.error("Error logging in!")
        exit()

    # Retreive relevant emails
    emails = get_grab_emails(creds)

    if len(emails) == 0:
        exit()

    # Extract transactions
    transactions = extract_transactions(emails)

    # Add transactions to ynab
    for transaction in transactions:
        add_to_ynab(transaction)


if __name__ == "__main__":
    main()
