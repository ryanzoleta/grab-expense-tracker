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
from utils import authenticate_gmail

SUBJECTS = ["Your Grab E-Receipt", "Transaction Notification"]


load_dotenv()

logger.remove()
logger.add(
    "logs/logs_{time:YYYYMMDD}.log",
    rotation="1 week",
    format="{time:YYYY-MM-DD.HH:mm:ss} [{level}] {message}",
)
logger.add(sys.stdout, format="{time:YYYY-MM-DD.HH:mm:ss} [{level}] {message}")

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


def get_emails(creds):
    emails = []

    data_file = open("data.json")
    data = json.load(data_file)
    last_processed_email_id = data["last_processed_email_id"]

    logger.info(f"last_processed_email_id {last_processed_email_id}")
    service = build("gmail", "v1", credentials=creds)

    try:
        msgs = service.users().messages().list(userId="me").execute()

        for msg in msgs["messages"]:
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

                if subject is not None and subject_matches(subject, SUBJECTS):
                    emails.append(email)
                    break

            if args.processlast:
                break

        if len(emails) > 0 and not args.processlast:
            data["last_processed_email_id"] = emails[0]["id"]
            with open("data.json", "w") as outfile:
                json.dump(data, outfile)

    except HttpError as error:
        logger.info(f"An error occured: {error}")

    logger.info(f"Retrieved {len(emails)} emails")

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

    if plain_text.strip() == "":
        for part in email.walk():
            if part.get_content_type() == "text/html":
                html_text = part.get_payload(decode=True).decode("UTF-8")
                soup = BeautifulSoup(html_text, "html.parser")
                plain_text = soup.get_text()

        # for s in soup:
        #     plain_text += s.text.replace("\n", "")
        #     logger.info(f"Adding to plain_text {s.text}")

    plain_text = plain_text.replace("\n", " ")
    plain_text = re.sub(" +", " ", plain_text)

    return {
        "text": plain_text,
        "subject": email["Subject"],
    }


def extract_data(text, subject):
    pattern_file = open("data_patterns.json")
    email_types = json.load(pattern_file)

    for email_type in email_types["email_types"]:
        if subject in email_type["subject"]:
            patterns = email_type
            break

    data_extract = {}

    for pattern in patterns["pattern_list"]:
        if "default" in pattern.keys():
            data_extract[pattern["data"]] = pattern["default"]
            continue

        matches = re.search(pattern["pattern"], text)
        if not matches:
            return None
        data_extract[pattern["data"]] = matches.groups()[0].strip()

    return data_extract


def add_to_ynab(transaction):
    if "date" in transaction.keys():
        date_obj = datetime.strptime(transaction["date"], "%d %b %y")
    else:
        date_obj = datetime.now()
    date = date_obj.strftime("%Y-%m-%d")

    amount = "-" + transaction["amount"].replace(".", "") + "0"

    if "shop" in transaction.keys():
        shop = transaction["shop"]
    else:
        shop = ""

    account = [x for x in account_ids if x["name"] == transaction["pay_method"]][0][
        "id"
    ]

    try:
        payee = ynab_ids["payees"][transaction["payee"]]
    except KeyError:
        logger.error(f"Payee {transaction['payee']} not found!")
        return

    json = {
        "transaction": {
            "date": date,
            "amount": amount,
            "memo": shop,
            "cleared": "uncleared",
            "approved": True,
            "account_id": account,
            "payee_id": payee,
            # "category_id": "293f682f-8a36-4ba4-9e9e-64f3877711c7",
        }
    }

    headers = {
        "Content-type": "application/json",
        "Authorization": f'Bearer {os.environ["YNAB_TOKEN"]}',
    }

    logger.info(f"Adding to YNAB: {json}")

    r = requests.post(
        "https://api.youneedabudget.com/v1/budgets/bfb94261-b4e3-4e9d-aa19-58b8d9d47678/transactions",
        headers=headers,
        json=json,
    )

    if r.status_code == 201:
        logger.info(f"Successfully added transaction to YNAB ")
        logger.info(f"Response: {r.json()}")
    else:
        logger.error(f"Failed to add transaction to YNAB: {r.json()}")


def extract_transactions(emails):
    transactions = []
    for email in emails:
        email_data = extract_plain_text(email)
        plain_text = email_data["text"]
        subject = email_data["subject"]
        data = extract_data(plain_text, subject)

        if data is not None:
            logger.info(f"Processing {email_data['subject']} {email['id']}")
            transactions.append(data)
        else:
            logger.error(f"Skipping {email_data['subject']} {email['id']}")

    logger.info(f"Found {len(transactions)} transactions!")

    return transactions


def subject_matches(subject, subjects_list):
    for s in subjects_list:
        if s in subject:
            return True

    return False


def main():
    # Login to gmail
    creds = authenticate_gmail()

    if creds is None:
        logger.error("Error logging in!")
        exit()

    # Retreive relevant emails
    logger.info("Retrieving emails...")
    emails = get_emails(creds)

    if len(emails) == 0:
        exit()

    # Extract transactions
    transactions = extract_transactions(emails)

    # Add transactions to ynab
    for transaction in transactions:
        add_to_ynab(transaction)


if __name__ == "__main__":
    main()
