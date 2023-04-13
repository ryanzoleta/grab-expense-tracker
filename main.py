from __future__ import print_function

import re
import json
import os.path
import base64
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError    
from email import message_from_string
from bs4 import BeautifulSoup

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


def authenticate_gmail():
    creds = None

    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)

        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    
    return creds


def get_grab_emails(creds):
    emails = []

    try:
        service = build('gmail', 'v1', credentials=creds)
        grabmsgs = service.users().messages().list(userId='me').execute()

        for msg in grabmsgs['messages']:
            email = service.users().messages().get(id=msg['id'], userId='me', format='raw').execute()

            raw_message = email['raw']
            decoded_message = base64.urlsafe_b64decode(raw_message.encode('UTF-8'))
            raw_email = decoded_message.decode('UTF-8')
            email_message = message_from_string(raw_email)

            for part in email_message.walk():
                if part.get_all('Subject') is None:
                    continue

                subject = part.get_all('Subject')[0]

                if subject is not None and subject == 'Your Grab E-Receipt':
                    emails.append(email)
                    break
             
            # if len(emails) > 0:
            #     break
            
    
    except HttpError as error:
        print(f'An error occured: {error}')
    
    return emails


def extract_plain_text(email):
    raw_message = email['raw']
    decoded_message = base64.urlsafe_b64decode(raw_message.encode('UTF-8'))
    raw_email = decoded_message.decode('UTF-8')
    email = message_from_string(raw_email)
    
    plain_text = ''
    for part in email.walk():
        if part.get_content_type() == 'text/plain':
            plain_text = part.get_payload(decode=True).decode('UTF-8')
            break 

    if not plain_text:
        for part in email.walk():
            if part.get_content_type() == 'text/html':
                html_text = part.get_payload(decode=True).decode('UTF-8')
                soup = BeautifulSoup(html_text, 'html.parser')
                plain_text = soup.get_text()
    
    all_text = ''

    for s in soup:
        all_text += s.text
    
    all_text = all_text.replace('\n', ' ')
    all_text = re.sub(' +', ' ', all_text)

    return all_text


def extract_data(text):

    pattern_file = open('data_patterns.json')
    patterns = json.load(pattern_file)

    data_extract = {}

    for pattern in patterns['pattern_list']:
        matches = re.search(pattern['pattern'], text)
        if not matches:
            return None
        data_extract[pattern['data']] = matches.groups()[0].strip()
    
    return data_extract


def main():

    print('Login to gmail... ', end='')
    creds = authenticate_gmail()
    print('OK')

    if creds is None:
        print('ERROR: unable to login to gmail')

    print('Retrieving grab emails...')
    emails = get_grab_emails(creds)
    print(f'Found {len(emails)} emails')

    print()
    print('Extracting data from emails...')
    transactions = []
    for email in emails:
        plain_text = extract_plain_text(email)
        data = extract_data(plain_text)

        if data is not None:
            transactions.append(data)
    
    print(f'Found {len(transactions)} transactions')

    # TODO: Process transactions

if __name__ == '__main__':
    main()