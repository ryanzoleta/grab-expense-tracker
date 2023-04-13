from __future__ import print_function

import re
import json
import os.path
import base64
import redis
import requests
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError    
from email import message_from_string
from bs4 import BeautifulSoup
from datetime import datetime

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


def connect_redis():
    return redis.Redis(
        host=os.environ['REDISHOST'],
        username=os.environ['REDISUSER'],
        password=os.environ['REDISPASSWORD'],
        port=os.environ['REDISPORT']
    )


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

    r = connect_redis()
    last_processed_email_id = r.get('last_processed_email_id').decode('utf-8')

    try:
        service = build('gmail', 'v1', credentials=creds)
        grabmsgs = service.users().messages().list(userId='me', labelIds='Label_6207772532920259483').execute()

        for msg in grabmsgs['messages']:

            if msg['id'] == last_processed_email_id:
                break

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
            
            if len(emails) > 0:
                break
        
        if len(emails) > 0:
            r.set('last_processed_email_id', emails[0]['id'])
    
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


def add_to_ynab(transaction):
    date_obj = datetime.strptime(transaction['date'], '%d %b %y')
    date = date_obj.strftime('%Y-%m-%d')
    
    amount = '-' + transaction['amount'].replace('.', '') + '0'
    shop = transaction['shop']

    json = {
        'transaction': {
            'date': date,
            'amount': amount,
            'memo': shop,
            'cleared': 'cleared',
            'approved': True,
            'account_id': '17a9221a-38ab-446a-9462-ca991410a2a6',
            'payee_id': 'e8c1dc4a-ecf4-4d94-80e9-7161d884916a',
            'category_id': '293f682f-8a36-4ba4-9e9e-64f3877711c7'
        }
    }

    headers = {
        'Content-type': 'application/json',
        'Authorization': f'Bearer {os.environ["YNAB_TOKEN"]}'
    }


    r = requests.post('https://api.youneedabudget.com/v1/budgets/bfb94261-b4e3-4e9d-aa19-58b8d9d47678/transactions', headers=headers, json=json)

    if r.status_code == 201:
        print(f'Successfully added {shop} transaction on {date}')
    else:
        print(r.json())


def main():

    print('Login to gmail... ', end='')
    creds = authenticate_gmail()
    print('OK')

    if creds is None:
        print('ERROR: unable to login to gmail')

    print('Retrieving grab emails... ', end='')
    emails = get_grab_emails(creds)
    print(f'found {len(emails)}')

    print('Extracting transactions from emails... ', end='')
    transactions = []
    for email in emails:
        plain_text = extract_plain_text(email)
        data = extract_data(plain_text)

        if data is not None:
            transactions.append(data)
    
    print(f'found {len(transactions)}')

    print('Adding to YNAB...')
    for transaction in transactions:
        add_to_ynab(transaction)

if __name__ == '__main__':
    main()