from __future__ import print_function

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
                subject = part.get_all('Subject')[0]

                if subject is not None and subject == 'Your Grab E-Receipt':
                    emails.append(email)
                    break
            
            break
    
    except HttpError as error:
        print(f'An error occured: {error}')
    
    return emails


def extract_soup(email):
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
    
    return soup


def extract_data_from_email(soup):
    print(soup.find_all('p'))


def main():

    # Authenticate gmail
    creds = authenticate_gmail()

    if creds is None:
        print('ERROR: unable to login to gmail')

    # Find new grab emails
    emails = get_grab_emails(creds)

    # For each new grab email, get the: restaurant, price, date, payment method; put into transactions
    for email in emails:
        soup = extract_soup(email)
        extract_data_from_email(soup)

if __name__ == '__main__':
    main()
