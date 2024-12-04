from utils import authenticate_gmail
from googleapiclient.discovery import build


def get_label_id(name, service):
    labels = service.users().labels().list(userId="me").execute()
    for label in labels["labels"]:
        if label["name"] == name:
            return label["id"]

    return None


def main():
    # Login to gmail
    creds = authenticate_gmail()
    service = build("gmail", "v1", credentials=creds)

    name = input("Label name: ")
    label = get_label_id(name, service)
    print("Label ID: ", label)


# if __name__ == "__main__":
#     main()
