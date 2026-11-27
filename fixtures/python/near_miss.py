import os

def status():
    secret = os.getenv("SYNTHETIC_TOKEN")
    secret_label = "public status"
    print(secret_label)
