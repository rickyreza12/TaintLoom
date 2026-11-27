import os

def disclose():
    secret = os.getenv("SYNTHETIC_TOKEN")
    print(secret)
