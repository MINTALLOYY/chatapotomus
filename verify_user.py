
import os
import sys
from firebase_admin import auth, credentials, initialize_app

# Set defaults to match app.py expectations
if "FIREBASE_CREDENTIALS_PATH" not in os.environ:
    os.environ["FIREBASE_CREDENTIALS_PATH"] = "firebase-sa-creds.json"

def verify_user_email(identifier):
    # Initialize Firebase Admin
    creds_path = os.getenv("FIREBASE_CREDENTIALS_PATH")
    if not os.path.exists(creds_path):
        print(f"Error: Credentials file not found at {creds_path}")
        return

    cred = credentials.Certificate(creds_path)
    try:
        initialize_app(cred)
    except ValueError:
        # App might already be initialized if this script is imported
        pass

    try:
        # Try to find user by email first
        try:
            user = auth.get_user_by_email(identifier)
        except auth.UserNotFoundError:
            # Try by UID
            user = auth.get_user(identifier)
        
        print(f"Found user: {user.email} (UID: {user.uid})")
        print(f"Current status - Email Verified: {user.email_verified}")

        if user.email_verified:
            print("User is already verified.")
        else:
            auth.update_user(user.uid, email_verified=True)
            print("Successfully updated user to email_verified=True.")
            print("Please log out and log back in on the client to refresh the ID token.")

    except auth.UserNotFoundError:
        print(f"Error: User not found with identifier '{identifier}'")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python verify_user.py <email_or_uid>")
    else:
        verify_user_email(sys.argv[1])
