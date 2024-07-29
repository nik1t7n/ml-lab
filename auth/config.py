from dotenv import load_dotenv
import os

load_dotenv()

connection_string = os.getenv("CONNECTION_STRING")
secret_key = os.getenv("SECRET_KEY")
access_token_expire_minutes = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
refresh_token_expire_days = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS"))
algorithm = os.getenv("ALGORITHM")