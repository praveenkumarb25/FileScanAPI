import os
from base64 import urlsafe_b64encode
from passlib.context import CryptContext
import boto3
from dotenv import load_dotenv
from datetime import datetime
import warnings
warnings.filterwarnings("ignore", message=".*error reading bcrypt version.*")
import logging
logging.getLogger("passlib").setLevel(logging.ERROR)
logging.getLogger("bcrypt").setLevel(logging.ERROR)
# Load AWS credentials
load_dotenv(dotenv_path="app/.env")
# AWS setup
dynamodb = boto3.resource(
    'dynamodb',
    region_name=os.getenv("AWS_REGION"),  # Default to 'us-east-1' if not set
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),  # Default to 'your_access_key_id' if not set
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")  # Default to 'your_secret_access_key' if not set
)
users = os.getenv("DYNAMODB_USERS_TABLE")  # Default to 'users' if not set
table = dynamodb.Table(users)

SECRET_KEY = urlsafe_b64encode(os.urandom(32)).decode('utf-8')  # Use a fixed one in production
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Function to get user from DynamoDB
def get_user_from_db(username: str):
    response = table.scan(
        FilterExpression="username = :u",
        ExpressionAttributeValues={":u": username}
    )
    items = response.get("Items", [])
    return items[0] if items else None
def update_token_metadata(username: str, success: bool, expire_time: str = ""):
    user = get_user_from_db(username)
    if not user:
        return

    updates = {
        "token_last_used": datetime.utcnow().isoformat()
    }

    if success:
        updates["token_created"] = datetime.utcnow().isoformat()
        updates["token_expiration"] = expire_time
        updates["token_failed"] = 0
    else:
        updates["token_failed"] = int(user.get("token_failed", 0)) + 1

    table.update_item(
        Key={"id": user["id"]},  # Assumes 'id' is the partition key
        UpdateExpression="SET " + ", ".join(f"{k} = :{k}" for k in updates),
        ExpressionAttributeValues={f":{k}": v for k, v in updates.items()}
    )