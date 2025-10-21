import os
from base64 import urlsafe_b64encode
from passlib.context import CryptContext
import boto3
from dotenv import load_dotenv

# Load AWS credentials
load_dotenv(dotenv_path="app/core/.env")
# AWS setup
dynamodb = boto3.resource(
    'dynamodb',
    region_name="region",
    aws_access_key_id="id",
    aws_secret_access_key="key"
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