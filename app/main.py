import os
import time
import logging
import boto3
import json
import magic
from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import warnings
from logging import StreamHandler
from dotenv import load_dotenv
import botocore.exceptions
from slowapi.middleware import SlowAPIMiddleware
from app.core.utils import limiter
from slowapi.errors import RateLimitExceeded
from fastapi.responses import JSONResponse

# Load environment variables from .env file
load_dotenv(dotenv_path="app/.env")

# AWS CloudWatch setup
cloudwatch_logs = boto3.client(
    'logs',
    region_name=os.getenv("AWS_REGION"),
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
)

log_group = "/EC2-Cloud-Watch"
log_stream = "EC2-Cloud-Watch-Log"

# Create CloudWatch Log Group
try:
    cloudwatch_logs.create_log_group(logGroupName=log_group)
except cloudwatch_logs.exceptions.ResourceAlreadyExistsException:
    pass

# Create CloudWatch Log Stream
try:
    cloudwatch_logs.create_log_stream(logGroupName=log_group, logStreamName=log_stream)
except cloudwatch_logs.exceptions.ResourceAlreadyExistsException:
    pass

class CloudWatchLoggingHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.sequence_token = None

    def emit(self, record):
        log_entry = self.format(record)
        timestamp = int(round(time.time() * 1000))
        try:
            kwargs = {
                'logGroupName': log_group,
                'logStreamName': log_stream,
                'logEvents': [{
                    'timestamp': timestamp,
                    'message': log_entry
                }]
            }
            if self.sequence_token:
                kwargs['sequenceToken'] = self.sequence_token

            response = cloudwatch_logs.put_log_events(**kwargs)
            self.sequence_token = response.get('nextSequenceToken')
        except botocore.exceptions.ClientError as e:
            print(f"Failed to send log to CloudWatch: {e}")

# Set up local logging
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE_PATH = os.path.join(LOG_DIR, "app.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE_PATH),
        logging.StreamHandler(),
        CloudWatchLoggingHandler()
    ]
)

logging.info("✅ Logging system initialized.")

app = FastAPI()

SENSITIVE_KEYS = {"password", "token", "access_token", "refresh_token", "secret", "authorization"}

def redact_sensitive(data):
    if isinstance(data, dict):
        return {
            k: ("***REDACTED***" if k.lower() in SENSITIVE_KEYS else redact_sensitive(v))
            for k, v in data.items()
        }
    elif isinstance(data, list):
        return [redact_sensitive(item) for item in data]
    else:
        return data

def try_decode_utf8(body_bytes):
    try:
        return body_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None

class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        print("🛡️ LoggingMiddleware triggered")
        start_time = time.time()

        body = await request.body()
        content_type = request.headers.get("content-type", "").lower()

        async def receive():
            return {"type": "http.request", "body": body}
        request._receive = receive

        response = await call_next(request)

        response_body = b""
        async for chunk in response.body_iterator:
            response_body += chunk

        final_response = Response(
            content=response_body,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.media_type
        )

        file_type_info = None
        if body and ("multipart/form-data" in content_type or "application/octet-stream" in content_type):
            try:
                file_type_info = magic.from_buffer(body[:2048])
            except Exception as e:
                file_type_info = f"Error detecting file type: {e}"

        headers = {
            k: ("***REDACTED***" if k.lower() in SENSITIVE_KEYS else v)
            for k, v in dict(request.headers).items()
        }

        if "multipart/form-data" in content_type or "application/octet-stream" in content_type:
            redacted_request = {
                "raw_length": len(body),
                "detected_file_type": file_type_info or "Unknown binary file",
                "content_type": content_type,
                "note": "***Binary or multipart data redacted***"
            }
        else:
            request_body_str = try_decode_utf8(body)
            if request_body_str:
                try:
                    parsed_request = json.loads(request_body_str)
                    redacted_request = redact_sensitive(parsed_request)
                except json.JSONDecodeError:
                    redacted_request = request_body_str
            else:
                redacted_request = "***Non-UTF8 or binary data***"

        try:
            parsed_response = json.loads(response_body.decode("utf-8"))
            redacted_response = redact_sensitive(parsed_response)
        except Exception:
            redacted_response = "***Binary or non-UTF8 response***"

        log_details = {
            "method": request.method,
            "url": str(request.url),
            "headers": headers,
            "query_params": dict(request.query_params),
            "path_params": request.path_params,
            "body": redacted_request,
            "status_code": response.status_code,
            "response_body": redacted_response,
            "process_time": f"{(time.time() - start_time):.4f}s",
        }

        logging.info(f"📋 Full API Call Log: {json.dumps(log_details, indent=2)}")
        return final_response

# Add middleware
app.add_middleware(LoggingMiddleware)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

# Include all API routers
from app.api.routes import router as api_router
app.include_router(api_router)

@app.exception_handler(RateLimitExceeded)
async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded. Please try again in a moment."},
    )
