import os
import time
import logging
from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.api.routes import router as api_router
import warnings
warnings.filterwarnings("ignore", message=".*error reading bcrypt version.*")

# ✅ Set up logs directory and path
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")  # inside 'app/'
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE_PATH = os.path.join(LOG_DIR, "app.log")

# ✅ Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE_PATH),
        logging.StreamHandler()
    ]
)

logging.info("✅ Logging system initialized.")

# ✅ Create FastAPI app
app = FastAPI()

# ✅ Logging Middleware
class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        print("🛡️ LoggingMiddleware triggered")  # Debug confirmation
        start_time = time.time()
        response: Response = await call_next(request)
        process_time = time.time() - start_time

        log_details = {
            "method": request.method,
            "url": request.url.path,
            "status_code": response.status_code,
            "process_time": f"{process_time:.4f}s",
        }

        logging.info(f"API Call: {log_details}")
        return response

# ✅ Add middleware
app.add_middleware(LoggingMiddleware)

# ✅ Include all API routers
app.include_router(api_router)
