import os
import time
import logging
from fastapi import FastAPI, Request

from app.api.routes import router as api_router
import warnings
warnings.filterwarnings("ignore", message=".*error reading bcrypt version.*")

# ✅ Create FastAPI app
app = FastAPI()
# ✅ Include all API routers
app.include_router(api_router)
