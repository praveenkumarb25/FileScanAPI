from fastapi import APIRouter, Depends, File, UploadFile, HTTPException, Request
from app.core.security import get_current_user
from app.models import Scan
from app.core.utils import limiter

import os
import subprocess
import logging
import time
import re
import uuid
import magic  # pip install python-magic

# Initialize router
router = APIRouter()

# Setup logging
logs_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs")
os.makedirs(logs_directory, exist_ok=True)
log_file = os.path.join(logs_directory, "file_changes.log")

logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def parse_virus_name(output: str) -> str | None:
    """
    Extracts virus name from ClamAV output.
    """
    match = re.search(r'(?<=: )(.+?)(?= FOUND)', output)
    return match.group(1).strip() if match else None

def scan_file(file_path: str) -> tuple[bool, str]:
    """
    Scans the file using ClamAV.
    Returns tuple (infected: bool, virus_name: str).
    """
    try:
        logging.info(f"Scanning file: {file_path}")
        result = subprocess.run(
            ['clamdscan', file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        output = result.stdout + result.stderr
        logging.debug(f"ClamAV scan output:\n{output}")

        if result.returncode == 0:
            logging.info(f"File is clean: {file_path}")
            return False, None
        elif result.returncode == 1:
            virus_name = parse_virus_name(output)
            logging.warning(f"Malware detected in {file_path}: {virus_name}")
            return True, virus_name
        else:
            raise RuntimeError(f"ClamAV scan failed (code {result.returncode}): {output}")

    except Exception as e:
        logging.error(f"Scanning error: {e}")
        raise HTTPException(status_code=500, detail=f"Error scanning file: {str(e)}")

@router.post("/", response_model=Scan)
@limiter.limit("5/minute")
async def scan_file_endpoint(
    request: Request,
    file: UploadFile = File(...),
    user: str = Depends(get_current_user)
) -> Scan:
    """
    Endpoint to scan uploaded files.
    Supports all file types.
    """
    unique_id = uuid.uuid4().hex
    safe_filename = f"{unique_id}_{file.filename}"
    file_location = os.path.join("/tmp", safe_filename)

    try:
        # Save uploaded file to disk
        with open(file_location, "wb") as f:
            f.write(await file.read())

        # Detect MIME type
        mime = magic.Magic(mime=True)
        mime_type = mime.from_file(file_location)
        logging.info(f"File received: {file.filename} | MIME: {mime_type} | User: {user}")

        # Scan the file
        infected, virus_name = scan_file(file_location)

        # Build response
        return Scan(
            time=time.strftime("%Y-%m-%d %H:%M:%S"),
            is_infected=infected,
            infected_by=virus_name
        )

    finally:
        # Always delete temporary file
        if os.path.exists(file_location):
            os.remove(file_location)
