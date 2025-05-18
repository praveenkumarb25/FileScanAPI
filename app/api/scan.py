from fastapi import APIRouter, Depends, File, UploadFile, HTTPException, Request
from app.core.security import get_current_user
from app.models import Scan
import os
import subprocess
import logging
import time
import re
import uuid
import magic  # pip install python-magic
from app.core.utils import limiter

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
    match = re.search(r'(?<=: )(.+?)(?= FOUND)', output)
    return match.group(1).strip() if match else None

def scan_file(file_path: str) -> tuple[bool, str]:
    try:
        logging.info(f"Scanning file: {file_path}")
        result = subprocess.run(
            ['clamdscan', file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        scan_result = result.stdout + result.stderr
        logging.debug(f"Scan result:\n{scan_result}")

        if result.returncode == 0:
            logging.info(f"File clean: {file_path}")
            return False, None
        elif result.returncode == 1:
            virus_name = parse_virus_name(scan_result)
            logging.warning(f"Infected file: {file_path} | Virus: {virus_name}")
            return True, virus_name
        else:
            raise RuntimeError(f"ClamAV error (code {result.returncode}): {scan_result}")

    except Exception as e:
        logging.error(f"Scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Error scanning file: {str(e)}")

@router.post("/", response_model=Scan)
@limiter.limit("5/minute")
async def scan_file_endpoint(
    request: Request,
    file: UploadFile = File(...),
    user: str = Depends(get_current_user)
) -> Scan:
    try:
        # Generate a safe unique file path
        unique_id = uuid.uuid4().hex
        temp_filename = f"{unique_id}_{file.filename}"
        file_location = os.path.join("/tmp", temp_filename)

        # Save uploaded file
        with open(file_location, "wb") as f:
            f.write(await file.read())

        # Optional: Log file type
        mime = magic.Magic(mime=True)
        mime_type = mime.from_file(file_location)
        logging.info(f"Received file: {file.filename} | MIME: {mime_type}")

        # Scan the file
        infected, virus_name = scan_file(file_location)

        # Create Scan result
        scan_result = Scan(
            time=time.strftime("%Y-%m-%d %H:%M:%S"),
            is_infected=infected,
            infected_by=virus_name
        )

        return scan_result

    finally:
        # Ensure file is always deleted
        if os.path.exists(file_location):
            os.remove(file_location)
