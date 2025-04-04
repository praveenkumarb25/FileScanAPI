from fastapi import APIRouter, Depends, File, UploadFile, HTTPException
from app.core.security import get_current_user  # Assuming you have this function for authentication
from app.models import Scan
import os
import subprocess
import logging
import time
import re

# Configure logger
logs_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs")
os.makedirs(logs_directory, exist_ok=True)

log_file = os.path.join(logs_directory, "file_changes.log")

logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

router = APIRouter()

def parse_virus_name(output):
    """Parses the ClamAV output to extract the virus name.

    Args:
        output: The output string from ClamAV.

    Returns:
        The virus name, or None if not found.
    """

    virus_name_pattern = r"(\w+\.\w+\.\w+)"
    match = re.search(virus_name_pattern, output)
    if match:
        return match.group(1)
    else:
        return None

def scan_file(file_path: str) -> tuple[bool, str]:
    try:
        print(f"Scanning file: {file_path}")
        logging.info(f"Scanning file: {file_path}")
        # Run clamscan on the file
        result = subprocess.run(
            ['clamdscan', file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        scan_result = result.stdout
        print(f"Scan details for {file_path}:\n{scan_result}")
        logging.debug(f"Scan details for {file_path}:\n{scan_result}")

        if result.returncode == 0:
            print(f"File {file_path} is clean.")
            logging.info(f"File {file_path} is clean.")
            return False, None  # No infection, no virus name
        else:
            print(f"Warning: Malware detected in file {file_path}.")
            logging.warning(f"Malware detected in file {file_path}.")
            virus_name = parse_virus_name(scan_result)
            return True, virus_name  # Infected, return virus name
    except Exception as e:
        print(f"Error scanning file {file_path}: {e}")
        logging.error(f"Error scanning file {file_path}: {e}")
        raise HTTPException(status_code=500, detail=f"Error scanning file: {e}")

@router.post("/", response_model=Scan)
async def scan_file_endpoint(file: UploadFile = File(...), user: str = Depends(get_current_user)) -> Scan:
    # Save the uploaded file temporarily
    file_location = f"/tmp/{file.filename}"
    with open(file_location, "wb") as f:
        f.write(await file.read())

    # Scan the file for malware
    infected, virus_name = scan_file(file_location)

    # Prepare the Scan result
    scan_result = Scan(
        time=time.strftime("%Y-%m-%d %H:%M:%S"),
        #username=user,
        is_infected=infected,
        infected_by=virus_name
    )

    # Clean up the temporary file
    os.remove(file_location)

    return scan_result
