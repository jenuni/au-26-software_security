# app api running on http://localhost:8000

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.responses import FileResponse
from pydantic import BaseModel
import requests
import os

app = FastAPI(title="ADFMS Application API", version="1.0.0")

# Internal service URLs 
MESSAGE_VAULT_URL = os.getenv("MESSAGE_VAULT_URL", "http://localhost:8001")
PROCESSING_WORKER_URL = os.getenv("PROCESSING_WORKER_URL", "http://localhost:8002")

# In-memory session store 
ACTIVE_SESSIONS = {}

class LoginModel(BaseModel):
    username: str
    password: str

class MessageModel(BaseModel):
    recipient: str
    text: str

@app.post("/login")
def login(creds: LoginModel):
    """Authenticates users and issues a session token."""
    # Vulnerability 2 Placeholder: Hardcoded check 
    if creds.username == "pilot1" and creds.password == "Drone@123":
        token = "token_ordinary_user_123"
        ACTIVE_SESSIONS[token] = {"username": creds.username, "role": "Operator"}
        return {"access_token": token, "role": "Operator"}
    elif creds.username == "admin" and creds.password == "Admin@123":
        token = "token_admin_789"
        ACTIVE_SESSIONS[token] = {"username": creds.username, "role": "Admin"}
        return {"access_token": token, "role": "Admin"}
    
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/messages")
def send_message(msg: MessageModel, authorization: str = Header(None)):
    """Coordinates sending a message through to the Message Vault."""
    if authorization not in ACTIVE_SESSIONS:
        raise HTTPException(status_code=403, detail="Unauthorized session")
    
    user_info = ACTIVE_SESSIONS[authorization]
    
    # Forward the request to the Message Vault (Resource Service)
    payload = {
        "sender": user_info["username"],
        "recipient": msg.recipient,
        "text": msg.text
    }
    response = requests.post(f"{MESSAGE_VAULT_URL}/store", json=payload)
    return response.json()

@app.post("/export")
def request_export(authorization: str = Header(None)):
    """Triggers the export job across all three components (API -> Worker -> Vault)."""
    if authorization not in ACTIVE_SESSIONS:
        raise HTTPException(status_code=403, detail="Unauthorized session")
    
    user_info = ACTIVE_SESSIONS[authorization]
    
    # Trigger the processing worker service
    response = requests.post(f"{PROCESSING_WORKER_URL}/run-export", json={"username": user_info["username"]})
    return response.json()

# --- VULNERABILITY: CWE-22 (Path Traversal) ---
@app.get("/download")
def download_file(filename: str):
    """
    Vulnerable file download endpoint for documents like Terms of Service (tos.txt) or Privacy Policy (privacy.txt).
    Allows an attacker to use '../../' to read arbitrary files from the container.
    """
    # Directory where safe documents are supposed to be stored
    target_dir = "./documents"
    
    # Unsafe path concatenation without proper sanitization or normalization checks
    file_path = os.path.join(target_dir, filename)
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
        
    return FileResponse(file_path)