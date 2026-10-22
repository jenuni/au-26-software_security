# processing worker running on http://localhost:8002
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests
import os
import base64
import pickle
from chat_formatter import format_chat_to_markdown

app = FastAPI(title="Processing Worker", version="1.0.0")

# Internal network route to the Message Vault (Resource Service)
MESSAGE_VAULT_URL = os.getenv("MESSAGE_VAULT_URL", "http://localhost:8001")

class ExportRequest(BaseModel):
    username: str

class ImportRequest(BaseModel):
    username: str
    backup: str  # base64-encoded serialized chat backup


@app.post("/run-export")
def run_export(req: ExportRequest):
    """
    Processing service job: Fetches records from the Message Vault,
    formats them using the external dependency, and returns the export.
    This workflow bridges all 3 components.
    """
    try:
        # --- VULNERABILITY: CWE-862 (Missing Authorization) + COMPOSITION FLAW ---
        # No auth check: port 8002 is published, so a direct POST bypasses the API's
        # session check and exports for ANY username (not just the caller's own).

        # Worker requests allowed records from Vault
        vault_response = requests.get(f"{MESSAGE_VAULT_URL}/messages/{req.username}")
        
        if vault_response.status_code != 200:
            raise HTTPException(status_code=502, detail="Failed to fetch records from Message Vault")
        
        data = vault_response.json()
        messages = data.get("messages", [])

        # Process the data using the external helper package dependency
        markdown_output = format_chat_to_markdown(messages)

        return {
            "status": "success",
            "export_format": "markdown",
            "exported_data": markdown_output
        }
        
    except requests.exceptions.RequestException:
        raise HTTPException(status_code=503, detail="Message Vault service unreachable")


@app.post("/import-backup")
def import_backup(req: ImportRequest):
    """
    Processing service job: restores a previously exported chat backup.
    The API hands the worker a base64-encoded backup blob, the worker
    deserializes it and writes each message into the Message Vault.
    This workflow bridges all 3 components.
    """
    try:
        # --- VULNERABILITY: CWE-862 (Missing Authorization) + COMPOSITION FLAW ---
        # No auth check: a direct caller on port 8002 bypasses the API's session check
        # AND the Admin-only role check on /import, writing messages without authenticating.
        raw = base64.b64decode(req.backup)

        # --- VULNERABILITY: CWE-502 (Deserialization of Untrusted Data) ---
        # The backup blob comes from the user and is deserialized with pickle
        # without any validation. A crafted payload executes arbitrary code
        # inside the worker during unpickling (via __reduce__).
        messages = pickle.loads(raw)

        stored = 0
        for msg in messages:
            payload = {
                "sender": msg.get("sender", req.username),
                "recipient": msg.get("recipient", req.username),
                "content": msg.get("content", ""),
            }
            vault_response = requests.post(f"{MESSAGE_VAULT_URL}/messages", json=payload)
            if vault_response.status_code == 200:
                stored += 1

        return {"status": "success", "imported": stored}

    except requests.exceptions.RequestException:
        raise HTTPException(status_code=503, detail="Message Vault service unreachable")


